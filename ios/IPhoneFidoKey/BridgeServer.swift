import Foundation
import Network

/// PC (Fedora) とのブリッジサーバー。
///
/// - NWListener で TCP 18765 を全インターフェースで待ち受ける
///   (usbmuxd 経由の到達性のため loopback には限定しない。到達制御は暗号層で行う)。
/// - フレーミングは 4 byte big-endian 長さ + payload (BRIDGE-PROTOCOL 0)。
/// - 未ペアリング (PSK が Keychain に無い) の間は接続を受けても即座に切断する。
/// - ハンドシェイク (平文 JSON) の後は ChaCha20-Poly1305 の暗号化チャネルに移る。
final class BridgeServer {
    private weak var appState: AppState?
    private let service: AuthenticatorService
    private let queue = DispatchQueue(label: "iphone-fido.bridge")
    private var listener: NWListener?
    /// ペアリング PSK。Keychain からの読み取りは MainActor (AppState) が担い、
    /// ここには値だけを保持する。バックグラウンドキューから Keychain を読むと
    /// 読めない場合がある (実機で確認済み) ため、サーバーは Keychain に触らない。
    private var psk: Data?
    /// ネットワーク構成の変化 (USB 接続でインターフェースが増える等) を
    /// 監視し、待ち受けを作り直す。「アプリを先に起動して後から USB を
    /// 挿す」場合でも接続できるようにするため。
    private var pathMonitor: NWPathMonitor?
    /// 同時に生かすセッションは 1 本だけ (プロトコル上も PC は 1 接続のみ)。
    private var currentConnection: NWConnection?
    private var stopped = false

    @MainActor
    init(appState: AppState) {
        self.appState = appState
        self.psk = appState.pairingPSK
        self.service = AuthenticatorService(
            approval: appState.approval,
            onCredentialsChanged: { [weak appState] in
                Task { @MainActor in
                    appState?.refreshCredentials()
                }
            }
        )
    }

    /// AppState (MainActor) から PSK を受け取る。生成・削除・再読み込みのたびに呼ばれる。
    @MainActor
    func setPSK(_ newValue: Data?) {
        queue.async { [weak self] in
            self?.psk = newValue
        }
    }

    // MARK: - 起動 / 停止

    func start() {
        queue.async { [weak self] in
            self?.stopped = false
            self?.startPathMonitorIfNeeded()
            self?.startListener()
        }
    }

    func stop() {
        queue.async { [weak self] in
            self?.stopped = true
            self?.pathMonitor?.cancel()
            self?.pathMonitor = nil
            self?.currentConnection?.cancel()
            self?.currentConnection = nil
            self?.listener?.cancel()
            self?.listener = nil
        }
    }

    private func startPathMonitorIfNeeded() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            // 経路が生きている限り、構成変化のたびに待ち受けを立て直す。
            // アプリ起動後に USB を挿したケースで新しいインターフェースに
            // リスナーが付かない問題への対策。
            if path.status == .satisfied {
                self?.ensureRunning()
            }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    /// アプリがフォアグラウンドに戻ったときに呼ぶ。待ち受けを作り直して、
    /// サスペンド中に固まった状態から自動で回復する。
    func ensureRunning() {
        queue.async { [weak self] in
            guard let self, !self.stopped else { return }
            self.listener?.cancel()
            self.listener = nil
            self.startListener()
        }
    }

    private func startListener() {
        guard listener == nil else { return }
        guard let port = NWEndpoint.Port(rawValue: BridgeConstants.listenPort) else {
            notifyListenerState(.failed("invalid port"))
            return
        }
        do {
            // requiredInterfaceType は指定しない = 全インターフェース bind。
            let parameters = NWParameters.tcp
            let listener = try NWListener(using: parameters, on: port)
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    if self.listener === listener {
                        self.notifyListenerState(.listening)
                    }
                case .failed(let error):
                    self.notifyListenerState(.failed("\(error)"))
                    // 失敗したリスナーは自分が現役のときだけ片付け、
                    // 自動で張り直す (手動再起動を不要にする)。
                    if self.listener === listener {
                        self.listener = nil
                        self.scheduleListenerRestart()
                    }
                case .cancelled:
                    if self.listener === listener {
                        self.notifyListenerState(.stopped)
                    }
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                self?.handle(connection: connection)
            }
            listener.start(queue: queue)
            self.listener = listener
        } catch {
            notifyListenerState(.failed("\(error)"))
        }
    }

    private func scheduleListenerRestart() {
        guard !stopped else { return }
        queue.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            guard let self, !self.stopped, self.listener == nil else { return }
            self.startListener()
        }
    }

    // MARK: - 接続処理

    private func handle(connection: NWConnection) {
        // 前の接続 (デーモンの再起動や電話のサスペンドで残った半死の
        // セッション) は、新しい接続で置き換える。
        if let previous = currentConnection {
            previous.cancel()
        }
        currentConnection = connection
        let sessionPSK = psk
        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                self?.notifyLog("connection failed: \(error)")
            }
        }
        connection.start(queue: queue)
        Task { [weak self] in
            await self?.runSession(connection: connection, psk: sessionPSK)
            connection.cancel()
            self?.clearCurrentConnection(connection)
        }
    }

    private func clearCurrentConnection(_ connection: NWConnection) {
        queue.async { [weak self] in
            if self?.currentConnection === connection {
                self?.currentConnection = nil
            }
        }
    }

    private func runSession(connection: NWConnection, psk: Data?) async {
        let io = FrameIO(connection: connection)

        // 未ペアリング時は接続を拒否する (PSK が無い状態では何もしない)。
        guard let psk else {
            notifyLog("接続を拒否しました (未ペアリング)")
            return
        }

        do {
            try await performHandshakeAndServe(io: io, psk: psk)
        } catch {
            notifyLog("セッション終了: \(error)")
        }
        notifyConnection(connected: false, event: "切断しました")
    }

    private func performHandshakeAndServe(io: FrameIO, psk: Data) async throws {
        // 1. hello (平文 JSON)
        let hello = try jsonObject(try await io.readFrame())
        guard
            (hello["type"] as? String) == "hello",
            ((hello["version"] as? NSNumber)?.intValue) == BridgeConstants.protocolVersion,
            let pcRandomB64 = hello["pc_random"] as? String,
            let pcRandom = Data(base64Encoded: pcRandomB64), pcRandom.count == 32,
            let pcPubB64 = hello["pc_ephemeral_pubkey"] as? String,
            let pcPub = Data(base64Encoded: pcPubB64),
            pcPub.count == 65, pcPub.first == 0x04
        else {
            throw BridgeInternalError.handshake("invalid hello")
        }

        // 2. hello_ack (一時鍵は接続ごとに新規生成する)
        guard let ephemeral = EphemeralECDH(),
              let phoneRandom = CryptoUtils.randomBytes(count: 32)
        else {
            throw BridgeInternalError.handshake("ephemeral key generation failed")
        }
        try await io.writeFrame(jsonData([
            "type": "hello_ack",
            "version": BridgeConstants.protocolVersion,
            "phone_random": phoneRandom.base64EncodedString(),
            "phone_ephemeral_pubkey": ephemeral.publicKeyX963.base64EncodedString(),
        ]))

        // 3. 鍵導出
        guard let ecdh = ephemeral.sharedSecret(withPeerPublicKeyX963: pcPub) else {
            throw BridgeInternalError.handshake("ecdh failed")
        }
        let keys = SessionCrypto.deriveSessionKeys(
            ecdhSharedSecret: ecdh,
            psk: psk,
            pcRandom: pcRandom,
            phoneRandom: phoneRandom
        )

        // 4. confirm (PC → Phone) を検証する。失敗したら切断。
        let confirm = try jsonObject(try await io.readFrame())
        guard
            (confirm["type"] as? String) == "confirm",
            let macB64 = confirm["mac"] as? String,
            let mac = Data(base64Encoded: macB64)
        else {
            throw BridgeInternalError.handshake("invalid confirm")
        }
        let expectedMAC = SessionCrypto.confirmMAC(
            confirmKey: keys.confirm,
            role: "pc",
            pcRandom: pcRandom,
            phoneRandom: phoneRandom
        )
        guard CryptoUtils.constantTimeEqual(mac, expectedMAC) else {
            throw BridgeInternalError.handshake("confirm mac mismatch")
        }

        // 5. confirm_ack (Phone → PC)
        let ackMAC = SessionCrypto.confirmMAC(
            confirmKey: keys.confirm,
            role: "phone",
            pcRandom: pcRandom,
            phoneRandom: phoneRandom
        )
        try await io.writeFrame(jsonData([
            "type": "confirm_ack",
            "mac": ackMAC.base64EncodedString(),
        ]))

        notifyConnection(connected: true, event: "接続中 (ハンドシェイク完了)")

        // 以降は暗号化チャネル。復号失敗・seq 不一致は SessionCipher が throw し、即切断する。
        let cipher = SessionCipher(sessionKeys: keys)
        while true {
            let frame = try await io.readFrame()
            let plaintext = try cipher.open(frame)
            let request: [String: Any]
            do {
                request = try jsonObject(plaintext)
            } catch {
                let response = try cipher.seal(jsonData([
                    "id": 0, "ok": false, "error": BridgeErrorCode.badRequest.rawValue,
                ]))
                try await io.writeFrame(response)
                continue
            }
            let responseObject = await service.handle(request: request)
            let sealed = try cipher.seal(jsonData(responseObject))
            try await io.writeFrame(sealed)
        }
    }

    // MARK: - JSON 補助

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BridgeInternalError.handshake("payload is not a JSON object")
        }
        return object
    }

    private func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object)
    }

    // MARK: - UI 通知 (MainActor へ hop する)

    private func notifyListenerState(_ state: AppState.ListenerState) {
        Task { @MainActor [weak appState] in
            appState?.serverDidChangeListenerState(state)
        }
    }

    private func notifyConnection(connected: Bool, event: String) {
        Task { @MainActor [weak appState] in
            appState?.serverDidChangeConnection(connected: connected, event: event)
        }
    }

    private func notifyLog(_ event: String) {
        Task { @MainActor [weak appState] in
            appState?.serverDidLog(event)
        }
    }
}

// MARK: - フレーミング (4 byte BE 長さ + payload)

private final class FrameIO {
    private let connection: NWConnection

    init(connection: NWConnection) {
        self.connection = connection
    }

    func readFrame() async throws -> Data {
        let header = try await readExact(4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= BridgeConstants.maxFrameSize else {
            throw BridgeInternalError.framing("invalid frame length \(length)")
        }
        return try await readExact(length)
    }

    func writeFrame(_ payload: Data) async throws {
        guard payload.count <= BridgeConstants.maxFrameSize else {
            throw BridgeInternalError.framing("payload too large")
        }
        var frame = Data.uint32BigEndian(UInt32(payload.count))
        frame.append(payload)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: frame, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: BridgeInternalError.io("\(error)"))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    private func readExact(_ count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: BridgeInternalError.io("\(error)"))
                    return
                }
                if let data, data.count == count {
                    continuation.resume(returning: data)
                    return
                }
                if isComplete {
                    continuation.resume(throwing: BridgeInternalError.io("connection closed by peer"))
                    return
                }
                continuation.resume(throwing: BridgeInternalError.io("short read"))
            }
        }
    }
}
