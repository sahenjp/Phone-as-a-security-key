import Foundation

/// 承認調整役。
/// PC からの作成 / 認証リクエストは、ここで画面表示され、
/// ユーザーが明示的にタップするまで絶対に先へ進まない。
/// 自動承認のコードパスは存在しない。タイムアウト時は拒否として扱う。
@MainActor
final class ApprovalCoordinator: ObservableObject {
    @Published private(set) var pending: PendingApproval?

    private var continuation: CheckedContinuation<Bool, Never>?
    private var timeoutTask: Task<Void, Never>?

    /// 承認待ちを開始し、承認 (true) / 拒否・タイムアウト (false) まで待つ。
    /// 既に別の承認待ちがある場合は即座に false を返す (同時 1 件のみ)。
    func requestApproval(_ approval: PendingApproval) async -> Bool {
        guard pending == nil, continuation == nil else { return false }
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            pending = approval
            continuation = cont
            timeoutTask = Task { @MainActor [weak self] in
                let ns = UInt64(BridgeConstants.approvalTimeoutSeconds * 1_000_000_000)
                try? await Task.sleep(nanoseconds: ns)
                guard !Task.isCancelled else { return }
                self?.finish(with: false)
            }
        }
    }

    func approve() {
        finish(with: true)
    }

    func deny() {
        finish(with: false)
    }

    private func finish(with result: Bool) {
        timeoutTask?.cancel()
        timeoutTask = nil
        pending = nil
        let cont = continuation
        continuation = nil
        cont?.resume(returning: result)
    }
}

/// アプリ全体の状態。BridgeServer (バックグラウンド) と UI の橋渡しをする。
@MainActor
final class AppState: ObservableObject {
    enum ListenerState: Equatable {
        case stopped
        case listening
        case failed(String)
    }

    @Published var listenerState: ListenerState = .stopped
    @Published var isConnected = false
    @Published var lastEvent = ""
    @Published var credentials: [CredentialMetadata] = []
    @Published private(set) var pairingPSK: Data?

    let approval = ApprovalCoordinator()

    private var server: BridgeServer?

    var isPaired: Bool { pairingPSK != nil }

    var pskBase32: String? {
        pairingPSK.map { CryptoUtils.base32EncodeNoPadding($0) }
    }

    var sasCode: String? {
        pairingPSK.map { CryptoUtils.sasCode(for: $0) }
    }

    func onAppear() {
        refreshPairing()
        refreshCredentials()
        startServerIfNeeded()
    }

    func startServerIfNeeded() {
        if server == nil {
            server = BridgeServer(appState: self)
        }
        server?.start()
    }

    // MARK: ペアリング

    func refreshPairing() {
        pairingPSK = KeychainStore.shared.loadPSK()
        // サーバーは Keychain を直接読まず、ここで渡した値を保持する。
        server?.setPSK(pairingPSK)
    }

    /// アプリがフォアグラウンドに戻ったとき。PSK をサーバーへ渡し直し、
    /// 待ち受けを作り直して自動で接続可能な状態に戻す。
    func onSceneActive() {
        startServerIfNeeded()
        refreshPairing()
        refreshCredentials()
        server?.ensureRunning()
    }

    func generatePSK() {
        KeychainStore.shared.generateAndSavePSK()
        refreshPairing()
    }

    func deletePSK() {
        KeychainStore.shared.deletePSK()
        refreshPairing()
    }

    // MARK: 資格

    func refreshCredentials() {
        credentials = KeychainStore.shared.allCredentials()
    }

    func deleteCredential(_ credential: CredentialMetadata) {
        SecureEnclaveKeyStore.shared.deleteKey(tag: credential.keyTag)
        KeychainStore.shared.deleteCredential(credentialId: credential.credentialId)
        refreshCredentials()
    }

    // MARK: BridgeServer からのイベント (メインスレッドで呼ばれる前提の口)

    func serverDidChangeListenerState(_ state: ListenerState) {
        listenerState = state
    }

    func serverDidChangeConnection(connected: Bool, event: String) {
        isConnected = connected
        lastEvent = event
    }

    func serverDidLog(_ event: String) {
        lastEvent = event
    }
}
