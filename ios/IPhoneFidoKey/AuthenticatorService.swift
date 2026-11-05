import Foundation

/// BRIDGE-PROTOCOL 3 の意味操作を処理する。
///
/// 原則: PC は任意バイト列への署名を電話に求めることはできない。
/// authData は必ずこのクラス (iPhone 側) が rp_id から組み立て、
/// ユーザーの画面タップ承認 + Face ID を通したときだけ署名する。
final class AuthenticatorService {
    private let keychain: KeychainStore
    private let enclave: SecureEnclaveKeyStore
    private let approval: ApprovalCoordinator
    private let onCredentialsChanged: () -> Void

    /// PRF (hmac-secret) の2段階フローの保留状態。
    /// eval で承認済みの文脈を ticket で引き継ぎ、finish で署名する。
    private struct PendingPrfAssertion {
        var metadata: CredentialMetadata
        var clientDataHash: Data
        var createdAt: Date
    }
    private var pendingPrf: [Data: PendingPrfAssertion] = [:]

    init(
        keychain: KeychainStore = .shared,
        enclave: SecureEnclaveKeyStore = .shared,
        approval: ApprovalCoordinator,
        onCredentialsChanged: @escaping () -> Void = {}
    ) {
        self.keychain = keychain
        self.enclave = enclave
        self.approval = approval
        self.onCredentialsChanged = onCredentialsChanged
    }

    // MARK: - ディスパッチ

    /// 暗号化チャネル内の JSON リクエストを受け取り、JSON レスポンスを返す。
    func handle(request: [String: Any]) async -> [String: Any] {
        guard let id = (request["id"] as? NSNumber)?.intValue else {
            return failure(id: 0, code: .badRequest)
        }
        guard let op = request["op"] as? String else {
            return failure(id: id, code: .badRequest)
        }
        switch op {
        case "ping":
            return success(id: id, result: ["app": "iphone-fido", "version": BridgeConstants.protocolVersion])
        case "create_credential":
            return await createCredential(id: id, request: request)
        case "get_assertion":
            return await getAssertion(id: id, request: request)
        case "get_assertion_finish":
            return await getAssertionFinish(id: id, request: request)
        case "list_credentials":
            return listCredentials(id: id)
        default:
            return failure(id: id, code: .badRequest)
        }
    }

    private func success(id: Int, result: [String: Any]) -> [String: Any] {
        ["id": id, "ok": true, "result": result]
    }

    private func failure(id: Int, code: BridgeErrorCode) -> [String: Any] {
        ["id": id, "ok": false, "error": code.rawValue]
    }

    // MARK: - 3.2 create_credential

    private func createCredential(id: Int, request: [String: Any]) async -> [String: Any] {
        guard
            let rpId = request["rp_id"] as? String, !rpId.isEmpty,
            let userIdB64 = request["user_id"] as? String,
            let userId = Data(base64Encoded: userIdB64),
            let userName = request["user_name"] as? String,
            let clientDataHashB64 = request["client_data_hash"] as? String,
            let clientDataHash = Data(base64Encoded: clientDataHashB64),
            clientDataHash.count == 32
        else {
            return failure(id: id, code: .badRequest)
        }
        let rpName = request["rp_name"] as? String
        let userDisplayName = request["user_display_name"] as? String
        // PRF (hmac-secret) を有効化する作成かどうか。
        let wantsHmacSecret = (request["hmac_secret"] as? NSNumber)?.boolValue ?? false

        // 1. rp_id と user_name を画面に出し、ユーザーの「作成」タップを待つ (必須)。
        let approved = await approval.requestApproval(
            PendingApproval(
                requestId: id,
                operation: .createCredential,
                rpId: rpId,
                userName: userName,
                requestedAt: Date()
            )
        )
        guard approved else { return failure(id: id, code: .userCancelled) }

        // 2. Secure Enclave に P-256 鍵を新規生成する。
        guard let credentialId = CryptoUtils.randomBytes(count: 32) else {
            return failure(id: id, code: .internalError)
        }
        let generated: GeneratedEnclaveKey
        do {
            generated = try enclave.generateKey(credentialId: credentialId)
        } catch {
            return failure(id: id, code: .internalError)
        }

        // 3. メタデータを Keychain に保存する (失敗したら Enclave 鍵を消して巻き戻す)。
        let hmacSecret: Data?
        if wantsHmacSecret {
            hmacSecret = CryptoUtils.randomBytes(count: 32)
            guard hmacSecret != nil else {
                enclave.deleteKey(tag: generated.keyTag)
                return failure(id: id, code: .internalError)
            }
        } else {
            hmacSecret = nil
        }
        let metadata = CredentialMetadata(
            credentialId: credentialId,
            rpId: rpId,
            rpName: rpName,
            userId: userId,
            userName: userName,
            userDisplayName: userDisplayName,
            publicKeyX963: generated.publicKeyX963,
            signCount: 0,
            keyTag: generated.keyTag,
            keyPersistentRef: generated.keyPersistentRef,
            createdAt: Date(),
            hmacSecret: hmacSecret
        )
        guard keychain.saveCredential(metadata) else {
            enclave.deleteKey(tag: generated.keyTag)
            return failure(id: id, code: .internalError)
        }
        onCredentialsChanged()

        // 4. authData を電話側で組み立てる。
        guard let coseKey = COSEKeyBuilder.ec2ES256(publicKeyX963: generated.publicKeyX963) else {
            return failure(id: id, code: .internalError)
        }
        var authData = CryptoUtils.sha256(Data(rpId.utf8))
        var flags: UInt8 = 0x45 // UP | UV | AT
        if hmacSecret != nil { flags |= 0x20 } // ED: 拡張出力を付ける
        authData.append(flags)
        authData.append(Data.uint32BigEndian(0)) // sign_count = 0
        authData.append(BridgeConstants.aaguid)
        authData.append(Data.uint16BigEndian(UInt16(credentialId.count)))
        authData.append(credentialId)
        authData.append(coseKey)
        if hmacSecret != nil {
            // authenticator extension outputs: {"hmac-secret": true}
            authData.append(CBORValue.map([(.text("hmac-secret"), .bool(true))]).encoded())
        }

        // 5. attestation は fmt "none"、attestation 署名は作らない。
        return success(id: id, result: [
            "credential_id": credentialId.base64EncodedString(),
            "public_key_x963": generated.publicKeyX963.base64EncodedString(),
            "auth_data": authData.base64EncodedString(),
            "fmt": "none",
        ])
    }

    // MARK: - 3.3 get_assertion

    private func getAssertion(id: Int, request: [String: Any]) async -> [String: Any] {
        guard
            let rpId = request["rp_id"] as? String, !rpId.isEmpty,
            let clientDataHashB64 = request["client_data_hash"] as? String,
            let clientDataHash = Data(base64Encoded: clientDataHashB64),
            clientDataHash.count == 32
        else {
            return failure(id: id, code: .badRequest)
        }
        let allowB64 = request["allow_credential_ids"] as? [String] ?? []
        let allowIds = allowB64.compactMap { Data(base64Encoded: $0) }

        // PRF (hmac-secret) の第1段階は専用処理へ。
        if (request["hmac_phase"] as? String) == "eval" {
            return await evalHmacSecret(
                id: id, request: request, rpId: rpId,
                clientDataHash: clientDataHash, allowIds: allowIds
            )
        }

        // 1. rp_id が一致し、allow リスト (空なら全資格) に含まれる資格を探す。
        let candidates = keychain.allCredentials().filter { metadata in
            metadata.rpId == rpId
                && (allowIds.isEmpty || allowIds.contains(metadata.credentialId))
        }
        guard var metadata = candidates.first else {
            return failure(id: id, code: .noCredentials)
        }

        // 2. rp_id と user_name を画面に出し、「承認」タップを待つ (必須)。
        let approved = await approval.requestApproval(
            PendingApproval(
                requestId: id,
                operation: .getAssertion,
                rpId: rpId,
                userName: metadata.userName,
                requestedAt: Date()
            )
        )
        guard approved else { return failure(id: id, code: .userCancelled) }

        // 3. sign_count を +1 して永続化する。
        metadata.signCount &+= 1
        guard keychain.saveCredential(metadata) else {
            return failure(id: id, code: .internalError)
        }

        // 4. authData を電話側で組み立て、署名して返す。
        var authData = CryptoUtils.sha256(Data(rpId.utf8))
        authData.append(0x05) // flags: UP | UV
        authData.append(Data.uint32BigEndian(metadata.signCount))
        return signAndRespond(id: id, metadata: metadata, authData: authData, clientDataHash: clientDataHash)
    }

    /// authData || client_data_hash を Enclave 鍵で署名して assertion
    /// レスポンスを返す。この呼び出しが Face ID prompt を出す。
    private func signAndRespond(id: Int, metadata: CredentialMetadata, authData: Data, clientDataHash: Data) -> [String: Any] {
        var message = authData
        message.append(clientDataHash)
        let signature: Data
        do {
            signature = try enclave.sign(
                keyTag: metadata.keyTag,
                keyPersistentRef: metadata.keyPersistentRef,
                message: message,
                localizedReason: "\(metadata.rpId) へのサインインを承認"
            )
        } catch let code as BridgeErrorCode {
            return failure(id: id, code: code)
        } catch {
            return failure(id: id, code: .internalError)
        }

        return success(id: id, result: [
            "credential_id": metadata.credentialId.base64EncodedString(),
            "auth_data": authData.base64EncodedString(),
            "signature": signature.base64EncodedString(),
            "user_handle": metadata.userId.base64EncodedString(),
        ])
    }

    // MARK: - PRF (hmac-secret) 2段階フロー
    //
    // CTAP 層 (PC) が pinUvAuthProtocol の鍵で塩を復号してから渡してくる。
    // 第1段階 (eval): 資格を選び、通常の認証と同じ承認 + Face ID を通した
    //   ときだけ、資格の hmac 秘密で計算した生の出力を返す。あわせて
    //   60 秒有効な ticket を発行する。
    // 第2段階 (get_assertion_finish): PC が暗号化した拡張出力を埋め込んだ
    //   authData を電話が組み立て、ticket の文脈で署名する。
    // hmac 秘密そのものはどちらの段階でも電話の外に出ない。

    private func evalHmacSecret(id: Int, request: [String: Any], rpId: String, clientDataHash: Data, allowIds: [Data]) async -> [String: Any] {
        guard
            let salt1B64 = request["salt1"] as? String,
            let salt1 = Data(base64Encoded: salt1B64), salt1.count == 32
        else {
            return failure(id: id, code: .badRequest)
        }
        var salt2: Data? = nil
        if let salt2B64 = request["salt2"] as? String {
            guard let decoded = Data(base64Encoded: salt2B64), decoded.count == 32 else {
                return failure(id: id, code: .badRequest)
            }
            salt2 = decoded
        }

        let candidates = keychain.allCredentials().filter { metadata in
            metadata.rpId == rpId
                && (allowIds.isEmpty || allowIds.contains(metadata.credentialId))
        }
        guard let metadata = candidates.first else {
            return failure(id: id, code: .noCredentials)
        }
        // PRF 未対応の資格では承認を求めず、未対応だけを返す
        // (PC 側が通常の認証に落とす)。
        guard let hmacSecret = metadata.hmacSecret else {
            return success(id: id, result: [
                "supported": false,
                "credential_id": metadata.credentialId.base64EncodedString(),
            ])
        }

        let approved = await approval.requestApproval(
            PendingApproval(
                requestId: id,
                operation: .getAssertion,
                rpId: rpId,
                userName: metadata.userName,
                requestedAt: Date()
            )
        )
        guard approved else { return failure(id: id, code: .userCancelled) }

        var outputs = CryptoUtils.hmacSHA256(key: hmacSecret, message: salt1)
        if let salt2 {
            outputs.append(CryptoUtils.hmacSHA256(key: hmacSecret, message: salt2))
        }
        guard let ticket = CryptoUtils.randomBytes(count: 16) else {
            return failure(id: id, code: .internalError)
        }
        pendingPrf[ticket] = PendingPrfAssertion(
            metadata: metadata, clientDataHash: clientDataHash, createdAt: Date()
        )
        return success(id: id, result: [
            "supported": true,
            "ticket": ticket.base64EncodedString(),
            "credential_id": metadata.credentialId.base64EncodedString(),
            "hmac_outputs": outputs.base64EncodedString(),
        ])
    }

    private func getAssertionFinish(id: Int, request: [String: Any]) async -> [String: Any] {
        guard
            let ticketB64 = request["ticket"] as? String,
            let ticket = Data(base64Encoded: ticketB64),
            let extB64 = request["auth_data_extensions"] as? String,
            let extensions = Data(base64Encoded: extB64)
        else {
            return failure(id: id, code: .badRequest)
        }
        guard
            let pending = pendingPrf.removeValue(forKey: ticket),
            Date().timeIntervalSince(pending.createdAt) <= 60
        else {
            return failure(id: id, code: .notFound)
        }

        var metadata = pending.metadata
        metadata.signCount &+= 1
        guard keychain.saveCredential(metadata) else {
            return failure(id: id, code: .internalError)
        }

        var authData = CryptoUtils.sha256(Data(metadata.rpId.utf8))
        authData.append(0x25) // flags: UP | UV | ED
        authData.append(Data.uint32BigEndian(metadata.signCount))
        authData.append(extensions)
        return signAndRespond(
            id: id, metadata: metadata, authData: authData,
            clientDataHash: pending.clientDataHash
        )
    }

    // MARK: - 3.4 list_credentials (管理用、署名なし・秘密情報なし)

    private func listCredentials(id: Int) -> [String: Any] {
        let items: [[String: Any]] = keychain.allCredentials().map { metadata in
            [
                "rp_id": metadata.rpId,
                "user_name": metadata.userName,
                "credential_id": metadata.credentialId.base64EncodedString(),
            ]
        }
        return success(id: id, result: ["credentials": items])
    }
}
