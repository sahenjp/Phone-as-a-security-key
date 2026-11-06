import Foundation
import LocalAuthentication
import Security

struct GeneratedEnclaveKey {
    var publicKeyX963: Data
    var keyTag: String
    var keyPersistentRef: Data?
}

/// Secure Enclave 鍵ストア。
///
/// 方針 (BRIDGE-PROTOCOL 3.2):
/// - 資格ごとに P-256 鍵を Enclave 内に生成し、秘密鍵は端末外に出さない。
/// - access control は .privateKeyUsage + .biometryCurrentSet。
///   鍵の「生成」自体では生体認証 prompt は出さず、「使用 (署名)」のたびに
///   Face ID を必須にする。署名呼び出しごとに新しい LAContext を作り、
///   先に 1 回だけ evaluatePolicy で評価してから、その評価済み
///   コンテキストを鍵の取り出しと署名の両方に渡す (プロンプトは 1 回)。
final class SecureEnclaveKeyStore {
    static let shared = SecureEnclaveKeyStore()

    private init() {}

    static func keyTag(for credentialId: Data) -> String {
        "iphfido.cred." + credentialId.hexString
    }

    // MARK: - 生成

    func generateKey(credentialId: Data) throws -> GeneratedEnclaveKey {
        let tag = Self.keyTag(for: credentialId)

        var aclError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &aclError
        ) else {
            throw BridgeErrorCode.internalError
        }

        let privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessControl as String: accessControl,
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]

        var createError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) else {
            throw BridgeErrorCode.internalError
        }
        guard let publicKeyX963 = Self.publicKeyX963(of: privateKey) else {
            throw BridgeErrorCode.internalError
        }
        return GeneratedEnclaveKey(
            publicKeyX963: publicKeyX963,
            keyTag: tag,
            keyPersistentRef: persistentRef(forTag: tag)
        )
    }

    static func publicKeyX963(of privateKey: SecKey) -> Data? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }
        return data
    }

    // MARK: - 参照の取得

    private func persistentRef(forTag tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnPersistentRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    /// 署名用に秘密鍵を取り出す。
    /// 渡される LAContext は呼び出し側 (sign) で評価済みのため、
    /// ここでの取り出しでは Face ID prompt は出ない。
    private func privateKey(
        tag: String,
        persistentRef: Data?,
        context: LAContext
    ) -> SecKey? {
        if let persistentRef,
           let key = privateKey(persistentRef: persistentRef, context: context) {
            return key
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else { return nil }
        return (item as! SecKey)
    }

    private func privateKey(persistentRef: Data, context: LAContext) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValuePersistentRef as String: persistentRef,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else { return nil }
        return (item as! SecKey)
    }

    // MARK: - 署名 (Face ID prompt が出る操作)

    /// authData || clientDataHash を署名し、ASN.1 DER 形式で返す (WebAuthn の ES256 形式)。
    /// - Throws: ユーザーが Face ID をキャンセルした場合は BridgeErrorCode.userCancelled、
    ///   それ以外は BridgeErrorCode.internalError。
    func sign(
        keyTag: String,
        keyPersistentRef: Data?,
        message: Data,
        localizedReason: String
    ) async throws -> Data {
        // 認証コンテキストは操作ごとに新規作成する (使い回さない)。
        let context = LAContext()
        context.localizedReason = localizedReason
        context.localizedCancelTitle = NSLocalizedString(
            "common.cancel",
            comment: "Cancel button title in the biometric prompt"
        )

        // Face ID はこの操作につき 1 回だけ評価する。先にここで評価し、
        // 評価済みの同じコンテキストを鍵の取り出し (SecItemCopyMatching) と
        // 署名 (SecKeyCreateSignature) の両方に渡す。未評価のコンテキストを
        // 両方に渡すと、取り出しと署名で別々に評価が走ってプロンプトが
        // 2 回出てしまう。
        do {
            _ = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: localizedReason
            )
        } catch let error as LAError where error.code == .userCancel {
            throw BridgeErrorCode.userCancelled
        } catch {
            // 生体認証が使えない・ロックアウト・認証失敗などは内部エラー扱い。
            throw BridgeErrorCode.internalError
        }

        guard let privateKey = privateKey(
            tag: keyTag,
            persistentRef: keyPersistentRef,
            context: context
        ) else {
            throw BridgeErrorCode.notFound
        }
        guard SecKeyIsAlgorithmSupported(
            privateKey,
            .sign,
            .ecdsaSignatureMessageX962SHA256
        ) else {
            throw BridgeErrorCode.internalError
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            if let cfError = error?.takeRetainedValue(),
               CFErrorGetCode(cfError) == Int(errSecUserCanceled) {
                throw BridgeErrorCode.userCancelled
            }
            throw BridgeErrorCode.internalError
        }
        return signature
    }

    // MARK: - 削除

    @discardableResult
    func deleteKey(tag: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
