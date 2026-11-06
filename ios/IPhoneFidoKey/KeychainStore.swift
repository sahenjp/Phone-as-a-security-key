import Foundation
import Security

/// Keychain 保存層。
/// - ペアリング PSK (32 byte)
/// - 資格メタデータ (CredentialMetadata の JSON)
/// どちらも kSecClassGenericPassword / WhenUnlockedThisDeviceOnly で保存し、
/// iCloud バックアップや端末移行で外に出ないようにする。
/// Secure Enclave 内の秘密鍵そのものはここには置かない (参照だけを保持する)。
final class KeychainStore {
    static let shared = KeychainStore()

    private let service = "iphone-fido-key"
    private let pairingAccount = "pairing.psk.v1"
    private let credentialAccountPrefix = "cred."

    private init() {}

    // MARK: - 汎用 (generic password)

    private func saveGeneric(account: String, value: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            for (k, v) in attributes {
                addQuery[k] = v
            }
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }
        return status == errSecSuccess
    }

    private func loadGeneric(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private func deleteGeneric(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - ペアリング PSK

    func loadPSK() -> Data? {
        guard let psk = loadGeneric(account: pairingAccount), psk.count == 32 else {
            return nil
        }
        return psk
    }

    var isPaired: Bool { loadPSK() != nil }

    /// PSK を新規生成して保存する。既存の PSK は上書きされ、
    /// 旧 PSK でペアリングした PC とは通信できなくなる。
    @discardableResult
    func generateAndSavePSK() -> Data? {
        guard let psk = CryptoUtils.randomBytes(count: 32) else { return nil }
        return saveGeneric(account: pairingAccount, value: psk) ? psk : nil
    }

    /// 外部から与えられた PSK (QR コードで読み取った 32 byte) を保存する。
    /// 既存の PSK は上書きされ、旧 PSK でペアリングした PC とは通信できなくなる。
    @discardableResult
    func savePSK(_ psk: Data) -> Bool {
        guard psk.count == 32 else { return false }
        return saveGeneric(account: pairingAccount, value: psk)
    }

    @discardableResult
    func deletePSK() -> Bool {
        deleteGeneric(account: pairingAccount)
    }

    // MARK: - 資格メタデータ

    private func account(for credentialId: Data) -> String {
        credentialAccountPrefix + credentialId.base64EncodedString()
    }

    @discardableResult
    func saveCredential(_ metadata: CredentialMetadata) -> Bool {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard let data = try? encoder.encode(metadata) else { return false }
        return saveGeneric(account: account(for: metadata.credentialId), value: data)
    }

    func loadCredential(credentialId: Data) -> CredentialMetadata? {
        guard let data = loadGeneric(account: account(for: credentialId)) else { return nil }
        return decodeCredential(data)
    }

    func allCredentials() -> [CredentialMetadata] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess, let dicts = items as? [[String: Any]] else {
            return []
        }
        var result: [CredentialMetadata] = []
        for dict in dicts {
            guard let account = dict[kSecAttrAccount as String] as? String,
                  account.hasPrefix(credentialAccountPrefix),
                  let data = dict[kSecValueData as String] as? Data,
                  let metadata = decodeCredential(data)
            else { continue }
            result.append(metadata)
        }
        return result.sorted { $0.createdAt < $1.createdAt }
    }

    @discardableResult
    func deleteCredential(credentialId: Data) -> Bool {
        deleteGeneric(account: account(for: credentialId))
    }

    private func decodeCredential(_ data: Data) -> CredentialMetadata? {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(CredentialMetadata.self, from: data)
    }
}
