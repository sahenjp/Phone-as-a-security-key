import Foundation

// MARK: - プロジェクト定数 (BRIDGE-PROTOCOL.md が正)

enum BridgeConstants {
    /// iPhone 側待ち受けポート (usbmuxd / iproxy の転送先)
    static let listenPort: UInt16 = 18765
    /// フレーム payload の最大長 (1 MiB)
    static let maxFrameSize = 1_048_576
    /// プロトコルバージョン
    static let protocolVersion = 1
    /// 承認待ちのタイムアウト (秒)
    static let approvalTimeoutSeconds: TimeInterval = 60
    /// AAGUID: BRIDGE-PROTOCOL 3.2 の固定 16 byte
    /// (16 進表記 69 70 68 2d 66 69 64 6f 2d 30 30 30 30 30 30 31)
    static let aaguid = Data([
        0x69, 0x70, 0x68, 0x2d, 0x66, 0x69, 0x64, 0x6f,
        0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
    ])
}

// MARK: - 資格メタデータ (Keychain に JSON で保存する。秘密鍵そのものは含まない)

struct CredentialMetadata: Codable, Identifiable, Equatable {
    /// ランダム 32 byte
    var credentialId: Data
    var rpId: String
    var rpName: String?
    /// WebAuthn user.id (生バイト)
    var userId: Data
    var userName: String
    var userDisplayName: String?
    /// 公開鍵 (ANSI X9.63 形式 65 byte: 0x04 || X || Y)
    var publicKeyX963: Data
    var signCount: UInt32
    /// Secure Enclave 鍵を引くための application tag 文字列
    var keyTag: String
    /// SecKey の persistent ref (取得できた場合のみ)
    var keyPersistentRef: Data?
    var createdAt: Date
    /// hmac-secret (WebAuthn PRF) 用の資格ごとの秘密 (32 byte)。
    /// 作成時に PRF を有効化した資格だけが持つ。電話の外に出ない。
    /// 旧レコードには存在しないため Optional (nil = PRF 未対応の資格)。
    var hmacSecret: Data? = nil

    var id: Data { credentialId }

    /// 一覧表示用の短い credential_id 表記
    var shortCredentialId: String {
        credentialId.prefix(6).map { String(format: "%02x", $0) }.joined() + "…"
    }
}

// MARK: - 承認待ちリクエスト (UI 表示用)

struct PendingApproval: Identifiable, Equatable {
    enum Operation: String, Equatable {
        case createCredential = "create_credential"
        case getAssertion = "get_assertion"

        var displayName: String {
            switch self {
            case .createCredential: return "パスキーを作成"
            case .getAssertion: return "サインインを承認"
            }
        }
    }

    /// 暗号化チャネル内のリクエスト id
    var requestId: Int
    var operation: Operation
    var rpId: String
    var userName: String
    var requestedAt: Date

    var id: Int { requestId }
}

// MARK: - ブリッジ層のエラーコード (BRIDGE-PROTOCOL 3.5)

enum BridgeErrorCode: String, Error {
    case userCancelled = "user_cancelled"
    case noCredentials = "no_credentials"
    case notFound = "not_found"
    case internalError = "internal"
    case badRequest = "bad_request"
}

/// プロトコル内部エラー (接続を切るべきもの)
enum BridgeInternalError: Error, CustomStringConvertible {
    case framing(String)
    case handshake(String)
    case crypto(String)
    case io(String)

    var description: String {
        switch self {
        case .framing(let m): return "framing: \(m)"
        case .handshake(let m): return "handshake: \(m)"
        case .crypto(let m): return "crypto: \(m)"
        case .io(let m): return "io: \(m)"
        }
    }
}
