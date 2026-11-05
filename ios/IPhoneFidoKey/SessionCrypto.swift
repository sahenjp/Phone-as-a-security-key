import CryptoKit
import Foundation
import Security

/// セッション鍵一式 (BRIDGE-PROTOCOL 2)。
struct SessionKeys: Equatable {
    /// PC → Phone 方向の ChaCha20-Poly1305 鍵
    let pcToPhone: Data
    /// Phone → PC 方向の ChaCha20-Poly1305 鍵
    let phoneToPC: Data
    /// ハンドシェイク確認 MAC 用の鍵
    let confirm: Data
}

/// ハンドシェイクの鍵導出。
/// 文字列リテラル (info / salt の組み立て順) は BRIDGE-PROTOCOL 2 と完全一致させること。
/// `deriveSessionKeys` は入力→出力が仕様から追える純粋関数として切り出してあり、
/// Rust 側のテストベクタと突き合わせる対象はこの関数。
enum SessionCrypto {
    // MARK: HKDF (RFC 5869, SHA-256) — CryptoKit の HMAC で構成する

    static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        CryptoUtils.hmacSHA256(key: salt, message: ikm)
    }

    static func hkdfExpand(prk: Data, info: Data, outputByteCount: Int) -> Data {
        precondition(outputByteCount > 0 && outputByteCount <= 255 * 32)
        var output = Data()
        var previous = Data()
        var counter: UInt8 = 1
        while output.count < outputByteCount {
            var message = previous
            message.append(info)
            message.append(counter)
            previous = CryptoUtils.hmacSHA256(key: prk, message: message)
            output.append(previous)
            counter &+= 1
        }
        return output.prefix(outputByteCount)
    }

    // MARK: 鍵導出 (テストベクタ対象)

    /// - Parameters:
    ///   - ecdhSharedSecret: ECDH の x 座標 32 byte
    ///   - psk: ペアリング秘密 32 byte
    ///   - pcRandom: hello の pc_random 32 byte
    ///   - phoneRandom: hello_ack の phone_random 32 byte
    static func deriveSessionKeys(
        ecdhSharedSecret: Data,
        psk: Data,
        pcRandom: Data,
        phoneRandom: Data
    ) -> SessionKeys {
        // ikm = ecdh || PSK
        var ikm = ecdhSharedSecret
        ikm.append(psk)
        // salt = pc_random || phone_random
        var salt = pcRandom
        salt.append(phoneRandom)

        let prk = hkdfExtract(salt: salt, ikm: ikm)
        let pcToPhone = hkdfExpand(
            prk: prk,
            info: Data("iphone-fido v1 pc-to-phone".utf8),
            outputByteCount: 32
        )
        let phoneToPC = hkdfExpand(
            prk: prk,
            info: Data("iphone-fido v1 phone-to-pc".utf8),
            outputByteCount: 32
        )
        let confirm = hkdfExpand(
            prk: prk,
            info: Data("iphone-fido v1 confirm".utf8),
            outputByteCount: 32
        )
        return SessionKeys(pcToPhone: pcToPhone, phoneToPC: phoneToPC, confirm: confirm)
    }

    /// 確認 MAC: HMAC-SHA256(confirm_key, role || pc_random || phone_random)
    /// - Parameter role: "pc" または "phone" (ASCII そのまま)
    static func confirmMAC(confirmKey: Data, role: String, pcRandom: Data, phoneRandom: Data) -> Data {
        var message = Data(role.utf8)
        message.append(pcRandom)
        message.append(phoneRandom)
        return CryptoUtils.hmacSHA256(key: confirmKey, message: message)
    }
}

// MARK: - 一時 P-256 ECDH (Security framework の SecKey で生の共有秘密を取る)

final class EphemeralECDH {
    let privateKey: SecKey
    /// 自分の公開鍵 (x963 形式 65 byte)
    let publicKeyX963: Data

    init?() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
        }
        guard let pub = SecKeyCopyPublicKey(priv) else { return nil }
        var pubError: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(pub, &pubError) as Data? else {
            return nil
        }
        guard pubData.count == 65 else { return nil }
        self.privateKey = priv
        self.publicKeyX963 = pubData
    }

    /// 相手の x963 公開鍵と ECDH を行い、x 座標 32 byte を返す。
    func sharedSecret(withPeerPublicKeyX963 peerPublicKey: Data) -> Data? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var createError: Unmanaged<CFError>?
        guard let peerKey = SecKeyCreateWithData(
            peerPublicKey as CFData,
            attributes as CFDictionary,
            &createError
        ) else {
            return nil
        }
        var exchangeError: Unmanaged<CFError>?
        // ecdhKeyExchangeStandard は P-256 で x 座標を返す。
        guard let shared = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeStandard,
            peerKey,
            [:] as CFDictionary,
            &exchangeError
        ) as Data? else {
            return nil
        }
        return Self.normalizeSharedSecret(shared)
    }

    /// 共有秘密を 32 byte に正規化する (先行ゼロの有無の揺れを吸収)。
    static func normalizeSharedSecret(_ shared: Data) -> Data {
        if shared.count == 32 { return shared }
        if shared.count < 32 {
            var padded = Data(repeating: 0, count: 32 - shared.count)
            padded.append(shared)
            return padded
        }
        var trimmed = shared
        while trimmed.count > 32, trimmed.first == 0 {
            trimmed.removeFirst()
        }
        if trimmed.count > 32 {
            trimmed = trimmed.suffix(32)
        }
        return trimmed
    }
}

// MARK: - 暗号化フレーム (BRIDGE-PROTOCOL 2 後段)

/// payload = seq (8 byte BE) || ChaCha20-Poly1305 ciphertext || tag (16 byte)
/// nonce (12 byte) = 0x00000000 || seq (8 byte BE)
/// seq は方向ごとに 0 から単調増加し、受信側は一致しない seq を即座に拒否する。
final class SessionCipher {
    private let sendKey: SymmetricKey
    private let receiveKey: SymmetricKey
    private(set) var sendSeq: UInt64 = 0
    private(set) var receiveSeq: UInt64 = 0

    /// Phone 視点で初期化する (send = phone→pc, receive = pc→phone)。
    init(sessionKeys: SessionKeys) {
        self.sendKey = SymmetricKey(data: sessionKeys.phoneToPC)
        self.receiveKey = SymmetricKey(data: sessionKeys.pcToPhone)
    }

    static func nonce(forSeq seq: UInt64) -> Data {
        var nonce = Data([0, 0, 0, 0])
        nonce.append(Data.uint64BigEndian(seq))
        return nonce
    }

    func seal(_ plaintext: Data) throws -> Data {
        let seq = sendSeq
        let nonce = try ChaChaPoly.Nonce(data: Self.nonce(forSeq: seq))
        let sealed = try ChaChaPoly.seal(plaintext, using: sendKey, nonce: nonce)
        // ワイヤ形式には nonce を含めない (seq から復元できるため)。
        // CryptoKit の combined は nonce を含むので ciphertext + tag を自前で連結する。
        var frame = Data.uint64BigEndian(seq)
        frame.append(sealed.ciphertext)
        frame.append(sealed.tag)
        sendSeq &+= 1
        return frame
    }

    func open(_ frame: Data) throws -> Data {
        guard frame.count >= 8 + 16, let seq = frame.uint64BigEndianPrefix else {
            throw BridgeInternalError.crypto("encrypted frame too short")
        }
        guard seq == receiveSeq else {
            throw BridgeInternalError.crypto("unexpected seq \(seq), expected \(receiveSeq)")
        }
        let body = frame.subdata(in: 8..<frame.count)
        let ciphertext = body.prefix(body.count - 16)
        let tag = body.suffix(16)
        let nonce = try ChaChaPoly.Nonce(data: Self.nonce(forSeq: seq))
        let box = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertext),
            tag: Data(tag)
        )
        let plaintext = try ChaChaPoly.open(box, using: receiveKey)
        receiveSeq &+= 1
        return plaintext
    }
}
