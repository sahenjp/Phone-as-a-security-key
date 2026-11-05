import CryptoKit
import Foundation
import Security

enum CryptoUtils {
    /// 暗号用乱数 (SecRandomCopyBytes)
    static func randomBytes(count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { return nil }
        return Data(bytes)
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hmacSHA256(key: Data, message: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: key)
        )
        return Data(mac)
    }

    /// タイミング差を避ける比較 (長さが違う場合は即 false)
    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }

    // MARK: - Base32 (RFC 4648, padding なし)

    private static let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    static func base32EncodeNoPadding(_ data: Data) -> String {
        var result = ""
        result.reserveCapacity((data.count * 8 + 4) / 5)
        var buffer: UInt32 = 0
        var bitsInBuffer = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bitsInBuffer += 8
            while bitsInBuffer >= 5 {
                bitsInBuffer -= 5
                let index = Int((buffer >> bitsInBuffer) & 0x1f)
                result.append(base32Alphabet[index])
            }
        }
        if bitsInBuffer > 0 {
            let index = Int((buffer << (5 - bitsInBuffer)) & 0x1f)
            result.append(base32Alphabet[index])
        }
        return result
    }

    // MARK: - SAS (BRIDGE-PROTOCOL 1)

    /// SHA-256(PSK || "iphone-fido-sas-v1") の先頭 3 byte を整数として mod 1_000_000
    static func sasCode(for psk: Data) -> String {
        var input = psk
        input.append(Data("iphone-fido-sas-v1".utf8))
        let digest = sha256(input)
        var value: UInt32 = 0
        for i in 0..<3 {
            value = (value << 8) | UInt32(digest[i])
        }
        return String(format: "%06d", value % 1_000_000)
    }
}

// MARK: - Data の 16 進 / big-endian 補助

extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var data = Data()
        data.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let byte = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
            data.append(byte)
            i += 2
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// 先頭に big-endian UInt32 を付け足す等で使う
    static func uint32BigEndian(_ value: UInt32) -> Data {
        var v = value.bigEndian
        return Data(bytes: &v, count: 4)
    }

    static func uint16BigEndian(_ value: UInt16) -> Data {
        var v = value.bigEndian
        return Data(bytes: &v, count: 2)
    }

    static func uint64BigEndian(_ value: UInt64) -> Data {
        var v = value.bigEndian
        return Data(bytes: &v, count: 8)
    }

    /// 先頭 8 byte を big-endian UInt64 として読む (フレーム seq 用)
    var uint64BigEndianPrefix: UInt64? {
        guard count >= 8 else { return nil }
        var value: UInt64 = 0
        for i in 0..<8 {
            value = (value << 8) | UInt64(self[i])
        }
        return value
    }
}
