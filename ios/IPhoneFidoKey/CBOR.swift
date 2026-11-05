import Foundation

/// 最小限の CBOR エンコーダ。
/// WebAuthn / CTAP2 で必要なのは COSE_Key の生成だけなので、
/// int / bytes / text / map / array の符号化のみを実装する。
/// map のキー順は呼び出し側が与えた順をそのまま使う
/// (COSE_Key では canonical 順 1, 3, -1, -2, -3 で渡すこと)。
enum CBORValue {
    case uint(UInt64)
    /// 負の整数そのもの (例: -7)。内部表現は major type 1 の n = -1 - value。
    case int(Int64)
    case bytes(Data)
    case text(String)
    case bool(Bool)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])

    func encoded() -> Data {
        var out = Data()
        appendEncoded(into: &out)
        return out
    }

    private func appendEncoded(into out: inout Data) {
        switch self {
        case .bool(let b):
            CBORWriter.writeHeader(major: 7, value: b ? 21 : 20, into: &out)
        case .uint(let v):
            CBORWriter.writeHeader(major: 0, value: v, into: &out)
        case .int(let v):
            if v >= 0 {
                CBORWriter.writeHeader(major: 0, value: UInt64(v), into: &out)
            } else {
                // RFC 8949: negative value is encoded as -1 - n
                CBORWriter.writeHeader(major: 1, value: UInt64(-1 - v), into: &out)
            }
        case .bytes(let d):
            CBORWriter.writeHeader(major: 2, value: UInt64(d.count), into: &out)
            out.append(d)
        case .text(let s):
            let utf8 = Data(s.utf8)
            CBORWriter.writeHeader(major: 3, value: UInt64(utf8.count), into: &out)
            out.append(utf8)
        case .array(let items):
            CBORWriter.writeHeader(major: 4, value: UInt64(items.count), into: &out)
            for item in items {
                item.appendEncoded(into: &out)
            }
        case .map(let pairs):
            CBORWriter.writeHeader(major: 5, value: UInt64(pairs.count), into: &out)
            for (k, v) in pairs {
                k.appendEncoded(into: &out)
                v.appendEncoded(into: &out)
            }
        }
    }
}

private enum CBORWriter {
    static func writeHeader(major: UInt8, value: UInt64, into out: inout Data) {
        let mt = major << 5
        switch value {
        case 0..<24:
            out.append(mt | UInt8(value))
        case 24...0xff:
            out.append(mt | 24)
            out.append(UInt8(value))
        case 0x100...0xffff:
            out.append(mt | 25)
            out.append(UInt8((value >> 8) & 0xff))
            out.append(UInt8(value & 0xff))
        case 0x1_0000...0xffff_ffff:
            out.append(mt | 26)
            for shift in stride(from: 24, through: 0, by: -8) {
                out.append(UInt8((value >> shift) & 0xff))
            }
        default:
            out.append(mt | 27)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((value >> shift) & 0xff))
            }
        }
    }
}

enum COSEKeyBuilder {
    /// COSE_Key (EC2 / ES256) を組み立てる。
    /// map {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    /// - Parameter publicKeyX963: 0x04 || X(32B) || Y(32B) の 65 byte
    static func ec2ES256(publicKeyX963: Data) -> Data? {
        guard publicKeyX963.count == 65, publicKeyX963.first == 0x04 else {
            return nil
        }
        let x = publicKeyX963.subdata(in: 1..<33)
        let y = publicKeyX963.subdata(in: 33..<65)
        let value: CBORValue = .map([
            (.int(1), .int(2)),     // kty: EC2
            (.int(3), .int(-7)),    // alg: ES256
            (.int(-1), .int(1)),    // crv: P-256
            (.int(-2), .bytes(x)),  // x
            (.int(-3), .bytes(y)),  // y
        ])
        return value.encoded()
    }
}
