import XCTest
@testable import IPhoneFidoKey

/// 暗号相互運用の既知答テスト。
/// 期待値は BRIDGE-PROTOCOL の定義から独立に計算したもので、
/// Rust 側実装のテストベクタと一致しなければならない。
/// (入力はいずれも 00.., 20.., 40.., 60.. から始まる連続バイト列)
final class BridgeCoreTests: XCTestCase {

    private func seq(_ start: UInt8) -> Data {
        Data((0..<32).map { start &+ UInt8($0) })
    }

    // MARK: - ハンドシェイク鍵導出 (BRIDGE-PROTOCOL 2)

    func testDeriveSessionKeysKnownVector() {
        let keys = SessionCrypto.deriveSessionKeys(
            ecdhSharedSecret: seq(0x20),
            psk: seq(0x00),
            pcRandom: seq(0x40),
            phoneRandom: seq(0x60)
        )
        XCTAssertEqual(
            keys.pcToPhone.hexString,
            "093052a5a2a26a710fb010734f5569ebcd2ec65c8336122feb38ef1917cb5591"
        )
        XCTAssertEqual(
            keys.phoneToPC.hexString,
            "f0681d919195bba9c5562d6148ca0673ad872ba80b20507c7e26352cc2f32d81"
        )
        XCTAssertEqual(
            keys.confirm.hexString,
            "2f1c882095510a5376a4a94d3bd711d0e8df3d17a0429d94c6cadf6bee2aad61"
        )
    }

    func testConfirmMACsKnownVector() {
        let keys = SessionCrypto.deriveSessionKeys(
            ecdhSharedSecret: seq(0x20),
            psk: seq(0x00),
            pcRandom: seq(0x40),
            phoneRandom: seq(0x60)
        )
        let pcMAC = SessionCrypto.confirmMAC(
            confirmKey: keys.confirm, role: "pc",
            pcRandom: seq(0x40), phoneRandom: seq(0x60)
        )
        XCTAssertEqual(pcMAC.base64EncodedString(), "BQIUMQKwysvX3l9RZz70MFccHqYuCKlFc+W+MDSo23Q=")

        let phoneMAC = SessionCrypto.confirmMAC(
            confirmKey: keys.confirm, role: "phone",
            pcRandom: seq(0x40), phoneRandom: seq(0x60)
        )
        XCTAssertEqual(phoneMAC.base64EncodedString(), "+KjEbAbdyW+wvCnE5d0wnOhoCjyHcMgc4sEAgElXGcQ=")
    }

    // MARK: - ペアリング表示 (BRIDGE-PROTOCOL 1)

    func testBase32OfPSK() {
        let encoded = CryptoUtils.base32EncodeNoPadding(seq(0x00))
        XCTAssertEqual(encoded, "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ")
        XCTAssertEqual(encoded.count, 52)
    }

    func testSASCode() {
        XCTAssertEqual(CryptoUtils.sasCode(for: seq(0x00)), "212523")
    }

    // MARK: - COSE_Key / authData (BRIDGE-PROTOCOL 3.2)

    func testCOSEKeyEncoding() {
        var x963 = Data([0x04])
        x963.append(seq(0x00)) // x
        x963.append(seq(0x20)) // y
        let cose = COSEKeyBuilder.ec2ES256(publicKeyX963: x963)
        XCTAssertEqual(
            cose?.hexString,
            "a5010203262001215820"
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "225820"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )
    }

    func testAuthDataForCreateKnownVector() {
        var x963 = Data([0x04])
        x963.append(seq(0x00))
        x963.append(seq(0x20))
        let cose = COSEKeyBuilder.ec2ES256(publicKeyX963: x963)!
        let credentialId = Data((0..<32).map { UInt8(0x50 + $0) })

        var authData = CryptoUtils.sha256(Data("github.com".utf8))
        authData.append(0x45)
        authData.append(Data.uint32BigEndian(0))
        authData.append(BridgeConstants.aaguid)
        authData.append(Data.uint16BigEndian(UInt16(credentialId.count)))
        authData.append(credentialId)
        authData.append(cose)

        XCTAssertEqual(
            authData.hexString,
            "3aeb002460381c6f258e8395d3026f571f0d9a76488dcd837639b13aed316560"
                + "45" + "00000000"
                + "6970682d6669646f2d30303030303031"
                + "0020"
                + "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
                + "a5010203262001215820"
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "225820"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )
    }

    // MARK: - 暗号化フレーム (BRIDGE-PROTOCOL 2 後段)

    func testNonceLayout() {
        XCTAssertEqual(SessionCipher.nonce(forSeq: 0).hexString, "000000000000000000000000")
        XCTAssertEqual(SessionCipher.nonce(forSeq: 1).hexString, "000000000000000000000001")
        XCTAssertEqual(
            SessionCipher.nonce(forSeq: 0x0102030405060708).hexString,
            "000000000102030405060708"
        )
    }

    func testCipherRoundTripAndSeqEnforcement() throws {
        let keys = SessionCrypto.deriveSessionKeys(
            ecdhSharedSecret: seq(0x20),
            psk: seq(0x00),
            pcRandom: seq(0x40),
            phoneRandom: seq(0x60)
        )
        // phone 視点の cipher と、鍵を入れ替えた pc 視点の cipher で往復させる。
        let phone = SessionCipher(sessionKeys: keys)
        let pc = SessionCipher(sessionKeys: SessionKeys(
            pcToPhone: keys.phoneToPC,
            phoneToPC: keys.pcToPhone,
            confirm: keys.confirm
        ))

        let plaintext = Data(#"{"op":"ping","id":1}"#.utf8)
        let frame = try phone.seal(plaintext)
        XCTAssertEqual(frame.uint64BigEndianPrefix, 0)
        XCTAssertEqual(frame.count, 8 + plaintext.count + 16)
        XCTAssertEqual(try pc.open(frame), plaintext)

        // 同じフレームの再送 (seq 不一致) は拒否される。
        XCTAssertThrowsError(try pc.open(frame))

        // 2 通目も seq が進んで往復できる。
        let frame2 = try phone.seal(plaintext)
        XCTAssertEqual(frame2.uint64BigEndianPrefix, 1)
        XCTAssertEqual(try pc.open(frame2), plaintext)
    }

    // MARK: - ECDH (SecKey 経由)

    func testEphemeralECDHMatchesBothWays() {
        let a = EphemeralECDH()
        let b = EphemeralECDH()
        XCTAssertNotNil(a)
        XCTAssertNotNil(b)
        guard let a, let b else { return }
        let secretA = a.sharedSecret(withPeerPublicKeyX963: b.publicKeyX963)
        let secretB = b.sharedSecret(withPeerPublicKeyX963: a.publicKeyX963)
        XCTAssertNotNil(secretA)
        XCTAssertEqual(secretA, secretB)
        XCTAssertEqual(secretA?.count, 32)
    }

    func testNormalizeSharedSecret() {
        XCTAssertEqual(EphemeralECDH.normalizeSharedSecret(seq(0x00)).count, 32)

        let short = Data(repeating: 0xaa, count: 31)
        let padded = EphemeralECDH.normalizeSharedSecret(short)
        XCTAssertEqual(padded.count, 32)
        XCTAssertEqual(padded.first, 0)
        XCTAssertEqual(padded.suffix(31), short)

        var long = Data([0x00])
        long.append(seq(0x00))
        XCTAssertEqual(EphemeralECDH.normalizeSharedSecret(long), seq(0x00))
    }
}
