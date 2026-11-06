package site.sahen.phonefido

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyAgreement
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/** Session keys for one bridge connection (BRIDGE-PROTOCOL 2). */
class SessionKeys(
    /** PC -> Phone direction ChaCha20-Poly1305 key. */
    val pcToPhone: ByteArray,
    /** Phone -> PC direction ChaCha20-Poly1305 key. */
    val phoneToPc: ByteArray,
    /** Handshake confirmation MAC key. */
    val confirm: ByteArray
)

/**
 * Handshake key derivation. The string literals (HKDF info labels, salt
 * assembly order) must match BRIDGE-PROTOCOL 2 exactly.
 *
 * Cross-implementation known-answer vectors (shared with src/bridge.rs and
 * the Swift tests; inputs are consecutive byte sequences):
 *   ecdh = 0x20..0x3F, psk = 0x00..0x1F, pc_random = 0x40..0x5F, phone_random = 0x60..0x7F
 *   pc_to_phone = 093052a5a2a26a710fb010734f5569ebcd2ec65c8336122feb38ef1917cb5591
 *   phone_to_pc = f0681d919195bba9c5562d6148ca0673ad872ba80b20507c7e26352cc2f32d81
 *   confirm     = 2f1c882095510a5376a4a94d3bd711d0e8df3d17a0429d94c6cadf6bee2aad61
 *   confirm MAC "pc"    -> BQIUMQKwysvX3l9RZz70MFccHqYuCKlFc+W+MDSo23Q=
 *   confirm MAC "phone" -> +KjEbAbdyW+wvCnE5d0wnOhoCjyHcMgc4sEAgElXGcQ=
 */
object SessionCrypto {
    // HKDF (RFC 5869, SHA-256), hand-rolled over HMAC like the Swift side.

    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray =
        CryptoUtils.hmacSHA256(key = salt, message = ikm)

    fun hkdfExpand(prk: ByteArray, info: ByteArray, outputByteCount: Int): ByteArray {
        require(outputByteCount in 1..(255 * 32)) { "invalid HKDF output length" }
        val out = ByteArray(outputByteCount)
        var previous = ByteArray(0)
        var counter = 1
        var written = 0
        while (written < outputByteCount) {
            val message = previous + info + byteArrayOf(counter.toByte())
            previous = CryptoUtils.hmacSHA256(key = prk, message = message)
            val n = minOf(previous.size, outputByteCount - written)
            previous.copyInto(out, written, 0, n)
            written += n
            counter++
        }
        return out
    }

    fun deriveSessionKeys(
        ecdhSharedSecret: ByteArray,
        psk: ByteArray,
        pcRandom: ByteArray,
        phoneRandom: ByteArray
    ): SessionKeys {
        // ikm = ecdh || PSK; salt = pc_random || phone_random
        val ikm = ecdhSharedSecret + psk
        val salt = pcRandom + phoneRandom
        val prk = hkdfExtract(salt, ikm)
        return SessionKeys(
            pcToPhone = hkdfExpand(prk, "iphone-fido v1 pc-to-phone".toByteArray(Charsets.UTF_8), 32),
            phoneToPc = hkdfExpand(prk, "iphone-fido v1 phone-to-pc".toByteArray(Charsets.UTF_8), 32),
            confirm = hkdfExpand(prk, "iphone-fido v1 confirm".toByteArray(Charsets.UTF_8), 32)
        )
    }

    /** Confirmation MAC: HMAC-SHA256(confirm_key, role || pc_random || phone_random); role is "pc" or "phone". */
    fun confirmMAC(confirmKey: ByteArray, role: String, pcRandom: ByteArray, phoneRandom: ByteArray): ByteArray {
        val message = role.toByteArray(Charsets.UTF_8) + pcRandom + phoneRandom
        return CryptoUtils.hmacSHA256(key = confirmKey, message = message)
    }
}

/** EC P-256 helpers shared by the ephemeral handshake keys and credential keys. */
object Ec {
    fun parameterSpec(): ECParameterSpec {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        return parameters.getParameterSpec(ECParameterSpec::class.java)
    }

    /** ANSI X9.63 encoding: 0x04 || X(32) || Y(32). */
    fun x963(publicKey: ECPublicKey): ByteArray =
        byteArrayOf(0x04) + toFixed32(publicKey.w.affineX) + toFixed32(publicKey.w.affineY)

    fun publicKeyFromX963(x963: ByteArray): ECPublicKey {
        require(x963.size == 65 && x963[0] == 0x04.toByte()) { "not an x963 P-256 key" }
        val x = BigInteger(1, x963.copyOfRange(1, 33))
        val y = BigInteger(1, x963.copyOfRange(33, 65))
        val spec = ECPublicKeySpec(ECPoint(x, y), parameterSpec())
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    /** Big-endian fixed 32-byte encoding (drops a sign byte, left-pads zeros). */
    fun toFixed32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        raw.copyInto(out, 32 - n, raw.size - n)
        return out
    }

    /** Normalize an ECDH result to exactly 32 bytes (providers differ on leading zeros). */
    fun normalizeSharedSecret(shared: ByteArray): ByteArray {
        if (shared.size == 32) return shared
        if (shared.size < 32) {
            val out = ByteArray(32)
            shared.copyInto(out, 32 - shared.size)
            return out
        }
        var trimmed = shared
        while (trimmed.size > 32 && trimmed[0] == 0.toByte()) {
            trimmed = trimmed.copyOfRange(1, trimmed.size)
        }
        if (trimmed.size > 32) {
            trimmed = trimmed.copyOfRange(trimmed.size - 32, trimmed.size)
        }
        return trimmed
    }
}

/** Per-connection ephemeral P-256 ECDH key pair (software key, never stored). */
class EphemeralECDH {
    private val privateKey: PrivateKey

    /** Own public key in x963 form (65 bytes). */
    val publicKeyX963: ByteArray

    init {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = generator.generateKeyPair()
        privateKey = keyPair.private
        publicKeyX963 = Ec.x963(keyPair.public as ECPublicKey)
    }

    /** ECDH with the peer's x963 public key; returns the x coordinate (32 bytes), or null on failure. */
    fun sharedSecret(peerPublicKeyX963: ByteArray): ByteArray? = try {
        val peerKey = Ec.publicKeyFromX963(peerPublicKeyX963)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(peerKey, true)
        Ec.normalizeSharedSecret(agreement.generateSecret())
    } catch (e: Exception) {
        null
    }
}

/**
 * Encrypted frame channel (BRIDGE-PROTOCOL 2, second half).
 *
 * payload = seq (8 bytes BE) || ChaCha20-Poly1305 ciphertext || tag (16 bytes)
 * nonce (12 bytes) = 0x00000000 || seq (8 bytes BE)
 * seq increases monotonically per direction starting at 0; a received seq
 * that does not match exactly is rejected and the connection is dropped.
 */
class SessionCipher(sessionKeys: SessionKeys) {
    private val sendKey: ByteArray = sessionKeys.phoneToPc // phone perspective
    private val receiveKey: ByteArray = sessionKeys.pcToPhone
    private var sendSeq = 0L
    private var receiveSeq = 0L

    fun seal(plaintext: ByteArray): ByteArray {
        val seq = sendSeq
        val body = ChaChaPoly.encrypt(sendKey, nonce(seq), plaintext)
        sendSeq++
        return CryptoUtils.uint64BigEndian(seq) + body
    }

    fun open(frame: ByteArray): ByteArray {
        if (frame.size < 8 + 16) throw BridgeException("encrypted frame too short")
        val seq = CryptoUtils.readUint64BigEndian(frame)
        if (seq != receiveSeq) {
            throw BridgeException("unexpected seq $seq, expected $receiveSeq")
        }
        val body = frame.copyOfRange(8, frame.size)
        val plaintext = ChaChaPoly.decrypt(receiveKey, nonce(seq), body)
        receiveSeq++
        return plaintext
    }

    private fun nonce(seq: Long): ByteArray =
        ByteArray(4) + CryptoUtils.uint64BigEndian(seq)
}
