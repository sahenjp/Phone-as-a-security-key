package site.sahen.phonefido

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Small cryptographic and encoding helpers (mirror of the Swift CryptoUtils). */
object CryptoUtils {
    private val secureRandom = SecureRandom()

    fun randomBytes(count: Int): ByteArray = ByteArray(count).also { secureRandom.nextBytes(it) }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun hmacSHA256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /** Length-checked constant-time comparison (used for the handshake confirm MAC). */
    fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    // MARK: - Base64 (standard alphabet, with padding — same as Swift's base64EncodedString)

    fun base64Encode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.NO_WRAP)

    /** Returns null instead of throwing on malformed input. */
    fun base64Decode(text: String): ByteArray? = try {
        Base64.decode(text, Base64.DEFAULT)
    } catch (e: IllegalArgumentException) {
        null
    }

    // MARK: - Base32 (RFC 4648, no padding)

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** 32 bytes encode to exactly 52 characters (BRIDGE-PROTOCOL 1). */
    fun base32EncodeNoPadding(data: ByteArray): String {
        val result = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsInBuffer = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsInBuffer += 8
            while (bitsInBuffer >= 5) {
                bitsInBuffer -= 5
                val index = (buffer shr bitsInBuffer) and 0x1F
                result.append(BASE32_ALPHABET[index])
            }
        }
        if (bitsInBuffer > 0) {
            val index = (buffer shl (5 - bitsInBuffer)) and 0x1F
            result.append(BASE32_ALPHABET[index])
        }
        return result.toString()
    }

    // MARK: - SAS (BRIDGE-PROTOCOL 1)

    /**
     * SHA-256(PSK || "iphone-fido-sas-v1"), first 3 bytes as an unsigned
     * big-endian integer mod 1_000_000, zero-padded to 6 digits.
     * Known answer: PSK = bytes 0x00..0x1F -> "212523" (see src/bridge.rs tests).
     */
    fun sasCode(psk: ByteArray): String {
        val digest = sha256(psk + "iphone-fido-sas-v1".toByteArray(Charsets.UTF_8))
        var value = 0
        for (i in 0 until 3) {
            value = (value shl 8) or (digest[i].toInt() and 0xFF)
        }
        return (value % 1_000_000).toString().padStart(6, '0')
    }

    // MARK: - Hex / big-endian helpers

    private const val HEX_DIGITS = "0123456789abcdef"

    fun toHex(data: ByteArray): String {
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_DIGITS[v shr 4])
            sb.append(HEX_DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    fun uint16BigEndian(value: Int): ByteArray = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    fun uint32BigEndian(value: Long): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte()
    )

    fun uint64BigEndian(value: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) {
            out[i] = (value ushr (56 - 8 * i)).toByte()
        }
        return out
    }

    fun readUint64BigEndian(data: ByteArray, offset: Int = 0): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return value
    }
}
