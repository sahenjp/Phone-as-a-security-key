package site.sahen.phonefido

import android.os.Build
import java.math.BigInteger
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439), as used by the bridge session frames.
 *
 * On API 28+ this delegates to javax.crypto ("ChaCha20-Poly1305", whose
 * doFinal output is ciphertext || 16-byte tag — exactly the wire body).
 * minSdk is 26, and the platform cipher only exists from API 28, so
 * API 26/27 uses the hand-rolled implementation below. Both paths are the
 * same construction: Poly1305 key from the counter-0 block, encryption
 * starting at counter 1, MAC over the padded ciphertext framing.
 *
 * encrypt() returns ciphertext || tag; decrypt() takes ciphertext || tag
 * and throws on tag mismatch.
 */
object ChaChaPoly {
    private const val TAG_BYTES = 16

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "ChaCha20-Poly1305 needs a 32B key and 12B nonce" }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            cipher.doFinal(plaintext)
        } else {
            pureEncrypt(key, nonce, plaintext)
        }
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "ChaCha20-Poly1305 needs a 32B key and 12B nonce" }
        if (ciphertextAndTag.size < TAG_BYTES) throw BridgeException("ciphertext shorter than tag")
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            cipher.doFinal(ciphertextAndTag) // throws AEADBadTagException on a bad tag
        } else {
            pureDecrypt(key, nonce, ciphertextAndTag)
        }
    }

    // MARK: - Pure Kotlin implementation (RFC 8439), for API 26/27

    private fun pureEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val polyKey = chachaBlock(key, nonce, 0).copyOfRange(0, 32)
        val ciphertext = chacha20Xor(key, nonce, 1, plaintext)
        val tag = poly1305Mac(macData(ciphertext), polyKey)
        return ciphertext + tag
    }

    private fun pureDecrypt(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
        val ciphertext = ciphertextAndTag.copyOfRange(0, ciphertextAndTag.size - TAG_BYTES)
        val tag = ciphertextAndTag.copyOfRange(ciphertextAndTag.size - TAG_BYTES, ciphertextAndTag.size)
        val polyKey = chachaBlock(key, nonce, 0).copyOfRange(0, 32)
        val expected = poly1305Mac(macData(ciphertext), polyKey)
        if (!MessageDigest.isEqual(expected, tag)) {
            throw BridgeException("poly1305 tag mismatch")
        }
        return chacha20Xor(key, nonce, 1, ciphertext)
    }

    /** AEAD MAC framing with an empty AAD: pad16(ct) || le64(0) || le64(ct.size). */
    private fun macData(ciphertext: ByteArray): ByteArray {
        val pad = (16 - ciphertext.size % 16) % 16
        val out = ByteArray(ciphertext.size + pad + 16)
        ciphertext.copyInto(out, 0)
        writeLe64(out, ciphertext.size + pad, 0)
        writeLe64(out, ciphertext.size + pad + 8, ciphertext.size.toLong())
        return out
    }

    // MARK: ChaCha20 block function

    private fun chachaBlock(key: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
        val state = IntArray(16)
        // "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = readLe32(key, i * 4)
        state[12] = counter
        for (i in 0 until 3) state[13 + i] = readLe32(nonce, i * 4)

        val working = state.copyOf()
        repeat(10) {
            quarterRound(working, 0, 4, 8, 12)
            quarterRound(working, 1, 5, 9, 13)
            quarterRound(working, 2, 6, 10, 14)
            quarterRound(working, 3, 7, 11, 15)
            quarterRound(working, 0, 5, 10, 15)
            quarterRound(working, 1, 6, 11, 12)
            quarterRound(working, 2, 7, 8, 13)
            quarterRound(working, 3, 4, 9, 14)
        }
        val out = ByteArray(64)
        for (i in 0 until 16) {
            writeLe32(out, i * 4, working[i] + state[i])
        }
        return out
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
    }

    private fun chacha20Xor(key: ByteArray, nonce: ByteArray, initialCounter: Int, data: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        var counter = initialCounter
        var offset = 0
        while (offset < data.size) {
            val keystream = chachaBlock(key, nonce, counter)
            val n = minOf(64, data.size - offset)
            for (i in 0 until n) {
                out[offset + i] = (data[offset + i].toInt() xor keystream[i].toInt()).toByte()
            }
            counter++
            offset += n
        }
        return out
    }

    // MARK: Poly1305 (BigInteger arithmetic; p = 2^130 - 5)

    private fun poly1305Mac(message: ByteArray, key32: ByteArray): ByteArray {
        val p = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5))
        val clamp = BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)
        val r = littleEndianToBigInteger(key32.copyOfRange(0, 16)).and(clamp)
        val s = littleEndianToBigInteger(key32.copyOfRange(16, 32))

        var acc = BigInteger.ZERO
        var offset = 0
        while (offset < message.size) {
            val len = minOf(16, message.size - offset)
            val block = message.copyOfRange(offset, offset + len)
            val n = littleEndianToBigInteger(block).add(BigInteger.ONE.shiftLeft(8 * len))
            acc = acc.add(n).multiply(r).mod(p)
            offset += len
        }

        var tag = acc.add(s).mod(BigInteger.ONE.shiftLeft(128))
        val out = ByteArray(16)
        for (i in 0 until 16) {
            out[i] = tag.and(BigInteger.valueOf(0xFF)).toByte()
            tag = tag.shiftRight(8)
        }
        return out
    }

    private fun littleEndianToBigInteger(bytes: ByteArray): BigInteger =
        BigInteger(1, bytes.reversedArray())

    // MARK: little-endian scalar helpers

    private fun readLe32(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)

    private fun writeLe32(out: ByteArray, offset: Int, value: Int) {
        out[offset] = value.toByte()
        out[offset + 1] = (value ushr 8).toByte()
        out[offset + 2] = (value ushr 16).toByte()
        out[offset + 3] = (value ushr 24).toByte()
    }

    private fun writeLe64(out: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) {
            out[offset + i] = (value ushr (8 * i)).toByte()
        }
    }
}
