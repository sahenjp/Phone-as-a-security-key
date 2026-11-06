package site.sahen.phonefido

import java.io.ByteArrayOutputStream

/**
 * Minimal CBOR encoder — only what WebAuthn needs (the COSE_Key built by
 * [CoseKeyBuilder]). Port of the Swift CBOR.swift: int / bytes / text /
 * bool / array / map. Map key order is the caller's responsibility
 * (COSE_Key is passed in canonical order 1, 3, -1, -2, -3).
 */
sealed class CborValue {
    abstract fun appendEncoded(out: ByteArrayOutputStream)

    fun encoded(): ByteArray {
        val out = ByteArrayOutputStream()
        appendEncoded(out)
        return out.toByteArray()
    }

    class Uint(val value: Long) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) = writeHeader(out, 0, value)
    }

    /** A possibly negative integer (e.g. -7). Major type 1 encodes n = -1 - value. */
    class IntVal(val value: Long) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) {
            if (value >= 0) writeHeader(out, 0, value) else writeHeader(out, 1, -1 - value)
        }
    }

    class Bytes(val value: ByteArray) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) {
            writeHeader(out, 2, value.size.toLong())
            out.write(value)
        }
    }

    class Text(val value: String) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) {
            val utf8 = value.toByteArray(Charsets.UTF_8)
            writeHeader(out, 3, utf8.size.toLong())
            out.write(utf8)
        }
    }

    class Bool(val value: Boolean) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) =
            writeHeader(out, 7, if (value) 21 else 20)
    }

    class Arr(val items: List<CborValue>) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) {
            writeHeader(out, 4, items.size.toLong())
            for (item in items) item.appendEncoded(out)
        }
    }

    class Map(val pairs: List<Pair<CborValue, CborValue>>) : CborValue() {
        override fun appendEncoded(out: ByteArrayOutputStream) {
            writeHeader(out, 5, pairs.size.toLong())
            for ((k, v) in pairs) {
                k.appendEncoded(out)
                v.appendEncoded(out)
            }
        }
    }
}

/** CBOR header: major type + argument in the shortest form (RFC 8949). */
private fun writeHeader(out: ByteArrayOutputStream, major: Int, value: Long) {
    val mt = major shl 5
    when {
        value < 24 -> out.write(mt or value.toInt())
        value <= 0xFF -> {
            out.write(mt or 24)
            out.write(value.toInt())
        }
        value <= 0xFFFF -> {
            out.write(mt or 25)
            out.write((value shr 8).toInt())
            out.write(value.toInt())
        }
        value <= 0xFFFF_FFFFL -> {
            out.write(mt or 26)
            for (shift in 24 downTo 0 step 8) out.write((value shr shift).toInt())
        }
        else -> {
            out.write(mt or 27)
            for (shift in 56 downTo 0 step 8) out.write((value shr shift).toInt())
        }
    }
}

object CoseKeyBuilder {
    /**
     * COSE_Key for EC2 / ES256: map {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
     * @param publicKeyX963 0x04 || X(32) || Y(32), 65 bytes.
     */
    fun ec2ES256(publicKeyX963: ByteArray): ByteArray? {
        if (publicKeyX963.size != 65 || publicKeyX963[0] != 0x04.toByte()) return null
        val x = publicKeyX963.copyOfRange(1, 33)
        val y = publicKeyX963.copyOfRange(33, 65)
        val value: CborValue = CborValue.Map(
            listOf(
                CborValue.IntVal(1) to CborValue.IntVal(2),   // kty: EC2
                CborValue.IntVal(3) to CborValue.IntVal(-7),  // alg: ES256
                CborValue.IntVal(-1) to CborValue.IntVal(1),  // crv: P-256
                CborValue.IntVal(-2) to CborValue.Bytes(x),   // x
                CborValue.IntVal(-3) to CborValue.Bytes(y)    // y
            )
        )
        return value.encoded()
    }
}
