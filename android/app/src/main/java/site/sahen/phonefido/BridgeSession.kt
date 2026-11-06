package site.sahen.phonefido

import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.OutputStream
import java.net.Socket

/**
 * One bridge connection: plaintext handshake (BRIDGE-PROTOCOL 2), then the
 * ChaCha20-Poly1305 encrypted request/response loop. Port of the Swift
 * BridgeServer session handling.
 *
 * Any framing / handshake / decryption failure throws and drops the
 * connection immediately — there is no error recovery inside a session.
 */
class BridgeSession(
    private val socket: Socket,
    /** Supplies the current pairing PSK, or null when unpaired (connections are then refused). */
    private val pskProvider: () -> ByteArray?,
    private val service: AuthenticatorService,
    private val callbacks: BridgeServer.Callbacks
) {
    /**
     * Set once the handshake completes and the encrypted channel is up.
     * Used so a session that never connected does not overwrite the
     * specific refusal event (unpaired / pairing mismatch) with a generic
     * "disconnected" in [run]'s finally block.
     */
    @Volatile
    private var handshakeComplete = false

    fun run() {
        try {
            val psk = pskProvider()
            if (psk == null) {
                callbacks.onLog(R.string.event_refused_unpaired)
                return
            }
            serve(psk)
        } catch (e: PairingMismatchException) {
            // The PC holds a different pairing secret (e.g. the key was
            // mistyped when copied by hand): say so explicitly instead of
            // reporting a generic session end.
            callbacks.onLog(R.string.event_pairing_mismatch)
        } catch (e: Exception) {
            callbacks.onLog(R.string.event_session_ended, e.message ?: e.javaClass.simpleName)
        } finally {
            try {
                socket.close()
            } catch (e: Exception) {
                // Already closed.
            }
            if (handshakeComplete) {
                callbacks.onConnection(false, R.string.event_disconnected)
            }
        }
    }

    private fun serve(psk: ByteArray) {
        val io = FrameIO(
            DataInputStream(BufferedInputStream(socket.getInputStream())),
            BufferedOutputStream(socket.getOutputStream())
        )

        // 1. hello (plaintext JSON)
        val hello = jsonObject(io.readFrame())
        val pcRandom = (hello.opt("pc_random") as? String)
            ?.let { CryptoUtils.base64Decode(it) }?.takeIf { it.size == 32 }
        val pcPub = (hello.opt("pc_ephemeral_pubkey") as? String)
            ?.let { CryptoUtils.base64Decode(it) }
            ?.takeIf { it.size == 65 && it[0] == 0x04.toByte() }
        if (hello.opt("type") != "hello" ||
            (hello.opt("version") as? Number)?.toInt() != BridgeConstants.PROTOCOL_VERSION ||
            pcRandom == null || pcPub == null
        ) {
            throw BridgeException("invalid hello")
        }

        // 2. hello_ack (a fresh ephemeral key pair per connection)
        val ephemeral = EphemeralECDH()
        val phoneRandom = CryptoUtils.randomBytes(32)
        io.writeFrame(
            jsonBytes(
                JSONObject()
                    .put("type", "hello_ack")
                    .put("version", BridgeConstants.PROTOCOL_VERSION)
                    .put("phone_random", CryptoUtils.base64Encode(phoneRandom))
                    .put("phone_ephemeral_pubkey", CryptoUtils.base64Encode(ephemeral.publicKeyX963))
            )
        )

        // 3. Key derivation
        val ecdh = ephemeral.sharedSecret(pcPub)
            ?: throw BridgeException("ecdh failed")
        val keys = SessionCrypto.deriveSessionKeys(ecdh, psk, pcRandom, phoneRandom)

        // 4. Verify the PC's confirm MAC; a mismatch drops the connection.
        val confirm = jsonObject(io.readFrame())
        val mac = (confirm.opt("mac") as? String)?.let { CryptoUtils.base64Decode(it) }
        if (confirm.opt("type") != "confirm" || mac == null) {
            throw BridgeException("invalid confirm")
        }
        val expectedMac = SessionCrypto.confirmMAC(keys.confirm, "pc", pcRandom, phoneRandom)
        if (!CryptoUtils.constantTimeEqual(mac, expectedMac)) {
            throw PairingMismatchException()
        }

        // 5. confirm_ack
        val ackMac = SessionCrypto.confirmMAC(keys.confirm, "phone", pcRandom, phoneRandom)
        io.writeFrame(
            jsonBytes(
                JSONObject()
                    .put("type", "confirm_ack")
                    .put("mac", CryptoUtils.base64Encode(ackMac))
            )
        )

        handshakeComplete = true
        callbacks.onConnection(true, R.string.event_connected)

        // Encrypted channel from here on. A decryption failure or a seq
        // mismatch throws out of SessionCipher and ends the session.
        val cipher = SessionCipher(keys)
        while (true) {
            val frame = io.readFrame()
            val plaintext = cipher.open(frame)
            val request = try {
                jsonObject(plaintext)
            } catch (e: Exception) {
                val badRequest = JSONObject()
                    .put("id", 0)
                    .put("ok", false)
                    .put("error", BridgeError.BAD_REQUEST)
                io.writeFrame(cipher.seal(jsonBytes(badRequest)))
                continue
            }
            val response = service.handle(request)
            io.writeFrame(cipher.seal(jsonBytes(response)))
        }
    }

    private fun jsonObject(data: ByteArray): JSONObject {
        val text = String(data, Charsets.UTF_8)
        try {
            return JSONObject(text)
        } catch (e: Exception) {
            throw BridgeException("payload is not a JSON object")
        }
    }

    private fun jsonBytes(obj: JSONObject): ByteArray =
        obj.toString().toByteArray(Charsets.UTF_8)
}

/** Frame framing: 4-byte big-endian length + payload (BRIDGE-PROTOCOL 0). */
private class FrameIO(
    private val input: DataInputStream,
    private val output: OutputStream
) {
    fun readFrame(): ByteArray {
        val header = ByteArray(4)
        input.readFully(header) // throws EOFException when the peer closes
        var length = 0
        for (b in header) {
            length = (length shl 8) or (b.toInt() and 0xFF)
        }
        if (length <= 0 || length > BridgeConstants.MAX_FRAME_SIZE) {
            throw BridgeException("invalid frame length $length")
        }
        val payload = ByteArray(length)
        input.readFully(payload)
        return payload
    }

    fun writeFrame(payload: ByteArray) {
        if (payload.size > BridgeConstants.MAX_FRAME_SIZE) {
            throw BridgeException("payload too large")
        }
        output.write(CryptoUtils.uint32BigEndian(payload.size.toLong()))
        output.write(payload)
        output.flush()
    }
}
