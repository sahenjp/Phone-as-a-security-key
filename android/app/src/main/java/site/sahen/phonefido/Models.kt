package site.sahen.phonefido

/**
 * Project constants. docs/BRIDGE-PROTOCOL.md is the single source of truth;
 * if this file and the document disagree, the document wins.
 */
object BridgeConstants {
    /** Phone-side listen port (the PC reaches it via adb forward / iproxy). */
    const val LISTEN_PORT = 18765

    /** Maximum frame payload: 1 MiB (BRIDGE-PROTOCOL 0). */
    const val MAX_FRAME_SIZE = 1_048_576

    const val PROTOCOL_VERSION = 1

    /**
     * QR pairing payload (daemon `iphone-fido pair-qr`): this prefix
     * followed by the 52-character uppercase Base32 (RFC 4648, no padding)
     * encoding of the 32-byte pairing secret.
     */
    const val PAIR_QR_PREFIX = "phonefido-pair:1:"

    /** Base32 characters in the QR payload after [PAIR_QR_PREFIX]. */
    const val PAIR_QR_CODE_LENGTH = 52

    /** Approval timeout in seconds; a timeout counts as a refusal. */
    const val APPROVAL_TIMEOUT_SECONDS = 60L

    /**
     * AAGUID for Android builds: ASCII "and-fido-0000001", exactly 16 bytes.
     * (The iOS build uses "iph-fido-0000001" per BRIDGE-PROTOCOL 3.2; the
     * value is per-platform so RPs can tell the authenticator model apart.)
     */
    val AAGUID: ByteArray = "and-fido-0000001".toByteArray(Charsets.US_ASCII)
}

/** Bridge error codes (BRIDGE-PROTOCOL 3.5). */
object BridgeError {
    const val USER_CANCELLED = "user_cancelled"
    const val NO_CREDENTIALS = "no_credentials"
    const val NOT_FOUND = "not_found"
    const val INTERNAL = "internal"
    const val BAD_REQUEST = "bad_request"
}

/** Carries a bridge error code out of the signing path (mirrors the Swift BridgeErrorCode throws). */
class AuthError(val code: String) : Exception("bridge error: $code")

/** Fatal session error: framing / handshake / crypto failures drop the connection immediately. */
class BridgeException(message: String) : Exception(message)

/**
 * The PC's handshake confirm MAC did not verify: the PC holds a different
 * pairing secret than this phone (the classic symptom of a mistyped
 * hand-copied pairing key). Surfaced as its own user-visible event instead
 * of a generic session end.
 */
class PairingMismatchException : BridgeException("confirm mac mismatch")

/**
 * Credential metadata. Stored as JSON in app-private storage (see
 * CredentialStore). The EC private key itself never appears here — it lives
 * in the Android Keystore under [keyAlias]. [hmacSecret] is the
 * per-credential PRF (hmac-secret) key; in the stored JSON it is kept
 * encrypted under a Keystore AES-GCM key, and it never leaves the phone.
 */
class CredentialMetadata(
    val credentialId: ByteArray,
    val rpId: String,
    val rpName: String?,
    val userId: ByteArray,
    val userName: String,
    val userDisplayName: String?,
    /** Public key, ANSI X9.63 form (0x04 || X(32) || Y(32)), 65 bytes. */
    val publicKeyX963: ByteArray,
    var signCount: Long,
    /** Android Keystore alias of the private key. */
    val keyAlias: String,
    val createdAtSeconds: Long,
    val hmacSecret: ByteArray?
) {
    /** Short display form of the credential id, like the iOS list. */
    fun shortCredentialId(): String {
        val n = minOf(6, credentialId.size)
        return CryptoUtils.toHex(credentialId.copyOfRange(0, n)) + "…"
    }
}

/** A create/assert request waiting for the user's on-screen decision. */
class PendingApproval(
    /** Request id inside the encrypted channel. */
    val requestId: Int,
    /** Raw op name: "create_credential" or "get_assertion". */
    val operation: String,
    val rpId: String,
    val userName: String,
    val requestedAtMillis: Long
) {
    val isCreate: Boolean get() = operation == "create_credential"
}
