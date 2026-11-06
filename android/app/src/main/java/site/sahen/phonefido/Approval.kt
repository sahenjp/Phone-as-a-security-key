package site.sahen.phonefido

import android.os.Handler
import android.os.Looper
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Approval coordinator (mirror of the Swift ApprovalCoordinator).
 *
 * A create/assert request from the PC parks here until the user explicitly
 * taps Approve or Cancel on the approval screen, or the 60-second timeout
 * fires (a timeout is a refusal). There is no auto-approve path. Only one
 * request may be pending at a time; a second one is refused immediately.
 */
class ApprovalCoordinator {
    @Volatile
    var pending: PendingApproval? = null
        private set

    /** Invoked (on an arbitrary thread) whenever [pending] changes; wired to the UI / notifications. */
    var onStateChanged: (() -> Unit)? = null

    private val lock = Object()
    private var latch: CountDownLatch? = null
    private var approved = false

    /**
     * Publishes [approval] and blocks the calling (session) thread for at
     * most [BridgeConstants.APPROVAL_TIMEOUT_SECONDS]. Returns true only on
     * an explicit Approve tap.
     */
    fun requestApproval(approval: PendingApproval): Boolean {
        val myLatch: CountDownLatch
        synchronized(lock) {
            if (pending != null) return false
            pending = approval
            approved = false
            myLatch = CountDownLatch(1)
            latch = myLatch
        }
        onStateChanged?.invoke()

        val completed = try {
            myLatch.await(BridgeConstants.APPROVAL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            false
        }

        val result: Boolean
        synchronized(lock) {
            result = completed && approved
            if (latch === myLatch) {
                latch = null
                pending = null
            }
        }
        onStateChanged?.invoke()
        return result
    }

    fun approve() {
        synchronized(lock) { approved = true }
        latch?.countDown()
    }

    fun deny() {
        synchronized(lock) { approved = false }
        latch?.countDown()
    }
}

/**
 * Bridges the (blocking, session-thread) authenticator service to a
 * BiometricPrompt that must run on the resumed activity.
 *
 * Signing flow, mirroring iOS: the user first taps Approve on the approval
 * screen; only then does the service call [sign], which shows
 * BiometricPrompt with a CryptoObject wrapping a Signature for the
 * credential's Keystore key. The key itself requires authentication for
 * every use, so the signature bytes can only be produced inside the
 * prompt's success callback — unlocking the phone is never enough.
 */
class BiometricSignCoordinator {
    interface Host {
        /**
         * Runs the biometric prompt. Called on the main thread. Must invoke
         * exactly one [Callback] method, exactly once.
         */
        fun performBiometricSign(
            keyAlias: String,
            message: ByteArray,
            reason: String,
            callback: Callback
        )
    }

    interface Callback {
        fun onSuccess(signatureDer: ByteArray)
        fun onError(code: String)
    }

    /** The currently resumed activity, or null (signing then fails with `internal`). */
    @Volatile
    var host: Host? = null

    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Blocks until the biometric prompt finishes. Returns the DER-encoded
     * ECDSA signature; throws [AuthError] with the bridge error code
     * (user_cancelled / not_found / internal) on failure.
     */
    fun sign(keyAlias: String, message: ByteArray, reason: String): ByteArray {
        val activeHost = host ?: throw AuthError(BridgeError.INTERNAL)
        val latch = CountDownLatch(1)
        var signature: ByteArray? = null
        var errorCode: String? = null
        val callback = object : Callback {
            override fun onSuccess(signatureDer: ByteArray) {
                signature = signatureDer
                latch.countDown()
            }

            override fun onError(code: String) {
                errorCode = code
                latch.countDown()
            }
        }
        mainHandler.post {
            try {
                activeHost.performBiometricSign(keyAlias, message, reason, callback)
            } catch (e: Exception) {
                callback.onError(BridgeError.INTERNAL)
            }
        }
        val finished = try {
            // Generous bound; the system prompt has its own timeout and the
            // PC-side session read timeout is 120 s.
            latch.await(90, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            false
        }
        if (!finished) throw AuthError(BridgeError.INTERNAL)
        errorCode?.let { throw AuthError(it) }
        return signature ?: throw AuthError(BridgeError.INTERNAL)
    }
}
