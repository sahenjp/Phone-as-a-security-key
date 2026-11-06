package site.sahen.phonefido

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.security.Signature

/**
 * The single activity: connection status, pairing (PSK + SAS), the
 * credential list, and — while a request is pending — a full-screen
 * approval state. It also hosts the BiometricPrompt used for signing.
 *
 * Like the iOS app, approval is only possible with this activity on
 * screen: there is deliberately no path that approves from a notification
 * or from the USB connection alone.
 */
class MainActivity : AppCompatActivity(), BiometricSignCoordinator.Host {

    private lateinit var tvListenerState: TextView
    private lateinit var tvConnectionState: TextView
    private lateinit var tvLastEvent: TextView
    private lateinit var llPaired: LinearLayout
    private lateinit var llUnpaired: LinearLayout
    private lateinit var tvPsk: TextView
    private lateinit var tvSas: TextView
    private lateinit var tvNoCredentials: TextView
    private lateinit var llCredentials: LinearLayout
    private lateinit var flApproval: FrameLayout
    private lateinit var tvApprovalOperation: TextView
    private lateinit var tvApprovalRp: TextView
    private lateinit var tvApprovalUser: TextView
    private lateinit var btnApprove: Button
    private lateinit var btnDeny: Button

    private val uiListener: () -> Unit = { refresh() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        AppRuntime.init(applicationContext)

        tvListenerState = findViewById(R.id.tvListenerState)
        tvConnectionState = findViewById(R.id.tvConnectionState)
        tvLastEvent = findViewById(R.id.tvLastEvent)
        llPaired = findViewById(R.id.llPaired)
        llUnpaired = findViewById(R.id.llUnpaired)
        tvPsk = findViewById(R.id.tvPsk)
        tvSas = findViewById(R.id.tvSas)
        tvNoCredentials = findViewById(R.id.tvNoCredentials)
        llCredentials = findViewById(R.id.llCredentials)
        flApproval = findViewById(R.id.flApproval)
        tvApprovalOperation = findViewById(R.id.tvApprovalOperation)
        tvApprovalRp = findViewById(R.id.tvApprovalRp)
        tvApprovalUser = findViewById(R.id.tvApprovalUser)
        btnApprove = findViewById(R.id.btnApprove)
        btnDeny = findViewById(R.id.btnDeny)

        findViewById<Button>(R.id.btnGeneratePsk).setOnClickListener {
            AppRuntime.store.generateAndSavePSK()
            refresh()
        }
        findViewById<Button>(R.id.btnRegeneratePsk).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle(R.string.confirm_regenerate_title)
                .setMessage(R.string.confirm_regenerate_msg)
                .setPositiveButton(R.string.btn_regenerate_psk) { _, _ ->
                    AppRuntime.store.generateAndSavePSK()
                    refresh()
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }
        findViewById<Button>(R.id.btnDeletePsk).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle(R.string.confirm_delete_psk_title)
                .setMessage(R.string.confirm_delete_psk_msg)
                .setPositiveButton(R.string.btn_delete_psk) { _, _ ->
                    AppRuntime.store.deletePSK()
                    refresh()
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }
        btnApprove.setOnClickListener {
            // Disable both buttons immediately: the tap is the decision,
            // and a second tap must not leak into the next request.
            btnApprove.isEnabled = false
            btnDeny.isEnabled = false
            AppRuntime.approval.approve()
        }
        btnDeny.setOnClickListener {
            AppRuntime.approval.deny()
        }

        // Pressing Back while an approval is up means "deny", never "leave
        // it hanging".
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (AppRuntime.approval.pending != null) {
                    AppRuntime.approval.deny()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        ContextCompat.startForegroundService(this, Intent(this, BridgeService::class.java))
        requestNotificationPermissionIfNeeded()
        refresh()
    }

    override fun onResume() {
        super.onResume()
        AppRuntime.signer.host = this
        AppRuntime.addUiListener(uiListener)
        AppRuntime.startServer() // no-op if the service already runs it
        refresh()
    }

    override fun onPause() {
        if (AppRuntime.signer.host === this) {
            AppRuntime.signer.host = null
        }
        AppRuntime.removeUiListener(uiListener)
        super.onPause()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_NOTIFICATIONS
            )
        }
    }

    // MARK: - UI refresh (called on the main thread)

    private fun refresh() {
        tvListenerState.text = getString(
            R.string.label_listener
        ) + ": " + when {
            AppRuntime.listenerState == "listening" -> getString(R.string.listener_listening)
            AppRuntime.listenerState == "stopped" -> getString(R.string.listener_stopped)
            else -> AppRuntime.listenerState
        }
        tvConnectionState.text = getString(R.string.label_connection) + ": " + getString(
            if (AppRuntime.connected) R.string.status_connected else R.string.status_disconnected
        ) + " · " + getString(R.string.label_port) + " " + BridgeConstants.LISTEN_PORT
        tvLastEvent.text = AppRuntime.lastEvent

        val psk = AppRuntime.store.loadPSK()
        if (psk != null) {
            llPaired.visibility = View.VISIBLE
            llUnpaired.visibility = View.GONE
            tvPsk.text = CryptoUtils.base32EncodeNoPadding(psk)
            tvSas.text = CryptoUtils.sasCode(psk)
        } else {
            llPaired.visibility = View.GONE
            llUnpaired.visibility = View.VISIBLE
        }

        val credentials = AppRuntime.credentials
        tvNoCredentials.visibility = if (credentials.isEmpty()) View.VISIBLE else View.GONE
        llCredentials.removeAllViews()
        for (credential in credentials) {
            llCredentials.addView(credentialRow(credential))
        }

        val pending = AppRuntime.approval.pending
        if (pending != null) {
            flApproval.visibility = View.VISIBLE
            tvApprovalOperation.text = getString(
                if (pending.isCreate) R.string.approval_create_title else R.string.approval_signin_title
            )
            tvApprovalRp.text = pending.rpId
            tvApprovalUser.text = pending.userName
            btnApprove.text = getString(
                if (pending.isCreate) R.string.approve_create else R.string.approve_signin
            )
            btnApprove.isEnabled = true
            btnDeny.isEnabled = true
        } else {
            flApproval.visibility = View.GONE
        }
    }

    private fun credentialRow(credential: CredentialMetadata): View {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(10), 0, dp(10))
        }
        container.addView(TextView(this).apply {
            text = credential.rpId
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
        })
        container.addView(TextView(this).apply {
            text = credential.userDisplayName ?: credential.userName
            textSize = 14f
        })
        container.addView(TextView(this).apply {
            text = getString(
                R.string.credential_meta,
                credential.shortCredentialId(),
                credential.signCount
            )
            textSize = 12f
        })
        container.addView(Button(this).apply {
            text = getString(R.string.delete)
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle(R.string.confirm_delete_cred_title)
                    .setMessage(R.string.confirm_delete_cred_msg)
                    .setPositiveButton(R.string.delete) { _, _ ->
                        AppRuntime.deleteCredential(credential)
                    }
                    .setNegativeButton(R.string.cancel, null)
                    .show()
            }
        })
        return container
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    // MARK: - BiometricSignCoordinator.Host (runs on the main thread)

    override fun performBiometricSign(
        keyAlias: String,
        message: ByteArray,
        reason: String,
        callback: BiometricSignCoordinator.Callback
    ) {
        if (isFinishing || isDestroyed) {
            callback.onError(BridgeError.INTERNAL)
            return
        }
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        if (BiometricManager.from(this).canAuthenticate(authenticators) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            callback.onError(BridgeError.INTERNAL)
            return
        }
        val privateKey = try {
            KeystoreKeys.privateKey(keyAlias)
        } catch (e: Exception) {
            null
        }
        if (privateKey == null) {
            callback.onError(BridgeError.NOT_FOUND)
            return
        }
        val signature = try {
            Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
        } catch (e: Exception) {
            callback.onError(BridgeError.INTERNAL)
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val code = when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED -> BridgeError.USER_CANCELLED
                        else -> BridgeError.INTERNAL
                    }
                    callback.onError(code)
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val authenticated = result.cryptoObject?.signature
                            ?: throw IllegalStateException("crypto object missing")
                        authenticated.update(message)
                        callback.onSuccess(authenticated.sign())
                    } catch (e: Exception) {
                        callback.onError(BridgeError.INTERNAL)
                    }
                }
            }
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(reason)
            .setNegativeButtonText(getString(R.string.cancel))
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    companion object {
        private const val REQUEST_NOTIFICATIONS = 1

        /** Intent that brings the app (and its approval screen) to the front. */
        fun pendingIntent(context: Context): PendingIntent {
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            return PendingIntent.getActivity(
                context,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }
    }
}
