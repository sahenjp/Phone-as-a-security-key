package site.sahen.phonefido

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.os.LocaleListCompat

/**
 * Settings: display language, credential management, pairing management
 * and about information. Connection status is NOT repeated here — it
 * lives on the main screen; the listener manages itself.
 *
 * Nothing here can weaken the security model: there is deliberately no
 * switch for biometrics, no auto-approve and no "trust this PC" option.
 * Destructive actions stay gated — credential deletion needs a
 * confirmation dialog AND a BIOMETRIC_STRONG prompt, pairing-key
 * regeneration needs a confirmation dialog and drops the live session.
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var btnLanguage: Button
    private lateinit var tvSettingsNoCredentials: TextView
    private lateinit var llSettingsCredentials: LinearLayout
    private lateinit var tvPairingState: TextView
    private lateinit var llSettingsPaired: LinearLayout
    private lateinit var llSettingsUnpaired: LinearLayout
    private lateinit var tvSettingsSas: TextView

    private val uiListener: () -> Unit = { refresh() }

    private lateinit var qrPairing: QrPairingController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        // Edge-to-edge (targetSdk 35): keep content clear of the status/nav bars.
        val rootId = if (this is MainActivity) R.id.rootMain else R.id.rootSettings
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(findViewById(rootId)) { v, insets ->
            val bars = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        AppRuntime.init(applicationContext)

        btnLanguage = findViewById(R.id.btnLanguage)
        tvSettingsNoCredentials = findViewById(R.id.tvSettingsNoCredentials)
        llSettingsCredentials = findViewById(R.id.llSettingsCredentials)
        tvPairingState = findViewById(R.id.tvPairingState)
        llSettingsPaired = findViewById(R.id.llSettingsPaired)
        llSettingsUnpaired = findViewById(R.id.llSettingsUnpaired)
        tvSettingsSas = findViewById(R.id.tvSettingsSas)

        btnLanguage.setOnClickListener { showLanguageDialog() }

        findViewById<Button>(R.id.btnCopyPsk).setOnClickListener {
            val psk = AppRuntime.store.loadPSK() ?: return@setOnClickListener
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(
                ClipData.newPlainText(
                    getString(R.string.psk_label),
                    CryptoUtils.base32EncodeNoPadding(psk).chunked(4).joinToString(" ")
                )
            )
            Toast.makeText(this, R.string.settings_psk_copied, Toast.LENGTH_SHORT).show()
        }
        findViewById<Button>(R.id.btnRegeneratePskSettings).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle(R.string.confirm_regenerate_title)
                .setMessage(R.string.confirm_regenerate_msg)
                .setPositiveButton(R.string.btn_regenerate_psk) { _, _ ->
                    AppRuntime.store.generateAndSavePSK()
                    // The old key is invalid from this moment: drop any live
                    // bridge session so it cannot keep using it.
                    AppRuntime.restartServer()
                    refresh()
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }
        findViewById<Button>(R.id.btnGeneratePskSettings).setOnClickListener {
            AppRuntime.store.generateAndSavePSK()
            refresh()
        }
        qrPairing = QrPairingController(this) { refresh() }
        findViewById<Button>(R.id.btnPairQrSettings).setOnClickListener { qrPairing.launch() }
        findViewById<Button>(R.id.btnPairQrSettingsUnpaired).setOnClickListener {
            qrPairing.launch()
        }

        val tvAboutVersion = findViewById<TextView>(R.id.tvAboutVersion)
        val versionName = try {
            packageManager.getPackageInfo(packageName, 0).versionName
        } catch (e: Exception) {
            null
        } ?: "?"
        tvAboutVersion.text = getString(R.string.settings_about_version) + ": " + versionName
        val tvRepoLink = findViewById<TextView>(R.id.tvRepoLink)
        tvRepoLink.text = REPO_URL
        tvRepoLink.paintFlags = tvRepoLink.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvRepoLink.setTextColor(ContextCompat.getColor(this, android.R.color.holo_blue_dark))
        tvRepoLink.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(REPO_URL)))
        }

        refresh()
    }

    override fun onResume() {
        super.onResume()
        AppRuntime.addUiListener(uiListener)
        refresh()
    }

    override fun onPause() {
        AppRuntime.removeUiListener(uiListener)
        super.onPause()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    // MARK: - UI refresh (called on the main thread)

    private fun refresh() {
        btnLanguage.text = currentLanguageLabel()

        val credentials = AppRuntime.credentials
        tvSettingsNoCredentials.visibility =
            if (credentials.isEmpty()) View.VISIBLE else View.GONE
        llSettingsCredentials.removeAllViews()
        for (credential in credentials) {
            llSettingsCredentials.addView(credentialRow(credential))
        }

        val psk = AppRuntime.store.loadPSK()
        if (psk != null) {
            tvPairingState.text = getString(R.string.settings_paired)
            llSettingsPaired.visibility = View.VISIBLE
            llSettingsUnpaired.visibility = View.GONE
            tvSettingsSas.text = CryptoUtils.sasCode(psk)
        } else {
            tvPairingState.text = getString(R.string.settings_not_paired)
            llSettingsPaired.visibility = View.GONE
            llSettingsUnpaired.visibility = View.VISIBLE
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
        // Swipe-to-delete: the row sits in a frame over a red delete
        // background; dragging left reveals it, and releasing past the
        // threshold opens the same confirmation + biometric flow the
        // old delete button used (confirmDeleteWithBiometrics).
        val bgValue = TypedValue()
        theme.resolveAttribute(android.R.attr.colorBackground, bgValue, true)
        container.setBackgroundColor(bgValue.data)
        val frame = FrameLayout(this)
        frame.addView(TextView(this).apply {
            text = getString(R.string.delete)
            textSize = 14f
            setTextColor(Color.WHITE)
            gravity = Gravity.END or Gravity.CENTER_VERTICAL
            setPadding(0, 0, dp(16), 0)
            setBackgroundColor(Color.rgb(217, 38, 56))
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        })
        frame.addView(container)
        attachSwipeToDelete(container, credential)
        return frame
    }

    /** Left-swipe gesture on a credential row: drag reveals the red
     * background; past ~35% of the row width the delete flow starts,
     * otherwise the row animates back. Vertical scrolling of the
     * parent stays untouched until the drag is clearly horizontal. */
    private fun attachSwipeToDelete(row: View, credential: CredentialMetadata) {
        var downX = 0f
        var downY = 0f
        var swiping = false
        row.setOnTouchListener { v, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    downX = event.rawX
                    downY = event.rawY
                    swiping = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = event.rawX - downX
                    val dy = event.rawY - downY
                    if (!swiping && dx < -dp(12) && kotlin.math.abs(dx) > kotlin.math.abs(dy)) {
                        swiping = true
                        v.parent?.requestDisallowInterceptTouchEvent(true)
                    }
                    if (swiping) {
                        v.translationX = dx.coerceIn(-v.width.toFloat(), 0f)
                        true
                    } else {
                        false
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    if (!swiping) {
                        false
                    } else {
                        val past = v.translationX < -v.width * 0.35f
                        v.animate().translationX(0f).setDuration(150).start()
                        if (past) confirmDeleteWithBiometrics(credential)
                        true
                    }
                }
                else -> false
            }
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    // MARK: - Credential deletion (confirmation dialog + biometrics)

    private fun confirmDeleteWithBiometrics(credential: CredentialMetadata) {
        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_delete_cred_title)
            .setMessage(R.string.confirm_delete_cred_msg)
            .setPositiveButton(R.string.delete) { _, _ -> promptBiometricDelete(credential) }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun promptBiometricDelete(credential: CredentialMetadata) {
        // Same policy as approvals: BIOMETRIC_STRONG only, never the device
        // credential. If biometrics are unavailable the deletion does not
        // happen (fail closed).
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        if (BiometricManager.from(this).canAuthenticate(authenticators) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            return
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    // Removes the metadata AND the Android Keystore key.
                    AppRuntime.deleteCredential(credential)
                    refresh()
                }
                // Errors and cancellation simply do not delete anything.
            }
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.settings_delete_biometric_title))
            .setSubtitle(credential.rpId)
            .setNegativeButtonText(getString(R.string.cancel))
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(info)
    }

    // MARK: - Language

    private fun showLanguageDialog() {
        val tags = LANGUAGE_TAGS
        val names = arrayOf(
            getString(R.string.settings_language_system_default),
            *LANGUAGE_NATIVE_NAMES
        )
        val checked = tags.indexOf(currentLanguageTag()).coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle(R.string.settings_language_title)
            .setSingleChoiceItems(names, checked) { dialog, which ->
                val tag = tags[which]
                AppCompatDelegate.setApplicationLocales(
                    if (tag == null) LocaleListCompat.getEmptyLocaleList()
                    else LocaleListCompat.forLanguageTags(tag)
                )
                dialog.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    /** The stored per-app language tag, or null for "follow the system". */
    private fun currentLanguageTag(): String? {
        val locales = AppCompatDelegate.getApplicationLocales()
        if (locales.isEmpty) return null
        return locales[0]?.toLanguageTag()
    }

    private fun currentLanguageLabel(): String {
        val tag = currentLanguageTag() ?: return getString(R.string.settings_language_system_default)
        val index = LANGUAGE_TAGS.indexOf(tag)
        return if (index > 0) LANGUAGE_NATIVE_NAMES[index - 1] else tag
    }

    companion object {
        private const val REPO_URL = "https://github.com/sahenjp/Phone-as-a-security-key"

        /** Selectable language tags; null (index 0) means "system default". */
        private val LANGUAGE_TAGS: List<String?> = listOf(
            null, "en", "ja", "de", "fr", "es", "pt-BR", "ko", "zh-Hans", "zh-Hant"
        )

        /**
         * Each language's name in that language, aligned with [LANGUAGE_TAGS]
         * after the system-default entry. Language names are conventionally
         * shown in their own language, so these are intentionally not string
         * resources.
         */
        private val LANGUAGE_NATIVE_NAMES: Array<String> = arrayOf(
            "English", "日本語", "Deutsch", "Français", "Español",
            "Português (Brasil)", "한국어", "简体中文", "繁體中文"
        )
    }
}
