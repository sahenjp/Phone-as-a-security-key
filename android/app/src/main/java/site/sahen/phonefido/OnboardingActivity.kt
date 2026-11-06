package site.sahen.phonefido

import android.content.Context
import android.os.Bundle
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * First-launch setup: what the app is, how requests arrive, where the
 * keys live, and pairing — the last page opens the QR scanner right
 * here, so setup ends with the phone paired. Pairing can be skipped
 * and done later from Settings, where the same scanner lives.
 * Shown once; the flag lives in SharedPreferences.
 */
class OnboardingActivity : AppCompatActivity() {

    private data class Page(val iconRes: Int, val title: String?, val titleRes: Int, val bodyRes: Int)

    private lateinit var pages: List<Page>
    private var page = 0

    private lateinit var qrPairing: QrPairingController

    private lateinit var icon: ImageView
    private lateinit var title: TextView
    private lateinit var body: TextView
    private lateinit var dots: TextView
    private lateinit var primary: Button
    private lateinit var secondary: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        val root = findViewById<android.view.View>(R.id.rootOnboarding)
        val baseL = root.paddingLeft
        val baseT = root.paddingTop
        val baseR = root.paddingRight
        val baseB = root.paddingBottom
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.systemBars())
            v.setPadding(baseL + bars.left, baseT + bars.top, baseR + bars.right, baseB + bars.bottom)
            insets
        }

        pages = listOf(
            Page(R.drawable.ic_key, getString(R.string.app_name), 0, 0),
            Page(R.drawable.ic_cable, null, R.string.onboarding_how_title, R.string.onboarding_how_body),
            Page(R.drawable.ic_shield_lock, null, R.string.onboarding_security_title, R.string.onboarding_security_body),
            Page(R.drawable.ic_qr, null, R.string.onboarding_pair_title, R.string.onboarding_pair_body)
        )

        // Created in onCreate as its contract requires. A saved pairing
        // completes the whole setup.
        qrPairing = QrPairingController(this) { finishOnboarding() }

        icon = findViewById(R.id.obIcon)
        title = findViewById(R.id.obTitle)
        body = findViewById(R.id.obBody)
        dots = findViewById(R.id.obDots)
        primary = findViewById(R.id.btnObPrimary)
        secondary = findViewById(R.id.btnObSecondary)

        primary.setOnClickListener {
            if (page < pages.lastIndex) {
                page++
                render()
            } else {
                qrPairing.launch()
            }
        }
        secondary.setOnClickListener { finishOnboarding() }
        render()
    }

    private fun render() {
        val p = pages[page]
        icon.setImageResource(p.iconRes)
        title.text = p.title ?: getString(p.titleRes)
        if (p.bodyRes == 0) {
            body.visibility = android.view.View.GONE
        } else {
            body.visibility = android.view.View.VISIBLE
            body.setText(p.bodyRes)
        }
        dots.text = pages.indices.joinToString("  ") { if (it == page) "●" else "○" }
        primary.setText(
            if (page < pages.lastIndex) R.string.onboarding_continue else R.string.btn_pair_qr
        )
        secondary.setText(
            if (page < pages.lastIndex) R.string.onboarding_skip else R.string.onboarding_later
        )
    }

    private fun finishOnboarding() {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_DONE, true).apply()
        finish()
    }

    companion object {
        const val PREFS_NAME = "app_prefs"
        const val KEY_DONE = "onboarding_done"

        fun isDone(context: Context): Boolean =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_DONE, false)
    }
}
