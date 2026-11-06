package site.sahen.phonefido

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * First-launch introduction: what the app is, how requests arrive,
 * where the keys live, and that pairing happens from Settings.
 * Shown once; the flag lives in SharedPreferences. Pairing itself is
 * not done here — the last page sends the user to Settings, where the
 * pairing controls (and the QR scanner) live.
 */
class OnboardingActivity : AppCompatActivity() {

    private data class Page(val iconRes: Int, val title: String?, val titleRes: Int, val bodyRes: Int)

    private lateinit var pages: List<Page>
    private var page = 0

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
            Page(R.drawable.ic_key, getString(R.string.app_name), 0, R.string.onboarding_tagline),
            Page(R.drawable.ic_cable, null, R.string.onboarding_how_title, R.string.onboarding_how_body),
            Page(R.drawable.ic_shield_lock, null, R.string.onboarding_security_title, R.string.onboarding_security_body),
            Page(R.drawable.ic_qr, null, R.string.onboarding_pair_title, R.string.onboarding_pair_body)
        )

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
                finishOnboarding(openSettings = true)
            }
        }
        secondary.setOnClickListener { finishOnboarding(openSettings = false) }
        render()
    }

    private fun render() {
        val p = pages[page]
        icon.setImageResource(p.iconRes)
        title.text = p.title ?: getString(p.titleRes)
        body.setText(p.bodyRes)
        dots.text = pages.indices.joinToString("  ") { if (it == page) "●" else "○" }
        primary.setText(
            if (page < pages.lastIndex) R.string.onboarding_continue else R.string.onboarding_open_settings
        )
        secondary.setText(
            if (page < pages.lastIndex) R.string.onboarding_skip else R.string.onboarding_later
        )
    }

    private fun finishOnboarding(openSettings: Boolean) {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_DONE, true).apply()
        if (openSettings) {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
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
