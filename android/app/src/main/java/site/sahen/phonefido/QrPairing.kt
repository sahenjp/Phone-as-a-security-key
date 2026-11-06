package site.sahen.phonefido

import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * QR-code pairing: the PC generates the pairing secret and displays it as
 * a QR code (`iphone-fido pair-qr`); the phone scans it instead of the
 * user copying 52 characters by hand.
 *
 * The payload is strictly validated (exact prefix + a 52-character Base32
 * code decoding to 32 bytes) and nothing is stored until the user
 * confirms the dialog showing the SAS — the same confirmation code the
 * PC displays — so a wrong or foreign code cannot slip in silently.
 *
 * Must be created during the host activity's onCreate: the constructor
 * registers the activity-result launcher.
 */
class QrPairingController(
    private val activity: AppCompatActivity,
    /** Called on the main thread after a new pairing secret was saved. */
    private val onPaired: () -> Unit
) {
    private val launcher = activity.registerForActivityResult(ScanContract()) { result ->
        // A null contents means the user backed out of the scanner.
        val contents = result.contents
        if (contents != null) {
            onScanned(contents)
        }
    }

    fun launch() {
        val options = ScanOptions()
            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            .setPrompt(activity.getString(R.string.qr_scan_prompt))
            .setBeepEnabled(false)
        launcher.launch(options)
    }

    private fun onScanned(contents: String) {
        val psk = CryptoUtils.decodePairQrPayload(contents)
        if (psk == null) {
            Toast.makeText(activity, R.string.qr_pair_invalid, Toast.LENGTH_LONG).show()
            return
        }
        AlertDialog.Builder(activity)
            .setTitle(R.string.qr_pair_title)
            .setMessage(activity.getString(R.string.qr_pair_msg, CryptoUtils.sasCode(psk)))
            .setPositiveButton(R.string.qr_pair_save) { _, _ -> save(psk) }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun save(psk: ByteArray) {
        if (AppRuntime.store.savePSK(psk)) {
            // The previous secret is invalid from this moment: drop any
            // live bridge session so it cannot keep using it.
            AppRuntime.restartServer()
            Toast.makeText(activity, R.string.qr_pair_saved, Toast.LENGTH_SHORT).show()
            onPaired()
        } else {
            Toast.makeText(activity, R.string.qr_pair_save_failed, Toast.LENGTH_LONG).show()
        }
    }
}
