package site.sahen.phonefido

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * Foreground service hosting the bridge listener.
 *
 * Like the iOS app (whose NWListener is suspended in the background), the
 * authenticator is meant to be used with the app brought to the foreground:
 * approvals can only be tapped and biometric prompts only shown there.
 * The foreground service keeps the TCP listener itself alive while the
 * app is open or recently used.
 */
class BridgeService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        AppRuntime.init(this)
        AppRuntime.attachService(this)
        startForegroundWithNotification()
        AppRuntime.startServer()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        START_STICKY

    override fun onDestroy() {
        AppRuntime.stopServer()
        AppRuntime.detachService()
        super.onDestroy()
    }

    private fun startForegroundWithNotification() {
        val notification = NotificationCompat.Builder(this, PhoneFidoApp.CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(MainActivity.pendingIntent(this))
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // The foregroundServiceType is declared in the manifest
            // (dataSync); pass it explicitly on API 29+ as well.
            startForeground(
                PhoneFidoApp.SERVICE_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(PhoneFidoApp.SERVICE_NOTIFICATION_ID, notification)
        }
    }
}
