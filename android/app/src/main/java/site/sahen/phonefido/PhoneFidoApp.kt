package site.sahen.phonefido

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class PhoneFidoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AppRuntime.init(this)
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.channel_bridge_name),
                NotificationManager.IMPORTANCE_LOW
            )
        )
        manager.createNotificationChannel(
            NotificationChannel(
                APPROVAL_CHANNEL_ID,
                getString(R.string.channel_approval_name),
                NotificationManager.IMPORTANCE_HIGH
            )
        )
    }

    companion object {
        const val CHANNEL_ID = "bridge"
        const val APPROVAL_CHANNEL_ID = "approval"
        const val SERVICE_NOTIFICATION_ID = 1
        const val APPROVAL_NOTIFICATION_ID = 2
    }
}
