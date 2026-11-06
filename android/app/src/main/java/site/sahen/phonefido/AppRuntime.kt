package site.sahen.phonefido

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import java.lang.ref.WeakReference
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Shared app state: the bridge between the background server (session
 * threads), the credential store, the approval flow and the UI.
 * Counterpart of the Swift AppState.
 */
object AppRuntime : BridgeServer.Callbacks {
    lateinit var store: CredentialStore
        private set

    val approval = ApprovalCoordinator()
    val signer = BiometricSignCoordinator()

    @Volatile
    var listenerState: String = "stopped"
        private set

    @Volatile
    var connected: Boolean = false
        private set

    @Volatile
    var lastEvent: String = ""
        private set

    @Volatile
    var credentials: List<CredentialMetadata> = emptyList()
        private set

    private var server: BridgeServer? = null
    private val uiListeners = CopyOnWriteArrayList<() -> Unit>()
    private val mainHandler = Handler(Looper.getMainLooper())

    /** Context of the running BridgeService, used to post approval notifications. */
    @Volatile
    private var serviceContext: WeakReference<Context>? = null

    fun init(context: Context) {
        if (!::store.isInitialized) {
            store = CredentialStore(context.applicationContext)
            refreshCredentials()
        }
        approval.onStateChanged = {
            notifyUi()
            updateApprovalNotification()
        }
    }

    // MARK: - Server lifecycle

    fun startServer() {
        check(::store.isInitialized) { "AppRuntime.init() must be called first" }
        if (server == null) {
            val service = AuthenticatorService(
                store = store,
                approval = approval,
                signer = signer,
                onCredentialsChanged = { refreshCredentials() }
            )
            server = BridgeServer(store, service, this)
        }
        server?.start()
    }

    fun stopServer() {
        server?.stop()
        server = null
    }

    fun attachService(context: Context) {
        serviceContext = WeakReference(context)
    }

    fun detachService() {
        serviceContext = null
    }

    // MARK: - Credentials

    fun refreshCredentials() {
        if (::store.isInitialized) {
            credentials = store.allCredentials()
        }
        notifyUi()
    }

    /** Deletes the Keystore key and the metadata, like the iOS list swipe-delete. */
    fun deleteCredential(metadata: CredentialMetadata) {
        KeystoreKeys.deleteKey(metadata.keyAlias)
        store.deleteCredential(metadata.credentialId)
        refreshCredentials()
    }

    // MARK: - UI observation

    fun addUiListener(listener: () -> Unit) {
        uiListeners.add(listener)
    }

    fun removeUiListener(listener: () -> Unit) {
        uiListeners.remove(listener)
    }

    fun notifyUi() {
        mainHandler.post {
            for (listener in uiListeners) {
                try {
                    listener()
                } catch (e: Exception) {
                    // A broken listener must not take the others down.
                }
            }
        }
    }

    // MARK: - BridgeServer.Callbacks

    override fun onListenerState(state: String) {
        listenerState = state
        notifyUi()
    }

    override fun onConnection(connected: Boolean, event: String) {
        this.connected = connected
        lastEvent = event
        notifyUi()
    }

    override fun onLog(event: String) {
        lastEvent = event
        notifyUi()
    }

    // MARK: - Approval notification
    //
    // The approval itself can only happen on the activity's approval
    // screen (same foreground-app constraint as iOS). When a request
    // arrives while the user is not looking at the app, a high-priority
    // notification tells them to open it; the 60 s timeout still applies.

    private fun updateApprovalNotification() {
        val context = serviceContext?.get() ?: return
        val manager = NotificationManagerCompat.from(context)
        val pending = approval.pending
        if (pending == null) {
            manager.cancel(PhoneFidoApp.APPROVAL_NOTIFICATION_ID)
            return
        }
        val notification = NotificationCompat.Builder(context, PhoneFidoApp.APPROVAL_CHANNEL_ID)
            .setContentTitle(context.getString(R.string.approval_notification_title))
            .setContentText(
                context.getString(
                    if (pending.isCreate) R.string.approval_notification_create
                    else R.string.approval_notification_signin,
                    pending.rpId
                )
            )
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setContentIntent(MainActivity.pendingIntent(context))
            .setAutoCancel(true)
            .build()
        try {
            manager.notify(PhoneFidoApp.APPROVAL_NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS not granted; the in-app screen still works.
        }
    }
}
