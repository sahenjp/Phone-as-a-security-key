package site.sahen.phonefido

import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * TCP listener for the bridge (BRIDGE-PROTOCOL 0).
 *
 * - Binds port 18765 on all interfaces (reachability through adb forward /
 *   iproxy comes from the host side; access control is the crypto layer:
 *   unpaired phones refuse connections, and every session must complete
 *   the PSK-bound handshake).
 * - Exactly one live session: a new connection replaces the previous one
 *   (the old socket is closed), like the Swift server.
 * - A failed listener is recreated after 1 s, so the server recovers on
 *   its own when the network configuration changes.
 */
class BridgeServer(
    private val store: CredentialStore,
    private val service: AuthenticatorService,
    private val callbacks: Callbacks
) {
    interface Callbacks {
        /** Listener state code: "listening", "stopped" or "failed" (with [detail]). */
        fun onListenerState(state: String, detail: String? = null)

        /** [eventRes] is a string resource describing the connection event. */
        fun onConnection(connected: Boolean, eventRes: Int)

        /** [eventRes] is a string resource; [detail] fills its %1$s if it has one. */
        fun onLog(eventRes: Int, detail: String? = null)
    }

    @Volatile
    private var running = false
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var currentSocket: Socket? = null
    private var acceptThread: Thread? = null

    fun start() {
        if (running) return
        running = true
        val thread = Thread({ acceptLoop() }, "phonefido-bridge-server")
        thread.isDaemon = true
        thread.start()
        acceptThread = thread
    }

    fun stop() {
        running = false
        closeQuietly(serverSocket)
        closeQuietly(currentSocket)
        serverSocket = null
        currentSocket = null
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val server = ServerSocket()
                server.reuseAddress = true
                server.bind(InetSocketAddress(BridgeConstants.LISTEN_PORT))
                serverSocket = server
                callbacks.onListenerState("listening")
                while (running) {
                    val socket = server.accept()
                    // Newest connection wins: any previous (possibly
                    // half-dead) session is replaced.
                    closeQuietly(currentSocket)
                    currentSocket = socket
                    val session = BridgeSession(socket, { store.loadPSK() }, service, callbacks)
                    val sessionThread = Thread({ session.run() }, "phonefido-bridge-session")
                    sessionThread.isDaemon = true
                    sessionThread.start()
                }
            } catch (e: Exception) {
                if (running) {
                    callbacks.onListenerState("failed", e.message ?: e.javaClass.simpleName)
                    try {
                        Thread.sleep(1000)
                    } catch (interrupted: InterruptedException) {
                        return
                    }
                }
            } finally {
                closeQuietly(serverSocket)
                serverSocket = null
            }
        }
        callbacks.onListenerState("stopped")
    }

    private fun closeQuietly(socket: Socket?) {
        try {
            socket?.close()
        } catch (e: Exception) {
            // Already closed.
        }
    }

    private fun closeQuietly(socket: ServerSocket?) {
        try {
            socket?.close()
        } catch (e: Exception) {
            // Already closed.
        }
    }
}
