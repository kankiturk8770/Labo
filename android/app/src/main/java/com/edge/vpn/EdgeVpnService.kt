package com.edge.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The system VPN service. Establishes a TUN interface routing all device
 * traffic, opens an authenticated tunnel to the edge gateway, and relays
 * packets through it with automatic reconnect.
 */
class EdgeVpnService : VpnService() {

    @Volatile private var worker: Thread? = null
    @Volatile private var bridge: PacketBridge? = null
    @Volatile private var tun: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (running.getAndSet(true)) return
        startForeground(NOTIFICATION_ID, notification("Starting…"))
        TunnelState.set(Stage.CONNECTING, "Loading profile")

        worker = Thread({ loop() }, "edge-vpn").also { it.start() }
    }

    private fun loop() {
        val config = runBlocking { SettingsStore(applicationContext).config.first() }
        val invalid = config.validate()
        if (invalid != null) {
            TunnelState.set(Stage.ERROR, invalid)
            stopTunnel()
            return
        }

        var attempt = 0
        while (running.get()) {
            try {
                TunnelState.set(
                    if (attempt == 0) Stage.CONNECTING else Stage.RECONNECTING,
                    "Connecting to ${config.host}:${config.port}",
                )
                val tunnel = GatewayTunnel(config, protect = { protect(it) })
                val connection = tunnel.open()

                val descriptor = establishTun()
                tun = descriptor
                attempt = 0

                TunnelState.set(Stage.CONNECTED, "Tunnel established")
                updateNotification("Connected · ${config.host}")

                val pb = PacketBridge(descriptor, connection, onError = {
                    TunnelState.set(Stage.RECONNECTING, it.message ?: "tunnel error")
                })
                bridge = pb
                // Publish traffic counters while the bridge runs.
                val meter = Thread({ meter(pb) }, "edge-meter").also { it.start() }
                pb.run()
                meter.interrupt()
                runCatching { descriptor.close() }
            } catch (t: Throwable) {
                if (!running.get()) break
                TunnelState.set(Stage.RECONNECTING, t.message ?: "connection failed")
            }
            if (!running.get()) break
            attempt++
            val backoff = minOf(30_000L, 1_000L * (1L shl minOf(attempt, 5)))
            try {
                Thread.sleep(backoff)
            } catch (_: InterruptedException) {
                break
            }
        }
        TunnelState.set(Stage.DISCONNECTED, "Disconnected")
    }

    private fun meter(pb: PacketBridge) {
        try {
            while (!Thread.currentThread().isInterrupted) {
                TunnelState.traffic(pb.bytesUp.get(), pb.bytesDown.get())
                Thread.sleep(1000)
            }
        } catch (_: InterruptedException) {
        }
    }

    private fun establishTun(): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("EdgeVPN")
            .setMtu(1500)
            .addAddress("10.111.0.2", 32)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
        // Keep this app's own traffic (the tunnel socket) off the VPN.
        runCatching { builder.addDisallowedApplication(packageName) }
        return builder.establish()
            ?: throw IllegalStateException("VPN permission not granted or TUN unavailable")
    }

    private fun stopTunnel() {
        running.set(false)
        bridge?.stop()
        bridge = null
        worker?.interrupt()
        worker = null
        runCatching { tun?.close() }
        tun = null
        TunnelState.set(Stage.DISCONNECTED, "Disconnected")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
        stopSelf()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        running.set(false)
        bridge?.stop()
        super.onDestroy()
    }

    private fun notification(text: String): Notification {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Edge VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, EdgeVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Edge VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stop)
            .build()
    }

    private fun updateNotification(text: String) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        const val ACTION_STOP = "com.edge.vpn.STOP"
        private const val CHANNEL_ID = "edge_vpn"
        private const val NOTIFICATION_ID = 0xED6E
    }
}
