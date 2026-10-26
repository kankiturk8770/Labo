package com.klink.vpn

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
import klinkmobile.Klinkmobile
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

/**
 * The system VPN service. It builds a TUN that captures ALL device traffic
 * (IPv4 + IPv6 default routes, DNS redirected into the tunnel) and hands the
 * TUN fd to the Go core (klinkmobile), which runs tun2socks + the KLINK SOCKS
 * client. Only this app's own UID is excluded from the VPN so the client's
 * upstream sockets to the server don't loop back — nothing else bypasses it.
 */
class KlinkVpnService : VpnService() {

    @Volatile private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification("Connecting…"))
        TunnelState.set(Stage.CONNECTING, "Starting tunnel")
        Thread({ connect() }, "klink-start").start()
        return START_STICKY
    }

    private fun connect() {
        try {
            val profile = runBlocking { SettingsStore(applicationContext).profile.first() }
            if (profile.subUrl.isBlank() &&
                (profile.serverAddr.isBlank() || profile.sessionHex.isBlank() || profile.masterHex.isBlank())
            ) {
                TunnelState.set(Stage.ERROR, "No subscription link or manual profile set")
                stopTunnel()
                return
            }

            val builder = Builder()
                .setSession("KLINK VPN")
                .setMtu(1500)
                .addAddress("10.66.0.2", 32)
                .addAddress("fd66:6666::2", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("2606:4700:4700::1111")
            runCatching { builder.addDisallowedApplication(packageName) }

            val pfd = builder.establish()
                ?: throw IllegalStateException("VPN permission not granted")
            tun = pfd

            // Hand the raw fd to the Go core; it runs tun2socks + KLINK SOCKS.
            Klinkmobile.start(
                pfd.fd.toLong(),
                profile.subUrl,
                profile.serverAddr,
                profile.sessionHex,
                profile.masterHex,
                profile.sni,
            )

            TunnelState.set(Stage.CONNECTED, "Connected")
            updateNotification("Connected")
        } catch (t: Throwable) {
            TunnelState.set(Stage.ERROR, t.message ?: "connection failed")
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        runCatching { Klinkmobile.stop() }
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
        runCatching { Klinkmobile.stop() }
        super.onDestroy()
    }

    private fun notification(text: String): Notification {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "KLINK VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, KlinkVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("KLINK VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stop)
            .build()
    }

    private fun updateNotification(text: String) {
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        const val ACTION_STOP = "com.klink.vpn.STOP"
        private const val CHANNEL_ID = "klink_vpn"
        private const val NOTIFICATION_ID = 0x4B4C
    }
}
