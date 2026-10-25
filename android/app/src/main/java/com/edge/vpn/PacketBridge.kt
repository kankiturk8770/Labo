package com.edge.vpn

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Pumps raw IP packets between the TUN interface and an open [GatewayTunnel]
 * connection.
 *
 * Framing contract (L3-over-WebSocket): every WebSocket **binary message**
 * carries exactly one IP packet, verbatim, with no additional header. The
 * internal backend that the gateway forwards to is expected to implement the
 * mirror image — decapsulate each packet, perform NAT / userspace TCP-UDP
 * handling against the real network, and send reply packets back as one
 * binary message each. This keeps the Android side a faithful, complete L3
 * endpoint regardless of the backend's internal stack.
 */
class PacketBridge(
    private val tun: ParcelFileDescriptor,
    private val connection: GatewayTunnel.Connection,
    private val mtu: Int = 1500,
    private val onError: (Throwable) -> Unit = {},
) {
    private val running = AtomicBoolean(true)
    val bytesUp = AtomicLong(0)
    val bytesDown = AtomicLong(0)

    private val tunIn = FileInputStream(tun.fileDescriptor)
    private val tunOut = FileOutputStream(tun.fileDescriptor)

    /** Starts both pump threads and blocks until one stops (then stops all). */
    fun run() {
        val up = Thread({ pumpUp() }, "edge-tun-up")
        val down = Thread({ pumpDown() }, "edge-tun-down")
        up.start()
        down.start()
        up.join()
        down.join()
    }

    fun stop() {
        running.set(false)
        runCatching { connection.close() }
        runCatching { tunIn.close() }
        runCatching { tunOut.close() }
    }

    /** TUN -> tunnel: device packets go out to the gateway. */
    private fun pumpUp() {
        val buffer = ByteArray(mtu)
        try {
            while (running.get()) {
                val n = tunIn.read(buffer)
                if (n <= 0) {
                    if (n < 0) break else continue
                }
                connection.send(buffer, 0, n)
                bytesUp.addAndGet(n.toLong())
            }
        } catch (t: Throwable) {
            if (running.get()) onError(t)
        } finally {
            stop()
        }
    }

    /** tunnel -> TUN: reply packets come back from the gateway. */
    private fun pumpDown() {
        try {
            while (running.get()) {
                val packet = connection.receive() ?: break
                if (packet.isNotEmpty()) {
                    tunOut.write(packet)
                    bytesDown.addAndGet(packet.size.toLong())
                }
            }
        } catch (t: Throwable) {
            if (running.get()) onError(t)
        } finally {
            stop()
        }
    }
}
