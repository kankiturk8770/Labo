package com.edge.vpn

import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/** Callback used so tunnel sockets bypass the VPN TUN (no routing loop). */
typealias SocketProtector = (Socket) -> Unit

/** TLS socket construction shared by the tunnel and the reachability probe. */
object Tls {

    /**
     * Opens a verified TLS socket to [host]:[port], presenting [sni] as the
     * SNI server name. The underlying plain socket is handed to [protect]
     * before connecting so a VpnService can keep it off the tunnel.
     */
    fun connect(
        host: String,
        port: Int,
        sni: String,
        allowInsecure: Boolean,
        connectTimeoutMs: Int = 15_000,
        protect: SocketProtector? = null,
    ): SSLSocket {
        val plain = Socket()
        protect?.invoke(plain)
        plain.tcpNoDelay = true
        plain.connect(java.net.InetSocketAddress(InetAddress.getByName(host), port), connectTimeoutMs)

        val context = SSLContext.getInstance("TLS")
        context.init(
            null,
            if (allowInsecure) arrayOf<TrustManager>(TRUST_ALL) else null,
            SecureRandom(),
        )

        val socket = context.socketFactory.createSocket(plain, sni, port, true) as SSLSocket
        val params = socket.sslParameters
        if (sni.isNotBlank() && !isIpLiteral(sni)) {
            params.serverNames = listOf(SNIHostName(sni))
        }
        if (!allowInsecure) {
            params.endpointIdentificationAlgorithm = "HTTPS"
        }
        socket.sslParameters = params
        socket.startHandshake()
        return socket
    }

    private fun isIpLiteral(h: String): Boolean =
        h.matches(Regex("^[0-9.]+$")) || h.contains(":")

    private val TRUST_ALL = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
}
