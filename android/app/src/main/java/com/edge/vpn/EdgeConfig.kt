package com.edge.vpn

import android.net.Uri

/**
 * Immutable connection profile for the edge gateway.
 *
 * @param host       gateway hostname or IP (the public HTTPS front).
 * @param port       gateway HTTPS port (the gateway always serves TLS).
 * @param tunnelPath request path used for the authenticated websocket tunnel.
 *                   The gateway forwards any *signed* request to an internal
 *                   backend, so this path only needs to match whatever the
 *                   internal tunnel backend expects.
 * @param secret     shared HMAC secret (>= 32 bytes), identical to the
 *                   gateway's EDGE_HMAC_SECRET.
 * @param sni        TLS SNI / Host to present. Defaults to [host]. Set this to
 *                   the decoy origin's hostname when fronting.
 * @param allowInsecureTls skip certificate verification. Intended ONLY for
 *                   local testing against the installer's self-signed cert.
 */
data class EdgeConfig(
    val host: String,
    val port: Int,
    val tunnelPath: String,
    val secret: String,
    val sni: String = host,
    val allowInsecureTls: Boolean = false,
) {
    val secretBytes: ByteArray get() = secret.toByteArray(Charsets.UTF_8)

    /** Absolute `wss://` URL used to open the tunnel. */
    val wsUrl: String
        get() {
            val p = if (tunnelPath.startsWith("/")) tunnelPath else "/$tunnelPath"
            return "wss://$host:$port$p"
        }

    /** Server-side RequestURI form of [tunnelPath] (raw path + raw query). */
    val requestUri: String
        get() {
            val raw = if (tunnelPath.startsWith("/")) tunnelPath else "/$tunnelPath"
            return raw
        }

    fun validate(): String? {
        if (host.isBlank()) return "Host is required"
        if (port !in 1..65535) return "Port must be between 1 and 65535"
        if (secret.toByteArray(Charsets.UTF_8).size < 32) {
            return "Secret must be at least 32 bytes"
        }
        val probe = Uri.parse("https://$host:$port$requestUri")
        if (probe.host.isNullOrBlank()) return "Host is not a valid name"
        return null
    }

    companion object {
        val EMPTY = EdgeConfig(
            host = "",
            port = 8443,
            tunnelPath = "/tunnel",
            secret = "",
        )
    }
}
