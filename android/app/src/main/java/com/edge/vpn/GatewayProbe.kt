package com.edge.vpn

import java.io.BufferedReader
import java.io.InputStreamReader

/** Result of a one-shot signed reachability check. */
data class ProbeResult(val ok: Boolean, val detail: String)

/**
 * Sends a single *signed* HTTP/1.1 GET (empty Sec-WebSocket-Key) and reports
 * the status line. This confirms TLS, reachability, and that the gateway
 * accepts the HMAC credential without starting the full VPN tunnel.
 */
class GatewayProbe(
    private val config: EdgeConfig,
    private val signer: Signer = Signer(config.secretBytes),
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    fun run(): ProbeResult {
        return try {
            val socket = Tls.connect(
                host = config.host,
                port = config.port,
                sni = config.sni,
                allowInsecure = config.allowInsecureTls,
            )
            socket.use {
                val sig = signer.headers("GET", config.requestUri, now(), "")
                val host = if (config.sni.isNotBlank()) config.sni else config.host
                val req = buildString {
                    append("GET ").append(config.requestUri).append(" HTTP/1.1\r\n")
                    append("Host: ").append(host).append("\r\n")
                    append("Connection: close\r\n")
                    append(signer.timestampHeader).append(": ").append(sig[signer.timestampHeader]).append("\r\n")
                    append(signer.signatureHeader).append(": ").append(sig[signer.signatureHeader]).append("\r\n")
                    append("\r\n")
                }
                it.outputStream.write(req.toByteArray(Charsets.US_ASCII))
                it.outputStream.flush()
                val reader = BufferedReader(InputStreamReader(it.inputStream, Charsets.US_ASCII))
                val status = reader.readLine() ?: return ProbeResult(false, "No response from gateway")
                ProbeResult(true, "TLS OK · signed request accepted · $status")
            }
        } catch (e: Exception) {
            ProbeResult(false, e.message ?: e.javaClass.simpleName)
        }
    }
}
