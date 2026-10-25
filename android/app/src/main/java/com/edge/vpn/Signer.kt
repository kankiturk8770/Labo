package com.edge.vpn

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Produces the exact credential the edge gateway validates.
 *
 * The gateway (see server/main.go, SignatureValidator) authenticates this
 * canonical byte sequence:
 *
 *     Unix timestamp + "\n" +
 *     HTTP method    + "\n" +
 *     Request URI    + "\n" +
 *     Sec-WebSocket-Key
 *
 * `X-Signature` carries the lowercase hex HMAC-SHA-256 result and
 * `X-Signature-Timestamp` carries the Unix seconds timestamp. For ordinary
 * HTTP requests the websocket key is empty; for a websocket upgrade it is the
 * exact value sent in the `Sec-WebSocket-Key` request header.
 *
 * The request URI must be the server-side RequestURI form: the raw (still
 * percent-encoded) path plus `?` and the raw query when a query is present.
 * This matches Go's *url.URL.RequestURI(), so the signed bytes are identical
 * on both sides.
 */
class Signer(secret: ByteArray) {

    init {
        require(secret.size >= 32) {
            "HMAC secret must contain at least 32 bytes to match the gateway"
        }
    }

    private val keySpec = SecretKeySpec(secret, HMAC_ALGORITHM)

    /** Header name carrying the hex signature. */
    val signatureHeader = SIGNATURE_HEADER

    /** Header name carrying the Unix-seconds timestamp. */
    val timestampHeader = TIMESTAMP_HEADER

    /**
     * Returns the two headers the gateway requires for [method] and
     * [requestUri], stamped at [timestampSeconds] and bound to
     * [secWebSocketKey] (empty for plain HTTP).
     */
    fun headers(
        method: String,
        requestUri: String,
        timestampSeconds: Long,
        secWebSocketKey: String = "",
    ): Map<String, String> {
        val stamp = timestampSeconds.toString()
        val canonical = stamp + "\n" + method + "\n" + requestUri + "\n" + secWebSocketKey
        return mapOf(
            TIMESTAMP_HEADER to stamp,
            SIGNATURE_HEADER to hex(mac(canonical)),
        )
    }

    private fun mac(canonical: String): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(keySpec)
        return mac.doFinal(canonical.toByteArray(Charsets.UTF_8))
    }

    private fun hex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            out.append(HEX[v ushr 4])
            out.append(HEX[v and 0x0F])
        }
        return out.toString()
    }

    companion object {
        const val SIGNATURE_HEADER = "X-Signature"
        const val TIMESTAMP_HEADER = "X-Signature-Timestamp"
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
