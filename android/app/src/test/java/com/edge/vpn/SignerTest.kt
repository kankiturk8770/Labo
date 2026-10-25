package com.edge.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the client signature to the gateway contract. The expected hex values
 * are produced by the same canonical string the server validates
 * (server/main.go + main_test.go, secret "0123456789abcdef0123456789abcdef").
 */
class SignerTest {

    private val secret = "0123456789abcdef0123456789abcdef".toByteArray()

    @Test
    fun plainHttpVectorMatchesServer() {
        val signer = Signer(secret)
        val h = signer.headers(
            method = "GET",
            requestUri = "/path%2Fpart?x=1",
            timestampSeconds = 1_700_000_000L,
            secWebSocketKey = "",
        )
        assertEquals("1700000000", h[Signer.TIMESTAMP_HEADER])
        assertEquals(
            "2d65c0aa3932ed011bcdcd135aa5fa97e71e575f2669224e5fa93d24d261a2e6",
            h[Signer.SIGNATURE_HEADER],
        )
    }

    @Test
    fun websocketVectorBindsTheKey() {
        val signer = Signer(secret)
        val h = signer.headers(
            method = "GET",
            requestUri = "/tunnel",
            timestampSeconds = 1_700_000_000L,
            secWebSocketKey = "dGhlIHNhbXBsZSBub25jZQ==",
        )
        assertEquals(
            "7e6c82d4e0e89893213e905d151b16a6f43d0db7f841a41d30ce32bdfa7eb208",
            h[Signer.SIGNATURE_HEADER],
        )
    }

    @Test
    fun signatureIsLowercaseHex64() {
        val h = Signer(secret).headers("GET", "/", 1L, "")
        val sig = h[Signer.SIGNATURE_HEADER]!!
        assertEquals(64, sig.length)
        assertTrue(sig.all { it in "0123456789abcdef" })
    }

    @Test(expected = IllegalArgumentException::class)
    fun shortSecretRejected() {
        Signer("tooshort".toByteArray())
    }
}
