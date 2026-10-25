package com.edge.vpn

import java.io.BufferedInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.SSLSocket

/**
 * A minimal, correct RFC 6455 client used as the authenticated transport to
 * the edge gateway.
 *
 * It owns the `Sec-WebSocket-Key` (which OkHttp hides) so the HMAC the gateway
 * validates can be computed over the exact key that is sent on the wire. The
 * gateway forwards the signed upgrade to an internal backend; the resulting
 * duplex binary frame stream is the tunnel the VpnService pumps packets over.
 */
class GatewayTunnel(
    private val config: EdgeConfig,
    private val signer: Signer = Signer(config.secretBytes),
    private val protect: SocketProtector? = null,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) {

    /** An open tunnel. Thread-safe for one reader and one writer. */
    class Connection internal constructor(
        private val socket: SSLSocket,
        private val input: InputStream,
        private val output: DataOutputStream,
    ) {
        private val random = SecureRandom()
        private val writeLock = Any()

        /** Sends one binary message. */
        @Throws(IOException::class)
        fun send(data: ByteArray, offset: Int = 0, length: Int = data.size) {
            synchronized(writeLock) { writeFrame(OPCODE_BINARY, data, offset, length) }
        }

        /**
         * Blocks for the next binary message. Returns null on a clean close.
         * Control frames (ping/close) are handled transparently.
         */
        @Throws(IOException::class)
        fun receive(): ByteArray? {
            while (true) {
                val frame = readFrame() ?: return null
                when (frame.opcode) {
                    OPCODE_BINARY, OPCODE_CONTINUATION -> return frame.payload
                    OPCODE_PING -> synchronized(writeLock) {
                        writeFrame(OPCODE_PONG, frame.payload, 0, frame.payload.size)
                    }
                    OPCODE_PONG -> {} // ignore
                    OPCODE_CLOSE -> {
                        synchronized(writeLock) { writeFrame(OPCODE_CLOSE, EMPTY, 0, 0) }
                        return null
                    }
                    else -> throw IOException("unsupported opcode ${frame.opcode}")
                }
            }
        }

        fun close() {
            try {
                synchronized(writeLock) { writeFrame(OPCODE_CLOSE, EMPTY, 0, 0) }
            } catch (_: IOException) {
            } finally {
                runCatching { socket.close() }
            }
        }

        private fun writeFrame(opcode: Int, data: ByteArray, offset: Int, length: Int) {
            output.writeByte(0x80 or opcode) // FIN + opcode
            val mask = ByteArray(4).also { random.nextBytes(it) }
            when {
                length < 126 -> output.writeByte(0x80 or length)
                length < 65_536 -> {
                    output.writeByte(0x80 or 126)
                    output.writeShort(length)
                }
                else -> {
                    output.writeByte(0x80 or 127)
                    output.writeLong(length.toLong())
                }
            }
            output.write(mask)
            val masked = ByteArray(length)
            for (i in 0 until length) {
                masked[i] = (data[offset + i].toInt() xor mask[i and 3].toInt()).toByte()
            }
            output.write(masked)
            output.flush()
        }

        private class Frame(val opcode: Int, val payload: ByteArray)

        private fun readFrame(): Frame? {
            val b0 = input.read()
            if (b0 == -1) return null
            val opcode = b0 and 0x0F
            val b1 = readByte()
            val masked = (b1 and 0x80) != 0
            var len = (b1 and 0x7F).toLong()
            when (len.toInt()) {
                126 -> len = ((readByte().toLong() shl 8) or readByte().toLong())
                127 -> {
                    len = 0
                    repeat(8) { len = (len shl 8) or readByte().toLong() }
                }
            }
            if (len > MAX_FRAME) throw IOException("frame too large: $len")
            val maskKey = if (masked) ByteArray(4) { readByte().toByte() } else null
            val payload = ByteArray(len.toInt())
            readFully(payload)
            if (maskKey != null) {
                for (i in payload.indices) {
                    payload[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
                }
            }
            return Frame(opcode, payload)
        }

        private fun readByte(): Int {
            val v = input.read()
            if (v == -1) throw EOFException("tunnel closed")
            return v
        }

        private fun readFully(buf: ByteArray) {
            var read = 0
            while (read < buf.size) {
                val n = input.read(buf, read, buf.size - read)
                if (n == -1) throw EOFException("tunnel closed mid-frame")
                read += n
            }
        }
    }

    /** Performs the signed upgrade and returns an open [Connection]. */
    @Throws(IOException::class)
    fun open(): Connection {
        val socket = Tls.connect(
            host = config.host,
            port = config.port,
            sni = config.sni,
            allowInsecure = config.allowInsecureTls,
            protect = protect,
        )
        val input = BufferedInputStream(socket.inputStream)
        val output = DataOutputStream(socket.outputStream.buffered())

        val key = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val sig = signer.headers(
            method = "GET",
            requestUri = config.requestUri,
            timestampSeconds = now(),
            secWebSocketKey = key,
        )

        val hostHeader = if (config.sni.isNotBlank()) config.sni else config.host
        val request = buildString {
            append("GET ").append(config.requestUri).append(" HTTP/1.1\r\n")
            append("Host: ").append(hostHeader).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append(signer.timestampHeader).append(": ").append(sig[signer.timestampHeader]).append("\r\n")
            append(signer.signatureHeader).append(": ").append(sig[signer.signatureHeader]).append("\r\n")
            append("\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()

        val statusLine = readHeaderLine(input)
        if (!statusLine.startsWith("HTTP/1.1 101")) {
            runCatching { socket.close() }
            throw IOException("upgrade rejected: $statusLine")
        }
        var accept: String? = null
        while (true) {
            val line = readHeaderLine(input)
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx > 0 && line.substring(0, idx).trim().equals("Sec-WebSocket-Accept", true)) {
                accept = line.substring(idx + 1).trim()
            }
        }
        val expected = acceptFor(key)
        if (accept != expected) {
            runCatching { socket.close() }
            throw IOException("invalid Sec-WebSocket-Accept")
        }
        return Connection(socket, input, output)
    }

    private fun readHeaderLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c == -1) throw EOFException("connection closed during handshake")
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun acceptFor(key: String): String {
        val magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        val sha1 = MessageDigest.getInstance("SHA-1").digest((key + magic).toByteArray(Charsets.US_ASCII))
        return Base64.getEncoder().encodeToString(sha1)
    }

    companion object {
        private const val OPCODE_CONTINUATION = 0x0
        private const val OPCODE_BINARY = 0x2
        private const val OPCODE_CLOSE = 0x8
        private const val OPCODE_PING = 0x9
        private const val OPCODE_PONG = 0xA
        private const val MAX_FRAME = 16L * 1024 * 1024
        private val EMPTY = ByteArray(0)
    }
}
