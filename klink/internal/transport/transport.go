package transport

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"klink/internal/crypto"
	"klink/internal/mux"
	"klink/internal/obfuscation"
	"klink/internal/session"
)

type Engine struct {
	SessionMgr *session.SessionManager
	Obfuscator *obfuscation.Obfuscator
	TCPAddr    string
	UDPAddr    string
	// MasterKey and TLSCert back the genuine TLS handshake gate (tlsgate.go).
	// They are set by main after NewEngine; the KLINK data/crypto/mux pipeline
	// below is unchanged and runs inside the terminated TLS session.
	MasterKey [32]byte
	TLSCert   tls.Certificate
	streamsMu sync.Mutex
	streams   map[uint32]net.Conn
	seenMu    sync.Mutex
	seen      map[string]int64 // anti-replay cache: token -> expiry unix
}

func NewEngine(sm *session.SessionManager, obf *obfuscation.Obfuscator, tcpAddr, udpAddr string) *Engine {
	return &Engine{
		SessionMgr: sm,
		Obfuscator: obf,
		TCPAddr:    tcpAddr,
		UDPAddr:    udpAddr,
		streams:    make(map[uint32]net.Conn),
	}
}

func (e *Engine) Start() error {
	go e.startUDP()
	return e.startTCP()
}

func (e *Engine) startTCP() error {
	ln, err := net.Listen("tcp", e.TCPAddr)
	if err != nil {
		return err
	}
	cfg := e.Obfuscator.GetConfig()
	log.Printf("[KLINK-TCP] Listening on %s (Active Masquerade: %s -> %s)", e.TCPAddr, cfg.MimicDomain, cfg.FallbackAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go e.handleTCPConn(conn)
	}
}

func (e *Engine) handleTCPConn(conn net.Conn) {
	// Genuine TLS handshake gate: authenticated KLINK clients speak a real
	// Chrome-fingerprinted TLS 1.3 handshake (token hidden in the ClientHello
	// session id). Anything else — browsers, scanners, active probes — is
	// diverted untouched to the real decoy site, which serves its own real
	// certificate and content.
	gated, raw, ok := e.gateTLS(conn)
	if !ok {
		e.Obfuscator.DivertToDomesticSite(conn, raw)
		return
	}
	conn = gated

	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	// اگر در پنل مدیریت، UpstreamTunnel (آی‌پی سرور آلمان در معماری دو سروری لبه) تنظیم شده باشد
	// و بسته یک فریم معتبر KLINK باشد، می‌توانیم یا مستقیم در لایه رمزنگاری بازش کنیم یا به سرور آلمان لوله کنیم.
	rawPacket, err := e.Obfuscator.Unwrap(buf[:n])
	if err != nil || len(rawPacket) < 24 {
		// هرگونه پینگ HTTP/TLS، مرورگر، یا اسکن فیلترچی فوراً به سرور واقعی سایت داخلی (آپارات/آنتن) لوله می‌شود
		// و گواهی SSL واقعی سایت داخلی را تحویل می‌گیرد!
		e.Obfuscator.DivertToDomesticSite(conn, buf[:n])
		return
	}

	var sid [16]byte
	copy(sid[:], rawPacket[:16])
	seq := binary.BigEndian.Uint64(rawPacket[16:24])

	sess, valid := e.SessionMgr.ValidateAndMigrate(sid, seq, int64(n), conn.RemoteAddr())
	if !valid {
		e.Obfuscator.DivertToDomesticSite(conn, buf[:n])
		return
	}

	defer conn.Close()

	// بررسی اینکه آیا سرور در حالت Bridge/Pipe به سرور خارج (UpstreamTunnel) است یا خودش سرور نهایی است
	cfg := e.Obfuscator.GetConfig()
	if cfg.UpstreamTunnel != "" {
		e.pipeToUpstreamServer(conn, cfg.UpstreamTunnel, buf[:n], sess)
		return
	}

	e.processDecryptedPacket(sess, seq, rawPacket[24:], func(resp []byte) {
		_, _ = conn.Write(e.Obfuscator.Wrap(resp))
	})

	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		pkt, err := e.Obfuscator.Unwrap(buf[:n])
		if err != nil || len(pkt) < 24 {
			break
		}
		copy(sid[:], pkt[:16])
		seq = binary.BigEndian.Uint64(pkt[16:24])
		sess, valid = e.SessionMgr.ValidateAndMigrate(sid, seq, int64(n), conn.RemoteAddr())
		if !valid {
			break
		}
		e.processDecryptedPacket(sess, seq, pkt[24:], func(resp []byte) {
			_, _ = conn.Write(e.Obfuscator.Wrap(resp))
		})
	}
}

// لوله‌کشی نامرئی از سرور لبه (داخل) به سرور اصلی (آلمان) فقط برای کاربران احراز هویت شده
// در این حالت فیلترچی روی سرور داخل هر تستی بزند فقط آپارات/آنتن را می‌بیند و آی‌پی آلمان کاملاً مخفی می‌ماند
func (e *Engine) pipeToUpstreamServer(clientConn net.Conn, upstreamAddr string, firstChunk []byte, sess *session.UserSession) {
	upConn, err := net.DialTimeout("tcp", upstreamAddr, 6*time.Second)
	if err != nil {
		return
	}
	defer upConn.Close()

	if len(firstChunk) > 0 {
		_, _ = upConn.Write(firstChunk)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				break
			}
			_, _ = e.SessionMgr.ValidateAndMigrate(sess.SessionID, 0, int64(n), clientConn.RemoteAddr())
			if _, werr := upConn.Write(buf[:n]); werr != nil {
				break
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := upConn.Read(buf)
			if err != nil {
				break
			}
			_, _ = e.SessionMgr.ValidateAndMigrate(sess.SessionID, 0, int64(n), nil)
			if _, werr := clientConn.Write(buf[:n]); werr != nil {
				break
			}
		}
	}()
	wg.Wait()
}

func (e *Engine) startUDP() {
	addr, err := net.ResolveUDPAddr("udp", e.UDPAddr)
	if err != nil {
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	log.Printf("[KLINK-UDP] Listening on %s (Zero-Response Anti-Probe Active)", e.UDPAddr)

	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil || n < 24 {
			continue
		}
		pkt, err := e.Obfuscator.Unwrap(buf[:n])
		if err != nil || len(pkt) < 24 {
			continue
		}
		var sid [16]byte
		copy(sid[:], pkt[:16])
		seq := binary.BigEndian.Uint64(pkt[16:24])

		sess, valid := e.SessionMgr.ValidateAndMigrate(sid, seq, int64(n), raddr)
		if !valid {
			continue
		}

		clientAddr := raddr
		e.processDecryptedPacket(sess, seq, pkt[24:], func(resp []byte) {
			_, _ = conn.WriteToUDP(e.Obfuscator.Wrap(resp), clientAddr)
		})
	}
}

func (e *Engine) processDecryptedPacket(sess *session.UserSession, seq uint64, cipherPayload []byte, sendBack func([]byte)) {
	plain, err := sess.Cipher.Decrypt(crypto.DirClientToServer, seq, cipherPayload, sess.SessionID[:])
	if err != nil {
		return
	}

	frame, err := mux.DecodeFrame(plain)
	if err != nil {
		return
	}

	switch frame.Cmd {
	case mux.CmdSYN:
		targetAddr := string(frame.Payload)
		go func(streamID uint32, target string) {
			remote, err := net.DialTimeout("tcp", target, 6*time.Second)
			if err != nil {
				return
			}
			e.streamsMu.Lock()
			e.streams[streamID] = remote
			e.streamsMu.Unlock()

			defer func() {
				remote.Close()
				e.streamsMu.Lock()
				delete(e.streams, streamID)
				e.streamsMu.Unlock()
			}()

			rbuf := make([]byte, 16384)
			for {
				rn, err := remote.Read(rbuf)
				if err != nil {
					if err != io.EOF {
						break
					}
					break
				}
				// One monotonic per-session counter for ALL server->client
				// packets across every stream, so no two s2c packets ever reuse
				// a nonce under this session's key.
				respSeq := sess.NextTx()
				_, _ = e.SessionMgr.ValidateAndMigrate(sess.SessionID, 0, int64(rn), nil)
				outFrame := mux.EncodeFrame(&mux.Frame{
					StreamID: streamID,
					Cmd:      mux.CmdDATA,
					Payload:  rbuf[:rn],
				})
				enc := sess.Cipher.Encrypt(crypto.DirServerToClient, respSeq, outFrame, sess.SessionID[:])
				fullPkt := make([]byte, 24+len(enc))
				copy(fullPkt[:16], sess.SessionID[:])
				binary.BigEndian.PutUint64(fullPkt[16:24], respSeq)
				copy(fullPkt[24:], enc)
				sendBack(fullPkt)
			}
		}(frame.StreamID, targetAddr)

	case mux.CmdDATA:
		e.streamsMu.Lock()
		remote, ok := e.streams[frame.StreamID]
		e.streamsMu.Unlock()
		if ok {
			_, _ = remote.Write(frame.Payload)
		}

	case mux.CmdFIN:
		e.streamsMu.Lock()
		if remote, ok := e.streams[frame.StreamID]; ok {
			remote.Close()
			delete(e.streams, frame.StreamID)
		}
		e.streamsMu.Unlock()
	}
}
