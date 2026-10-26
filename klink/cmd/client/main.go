package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"klink/internal/authtoken"
	"klink/internal/crypto"
	"klink/internal/mux"
	"klink/internal/obfuscation"

	utls "github.com/refraction-networking/utls"
)

// dialKlinkTLS opens a genuine, Chrome-fingerprinted TLS 1.3 connection to the
// KLINK server. The per-connection auth token is hidden in the ClientHello's
// legacy_session_id, so to any observer this is an ordinary browser opening an
// HTTPS site with SNI = the mimic domain. The server's certificate is encrypted
// under TLS 1.3 and the client does not verify it (the mimic site's identity is
// not the trust boundary; the KLINK session key inside is).
func dialKlinkTLS(serverAddr, sni string, mkey [32]byte) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", serverAddr, 8*time.Second)
	if err != nil {
		return nil, err
	}
	u := utls.UClient(
		raw,
		&utls.Config{ServerName: sni, InsecureSkipVerify: true},
		utls.HelloChrome_Auto,
	)
	if err := u.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, err
	}
	u.HandshakeState.Hello.SessionId = authtoken.Make(mkey, time.Now().Unix())
	u.HandshakeState.Hello.Raw = nil
	if err := u.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return u, nil
}

var globalSeq uint64 = 1
var streamCounter uint32 = 1

type SubResponse struct {
	SessionID     string `json:"session_id"`
	MasterKey     string `json:"master_key"`
	SNIMasquerade string `json:"sni_masquerade"`
	TCPPort       int    `json:"tcp_port"`
	PaddingMax    int    `json:"padding_max"`
}

func main() {
	subURL := flag.String("sub", "", "Subscription URL from KLINK Panel (auto-syncs SNI & keys)")
	serverAddr := flag.String("server", "127.0.0.1:443", "KLINK Server Address (Edge IP or Foreign IP)")
	sessionHex := flag.String("session", "", "16-byte Session ID in hex")
	masterHex := flag.String("key", "", "32-byte Master Key in hex")
	sniDomain := flag.String("sni", "www.aparat.com", "Domestic SNI domain to mimic")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 listen address")
	flag.Parse()

	paddingMax := 64

	// دریافت خودکار تنظیمات از پنل در صورت دادن لینک سابسکریپشن
	if *subURL != "" {
		u, err := url.Parse(*subURL)
		if err == nil {
			// The panel serves HTTPS with a self-signed certificate, so the
			// subscription fetch accepts it. The payload itself is bound to the
			// per-user master key, so this fetch is not the trust boundary.
			cl := &http.Client{
				Timeout: 6 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			resp, err := cl.Get(*subURL)
			if err == nil {
				var sr SubResponse
				if json.NewDecoder(resp.Body).Decode(&sr) == nil && sr.SessionID != "" {
					*sessionHex = sr.SessionID
					*masterHex = sr.MasterKey
					*sniDomain = sr.SNIMasquerade
					if sr.PaddingMax > 0 {
						paddingMax = sr.PaddingMax
					}
					host, _, err := net.SplitHostPort(u.Host)
					if err != nil {
						host = u.Host
					}
					*serverAddr = fmt.Sprintf("%s:%d", host, sr.TCPPort)
					log.Printf("[KLINK-CLIENT] Synced from Panel -> Masquerade: %s | Server: %s", *sniDomain, *serverAddr)
				}
				resp.Body.Close()
			}
		}
	}

	if *sessionHex == "" || *masterHex == "" {
		log.Println("[KLINK-CLIENT] Usage: klink-client -sub https://SERVER:8443/sub/TOKEN -socks 127.0.0.1:1080")
		return
	}

	var sid [16]byte
	sb, _ := hex.DecodeString(*sessionHex)
	copy(sid[:], sb)

	var mkey [32]byte
	kb, _ := hex.DecodeString(*masterHex)
	copy(mkey[:], kb)

	cipherState, err := crypto.NewCipherState(mkey)
	if err != nil {
		log.Fatalf("Cipher init error: %v", err)
	}

	obf := obfuscation.NewObfuscator(obfuscation.DynamicConfig{
		Profile:     obfuscation.ProfileTLSMimic,
		MimicDomain: *sniDomain,
		PaddingMax:  paddingMax,
	})

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("Failed to listen on SOCKS5 %s: %v", *socksAddr, err)
	}
	log.Printf("[KLINK-CLIENT] Local SOCKS5 on %s -> Pipe to %s (SNI: %s)", *socksAddr, *serverAddr, *sniDomain)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSocksConnection(clientConn, *serverAddr, *sniDomain, sid, mkey, cipherState, obf)
	}
}

func handleSocksConnection(local net.Conn, serverAddr, sni string, sid [16]byte, mkey [32]byte, cs *crypto.CipherState, obf *obfuscation.Obfuscator) {
	defer local.Close()

	buf := make([]byte, 512)
	n, err := local.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	_, _ = local.Write([]byte{0x05, 0x00})

	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		return
	}

	var host string
	switch buf[3] {
	case 0x01:
		host = net.IP(buf[4:8]).String()
		port := binary.BigEndian.Uint16(buf[8:10])
		host = fmt.Sprintf("%s:%d", host, port)
	case 0x03:
		dlen := int(buf[4])
		domain := string(buf[5 : 5+dlen])
		port := binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
		host = fmt.Sprintf("%s:%d", domain, port)
	default:
		return
	}

	_, _ = local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	remote, err := dialKlinkTLS(serverAddr, sni, mkey)
	if err != nil {
		return
	}
	defer remote.Close()

	streamID := atomic.AddUint32(&streamCounter, 1)

	sendMuxFrame(remote, sid, cs, obf, &mux.Frame{
		StreamID: streamID,
		Cmd:      mux.CmdSYN,
		Payload:  []byte(host),
	})

	go func() {
		rbuf := make([]byte, 65535)
		for {
			rn, err := remote.Read(rbuf)
			if err != nil {
				break
			}
			rawPkt, err := obf.Unwrap(rbuf[:rn])
			if err != nil || len(rawPkt) < 24 {
				continue
			}
			rSeq := binary.BigEndian.Uint64(rawPkt[16:24])
			plain, err := cs.Decrypt(rSeq, rawPkt[24:], sid[:])
			if err != nil {
				continue
			}
			frame, err := mux.DecodeFrame(plain)
			if err == nil && frame.Cmd == mux.CmdDATA {
				_, _ = local.Write(frame.Payload)
			}
		}
	}()

	lbuf := make([]byte, 16384)
	for {
		ln, err := local.Read(lbuf)
		if err != nil {
			if err != io.EOF {
				break
			}
			break
		}
		sendMuxFrame(remote, sid, cs, obf, &mux.Frame{
			StreamID: streamID,
			Cmd:      mux.CmdDATA,
			Payload:  lbuf[:ln],
		})
	}
}

func sendMuxFrame(remote net.Conn, sid [16]byte, cs *crypto.CipherState, obf *obfuscation.Obfuscator, f *mux.Frame) {
	seq := atomic.AddUint64(&globalSeq, 1)
	rawFrame := mux.EncodeFrame(f)
	enc := cs.Encrypt(seq, rawFrame, sid[:])

	pkt := make([]byte, 24+len(enc))
	copy(pkt[:16], sid[:])
	binary.BigEndian.PutUint64(pkt[16:24], seq)
	copy(pkt[24:], enc)

	_, _ = remote.Write(obf.Wrap(pkt))
}
