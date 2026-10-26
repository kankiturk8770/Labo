// Package klinkclient is the reusable KLINK client core: it resolves a profile
// (directly or from a panel subscription link), runs a local SOCKS5 server, and
// pipes each stream through a genuine Chrome-fingerprinted TLS 1.3 tunnel to the
// KLINK server. Both the desktop binary (cmd/client) and the Android library
// (mobile/) build on it, so they share one tested implementation and one TLS
// fingerprint.
package klinkclient

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"klink/internal/authtoken"
	"klink/internal/crypto"
	"klink/internal/mux"
	"klink/internal/obfuscation"

	utls "github.com/refraction-networking/utls"
)

// Config is a fully-resolved client profile.
type Config struct {
	ServerAddr string // host:port of the KLINK server (TCP data port)
	SessionHex string // 16-byte session id, hex
	MasterHex  string // 32-byte master key, hex
	SNI        string // mimic domain presented in the TLS ClientHello
	PaddingMax int
}

// SubResponse mirrors the panel's /sub/<token> JSON.
type SubResponse struct {
	SessionID     string `json:"session_id"`
	MasterKey     string `json:"master_key"`
	SNIMasquerade string `json:"sni_masquerade"`
	TCPPort       int    `json:"tcp_port"`
	PaddingMax    int    `json:"padding_max"`
}

// ResolveFromSub fetches a subscription link from the panel (self-signed TLS is
// accepted; the payload is bound to the per-user key) and returns a Config.
func ResolveFromSub(subURL string) (Config, error) {
	u, err := url.Parse(subURL)
	if err != nil {
		return Config{}, err
	}
	cl := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := cl.Get(subURL)
	if err != nil {
		return Config{}, err
	}
	defer resp.Body.Close()

	var sr SubResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return Config{}, err
	}
	if sr.SessionID == "" || sr.MasterKey == "" {
		return Config{}, errors.New("subscription missing session/key")
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}
	pad := sr.PaddingMax
	if pad <= 0 {
		pad = 64
	}
	return Config{
		ServerAddr: fmt.Sprintf("%s:%d", host, sr.TCPPort),
		SessionHex: sr.SessionID,
		MasterHex:  sr.MasterKey,
		SNI:        sr.SNIMasquerade,
		PaddingMax: pad,
	}, nil
}

// Client runs the local SOCKS5 server and the KLINK tunnel.
type Client struct {
	cfg      Config
	sid      [16]byte
	mkey     [32]byte
	cipher   *crypto.CipherState
	obf      *obfuscation.Obfuscator
	listener net.Listener

	globalSeq     uint64
	streamCounter uint32
	closed        atomic.Bool
}

// New builds a Client from a resolved Config.
func New(cfg Config) (*Client, error) {
	if cfg.PaddingMax <= 0 {
		cfg.PaddingMax = 64
	}
	sb, err := hex.DecodeString(cfg.SessionHex)
	if err != nil || len(sb) != 16 {
		return nil, errors.New("invalid session id")
	}
	kb, err := hex.DecodeString(cfg.MasterHex)
	if err != nil || len(kb) != 32 {
		return nil, errors.New("invalid master key")
	}
	c := &Client{cfg: cfg, globalSeq: 1, streamCounter: 1}
	copy(c.sid[:], sb)
	copy(c.mkey[:], kb)

	c.cipher, err = crypto.NewCipherState(c.mkey)
	if err != nil {
		return nil, err
	}
	c.obf = obfuscation.NewObfuscator(obfuscation.DynamicConfig{
		Profile:     obfuscation.ProfileTLSMimic,
		MimicDomain: cfg.SNI,
		PaddingMax:  cfg.PaddingMax,
	})
	return c, nil
}

// ListenAndServe starts the SOCKS5 server on socksAddr and blocks until Close.
func (c *Client) ListenAndServe(socksAddr string) error {
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return err
	}
	c.listener = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			if c.closed.Load() {
				return nil
			}
			continue
		}
		go c.handleSocks(conn)
	}
}

// Close stops the SOCKS server.
func (c *Client) Close() error {
	c.closed.Store(true)
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

// dialTunnel opens a genuine, Chrome-fingerprinted TLS 1.3 connection to the
// server, hiding the auth token in the ClientHello legacy_session_id.
func (c *Client) dialTunnel() (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", c.cfg.ServerAddr, 8*time.Second)
	if err != nil {
		return nil, err
	}
	u := utls.UClient(
		raw,
		&utls.Config{ServerName: c.cfg.SNI, InsecureSkipVerify: true},
		utls.HelloChrome_Auto,
	)
	if err := u.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, err
	}
	u.HandshakeState.Hello.SessionId = authtoken.Make(c.mkey, time.Now().Unix())
	u.HandshakeState.Hello.Raw = nil
	if err := u.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return u, nil
}

func (c *Client) handleSocks(local net.Conn) {
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
		port := binary.BigEndian.Uint16(buf[8:10])
		host = fmt.Sprintf("%s:%d", net.IP(buf[4:8]).String(), port)
	case 0x03:
		dlen := int(buf[4])
		domain := string(buf[5 : 5+dlen])
		port := binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
		host = fmt.Sprintf("%s:%d", domain, port)
	case 0x04:
		port := binary.BigEndian.Uint16(buf[20:22])
		host = fmt.Sprintf("[%s]:%d", net.IP(buf[4:20]).String(), port)
	default:
		return
	}

	_, _ = local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	remote, err := c.dialTunnel()
	if err != nil {
		return
	}
	defer remote.Close()

	streamID := atomic.AddUint32(&c.streamCounter, 1)
	c.sendMuxFrame(remote, &mux.Frame{StreamID: streamID, Cmd: mux.CmdSYN, Payload: []byte(host)})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbuf := make([]byte, 65535)
		for {
			rn, err := remote.Read(rbuf)
			if err != nil {
				break
			}
			rawPkt, err := c.obf.Unwrap(rbuf[:rn])
			if err != nil || len(rawPkt) < 24 {
				continue
			}
			rSeq := binary.BigEndian.Uint64(rawPkt[16:24])
			plain, err := c.cipher.Decrypt(rSeq, rawPkt[24:], c.sid[:])
			if err != nil {
				continue
			}
			frame, err := mux.DecodeFrame(plain)
			if err == nil && frame.Cmd == mux.CmdDATA {
				if _, werr := local.Write(frame.Payload); werr != nil {
					break
				}
			}
		}
		local.Close()
	}()

	lbuf := make([]byte, 16384)
	for {
		ln, err := local.Read(lbuf)
		if err != nil {
			break
		}
		c.sendMuxFrame(remote, &mux.Frame{StreamID: streamID, Cmd: mux.CmdDATA, Payload: lbuf[:ln]})
	}
	c.sendMuxFrame(remote, &mux.Frame{StreamID: streamID, Cmd: mux.CmdFIN})
	remote.Close()
	wg.Wait()
}

func (c *Client) sendMuxFrame(remote net.Conn, f *mux.Frame) {
	seq := atomic.AddUint64(&c.globalSeq, 1)
	rawFrame := mux.EncodeFrame(f)
	enc := c.cipher.Encrypt(seq, rawFrame, c.sid[:])

	pkt := make([]byte, 24+len(enc))
	copy(pkt[:16], c.sid[:])
	binary.BigEndian.PutUint64(pkt[16:24], seq)
	copy(pkt[24:], enc)

	_, _ = remote.Write(c.obf.Wrap(pkt))
}

