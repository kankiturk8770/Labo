package transport

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"klink/internal/authtoken"
)

// prefixConn replays already-read bytes (the peeked ClientHello) before
// continuing to read from the underlying connection, so a real TLS server can
// take over the handshake transparently.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// peekClientHello reads the first TLS record and extracts the ClientHello's
// legacy_session_id. It returns every byte it consumed in raw so the caller can
// replay them, either into a real TLS server (authenticated client) or into the
// decoy site (anything else).
func peekClientHello(conn net.Conn) (sessionID, raw []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return nil, hdr, err
	}
	// 0x16 = TLS handshake record.
	if hdr[0] != 0x16 {
		return nil, hdr, errors.New("not a TLS handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 38 || recLen > 65535 {
		return nil, hdr, errors.New("implausible record length")
	}
	body := make([]byte, recLen)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, hdr, err
	}
	raw = append(hdr, body...)

	// Handshake: type(1)=0x01 ClientHello, length(3), version(2), random(32),
	// session_id_len(1), session_id...
	const off = 1 + 3 + 2 + 32
	if len(body) < off+1 || body[0] != 0x01 {
		return nil, raw, errors.New("not a ClientHello")
	}
	sidLen := int(body[off])
	if off+1+sidLen > len(body) {
		return nil, raw, errors.New("truncated session_id")
	}
	sessionID = body[off+1 : off+1+sidLen]
	return sessionID, raw, nil
}

// seenToken records a token and reports whether it was already used (a replay).
func (e *Engine) seenToken(sid []byte) bool {
	key := authtoken.ReplayKey(sid)
	now := time.Now().Unix()
	ttl := int64(authtoken.Window/time.Second) + 5

	e.seenMu.Lock()
	defer e.seenMu.Unlock()
	if e.seen == nil {
		e.seen = make(map[string]int64)
	}
	for k, exp := range e.seen {
		if exp < now {
			delete(e.seen, k)
		}
	}
	if _, used := e.seen[key]; used {
		return true
	}
	e.seen[key] = now + ttl
	return false
}

// gateTLS inspects an incoming connection. If it carries a valid KLINK auth
// token in its ClientHello, it terminates a real TLS 1.3 session (the server
// certificate is encrypted under TLS 1.3, so a passive observer cannot tell it
// apart from the mimic site) and returns that connection for the normal KLINK
// pipeline. Otherwise it returns ok=false along with the bytes already read, so
// the caller can divert the connection to the real decoy site untouched.
func (e *Engine) gateTLS(conn net.Conn) (net.Conn, []byte, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	sid, raw, err := peekClientHello(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || !authtoken.Verify(e.MasterKey, sid, time.Now()) {
		return conn, raw, false
	}
	// Anti-replay: a captured ClientHello replayed within the window is treated
	// like any unauthenticated connection and diverted to the real decoy site.
	if e.seenToken(sid) {
		return conn, raw, false
	}

	tconn := tls.Server(&prefixConn{Conn: conn, prefix: raw}, &tls.Config{
		Certificates: []tls.Certificate{e.TLSCert},
		MinVersion:   tls.VersionTLS13,
	})
	_ = tconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tconn.Handshake(); err != nil {
		return conn, nil, false
	}
	_ = tconn.SetDeadline(time.Time{})
	return tconn, nil, true
}
