// Package authtoken defines the 32-byte authenticator a KLINK client hides in
// its TLS ClientHello legacy_session_id so the server can tell real clients
// from probes before completing the handshake. Shared by client and server so
// the format stays in one place. It pulls in no heavy dependencies.
//
// Layout (32 bytes): nonce(8) + unixSeconds(uint32,4) + HMAC-SHA256(masterKey,
// nonce||time)[:20]. The random nonce makes every connection's token unique,
// which lets the server keep a short anti-replay cache and prevents a captured
// ClientHello from being replayed within the time window.
package authtoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Window bounds how far the token timestamp may drift from the server clock.
const Window = 90 * time.Second

// Make builds a fresh, unique token for one connection.
func Make(masterKey [32]byte) []byte {
	t := make([]byte, 32)
	_, _ = rand.Read(t[:8])
	binary.BigEndian.PutUint32(t[8:12], uint32(time.Now().Unix()))
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(t[:12])
	copy(t[12:], mac.Sum(nil)[:20])
	return t
}

// Verify reports whether sid is a valid, in-window KLINK auth token.
func Verify(masterKey [32]byte, sid []byte, now time.Time) bool {
	if len(sid) != 32 {
		return false
	}
	ts := int64(binary.BigEndian.Uint32(sid[8:12]))
	drift := now.Sub(time.Unix(ts, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > Window {
		return false
	}
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(sid[:12])
	return hmac.Equal(sid[12:32], mac.Sum(nil)[:20])
}

// ReplayKey returns the unique per-connection portion (nonce+time) to use as a
// key in an anti-replay cache.
func ReplayKey(sid []byte) string {
	if len(sid) < 12 {
		return string(sid)
	}
	return string(sid[:12])
}
