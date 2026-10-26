// Package authtoken defines the 32-byte authenticator a KLINK client hides in
// its TLS ClientHello legacy_session_id so the server can tell real clients
// from probes before completing the handshake. Shared by client and server so
// the format stays in one place. It pulls in no heavy dependencies.
package authtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Window bounds how far the token timestamp may drift from the server clock,
// and therefore the replay window for a captured ClientHello.
const Window = 90 * time.Second

// Make builds the token: unix-seconds(8) + HMAC-SHA256(masterKey, those 8
// bytes)[:24]. masterKey is shared between client and server.
func Make(masterKey [32]byte, unixSeconds int64) []byte {
	token := make([]byte, 32)
	binary.BigEndian.PutUint64(token[:8], uint64(unixSeconds))
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(token[:8])
	copy(token[8:], mac.Sum(nil)[:24])
	return token
}

// Verify reports whether sid is a valid, in-window KLINK auth token.
func Verify(masterKey [32]byte, sid []byte, now time.Time) bool {
	if len(sid) != 32 {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(sid[:8]))
	drift := now.Sub(time.Unix(ts, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > Window {
		return false
	}
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(sid[:8])
	return hmac.Equal(sid[8:32], mac.Sum(nil)[:24])
}
