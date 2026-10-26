package crypto

import (
	"bytes"
	"testing"
)

func newState(t *testing.T) *CipherState {
	t.Helper()
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	cs, err := NewCipherState(k)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestRoundTripPerDirection(t *testing.T) {
	cs := newState(t)
	ad := []byte("session-id")
	msg := []byte("hello klink")

	for _, dir := range []byte{DirClientToServer, DirServerToClient} {
		ct := cs.Encrypt(dir, 42, msg, ad)
		pt, err := cs.Decrypt(dir, 42, ct, ad)
		if err != nil {
			t.Fatalf("dir %d: decrypt failed: %v", dir, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("dir %d: round-trip mismatch", dir)
		}
	}
}

// The whole point of the direction byte: the same (key, seq) in opposite
// directions must NOT produce the same ciphertext, and must not cross-decrypt.
func TestDirectionsDoNotCollide(t *testing.T) {
	cs := newState(t)
	ad := []byte("ad")
	msg := []byte("same seq, two directions")

	c2s := cs.Encrypt(DirClientToServer, 7, msg, ad)
	s2c := cs.Encrypt(DirServerToClient, 7, msg, ad)
	if bytes.Equal(c2s, s2c) {
		t.Fatal("identical ciphertext across directions: nonce space shared")
	}
	if _, err := cs.Decrypt(DirServerToClient, 7, c2s, ad); err == nil {
		t.Fatal("c2s ciphertext decrypted as s2c: directions not isolated")
	}
}

func TestTamperRejected(t *testing.T) {
	cs := newState(t)
	ct := cs.Encrypt(DirClientToServer, 1, []byte("x"), nil)
	ct[len(ct)-1] ^= 0xFF
	if _, err := cs.Decrypt(DirClientToServer, 1, ct, nil); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
