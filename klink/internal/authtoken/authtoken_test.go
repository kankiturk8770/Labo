package authtoken

import (
	"testing"
	"time"
)

func TestMakeVerifyRoundTrip(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	tok := Make(key)
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32", len(tok))
	}
	if !Verify(key, tok, time.Now()) {
		t.Fatal("freshly made token did not verify")
	}
}

func TestTokensAreUnique(t *testing.T) {
	var key [32]byte
	a := Make(key)
	b := Make(key)
	if ReplayKey(a) == ReplayKey(b) {
		t.Fatal("two tokens shared a replay key; nonce not random")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	var key, other [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(other[:], []byte("ffffffffffffffffffffffffffffffff"))
	if Verify(other, Make(key), time.Now()) {
		t.Fatal("token verified under the wrong key")
	}
}

func TestVerifyRejectsOutOfWindow(t *testing.T) {
	var key [32]byte
	tok := Make(key)
	if Verify(key, tok, time.Now().Add(Window+time.Minute)) {
		t.Fatal("stale token verified outside the window")
	}
}

func TestVerifyRejectsTamperAndBadLength(t *testing.T) {
	var key [32]byte
	tok := Make(key)
	tok[20] ^= 0xFF
	if Verify(key, tok, time.Now()) {
		t.Fatal("tampered token verified")
	}
	if Verify(key, make([]byte, 31), time.Now()) {
		t.Fatal("31-byte session id accepted")
	}
}
