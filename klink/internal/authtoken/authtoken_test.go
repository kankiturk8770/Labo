package authtoken

import (
	"testing"
	"time"
)

func TestMakeVerifyRoundTrip(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	now := time.Unix(1_700_000_000, 0)

	tok := Make(key, now.Unix())
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32", len(tok))
	}
	if !Verify(key, tok, now) {
		t.Fatal("freshly made token did not verify")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	var key, other [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(other[:], []byte("ffffffffffffffffffffffffffffffff"))
	now := time.Unix(1_700_000_000, 0)
	if Verify(other, Make(key, now.Unix()), now) {
		t.Fatal("token verified under the wrong key")
	}
}

func TestVerifyRejectsOutOfWindow(t *testing.T) {
	var key [32]byte
	now := time.Unix(1_700_000_000, 0)
	tok := Make(key, now.Unix())
	if Verify(key, tok, now.Add(Window+time.Second)) {
		t.Fatal("stale token verified outside the window")
	}
	if !Verify(key, tok, now.Add(Window-time.Second)) {
		t.Fatal("in-window token failed to verify")
	}
}

func TestVerifyRejectsTamperAndBadLength(t *testing.T) {
	var key [32]byte
	now := time.Unix(1_700_000_000, 0)
	tok := Make(key, now.Unix())
	tok[20] ^= 0xFF
	if Verify(key, tok, now) {
		t.Fatal("tampered token verified")
	}
	if Verify(key, make([]byte, 31), now) {
		t.Fatal("31-byte session id accepted")
	}
}
