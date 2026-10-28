package main

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func testKeys(t *testing.T) (*pskKeys, *pskKeys) {
	psk := make([]byte, 32)
	rand.Read(psk)
	a, err := newPSKKeys(psk)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newPSKKeys(psk)
	return a, b
}

func testObfs(t *testing.T) []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

// handshake runs init/resp through the wire format and returns both sessions.
func handshake(t *testing.T) (cs, ss *session, obfsKey []byte) {
	obfsKey = testObfs(t)
	obfs, _ := newBlock(obfsKey)
	ck, sk := testKeys(t)

	ce, _ := newEphemeral()
	init := buildInit(obfs, ck, initMsg{eph: ce.PublicKey().Bytes(), ts: 1, idx: 7})
	mask(obfs, init)
	if beUint32(init) != 0 {
		t.Fatal("init idx not 0")
	}
	m, ok := parseInit(sk, init)
	if !ok || m.idx != 7 || m.ts != 1 {
		t.Fatal("parseInit failed")
	}
	se, _ := newEphemeral()
	resp := buildResp(obfs, sk, respMsg{eph: se.PublicKey().Bytes(), serverIdx: 9, clientIdx: m.idx}, m.eph, len(init))
	if len(resp) > len(init) {
		t.Fatalf("response %d larger than init %d", len(resp), len(init))
	}
	mask(obfs, resp)
	r, ok := parseResp(ck, resp, ce.PublicKey().Bytes())
	if !ok || r.serverIdx != 9 || r.clientIdx != 7 {
		t.Fatal("parseResp failed")
	}
	other, _ := newEphemeral()
	if _, ok := parseResp(ck, resp, other.PublicKey().Bytes()); ok {
		t.Fatal("response accepted for another init")
	}

	shS, _ := dh(se, m.eph)
	shC, _ := dh(ce, r.eph)
	c2s, s2c, _ := deriveKeys(shS, sk.psk, m.eph, se.PublicKey().Bytes(), m.idx, 9)
	ss, _ = newSession(9, m.idx, s2c, c2s)
	c2s, s2c, _ = deriveKeys(shC, ck.psk, ce.PublicKey().Bytes(), r.eph, 7, r.serverIdx)
	cs, _ = newSession(7, r.serverIdx, c2s, s2c)
	return
}

func TestDataRoundTrip(t *testing.T) {
	cs, ss, obfsKey := handshake(t)
	obfs, _ := newBlock(obfsKey)
	payload := []byte("game packet payload")
	buf := make([]byte, hdrLen+len(payload)+tagLen)
	copy(buf[hdrLen:], payload)
	pkt := cs.seal(obfs, buf, len(payload))
	if len(pkt) != len(payload)+overhead || overhead != 28 {
		t.Fatalf("overhead %d", len(pkt)-len(payload))
	}
	wire := append([]byte(nil), pkt...)

	recv := func() ([]byte, bool) {
		p := append([]byte(nil), wire...)
		mask(obfs, p)
		if beUint32(p) != ss.localIdx {
			t.Fatal("wrong idx after unmask")
		}
		return ss.open(p)
	}
	pt, ok := recv()
	if !ok || !bytes.Equal(pt, payload) {
		t.Fatal("open failed")
	}
	if _, ok := recv(); ok {
		t.Fatal("duplicate accepted")
	}
	wire[len(wire)-1] ^= 1
	if _, ok := recv(); ok {
		t.Fatal("tampered packet accepted")
	}

	// Server to client direction uses the other key.
	buf = make([]byte, overhead)
	back := ss.seal(obfs, buf, 0)
	mask(obfs, back)
	if pt, ok := cs.open(back); !ok || len(pt) != 0 {
		t.Fatal("keepalive failed")
	}
}

func TestHeaderHidden(t *testing.T) {
	cs, _, obfsKey := handshake(t)
	obfs, _ := newBlock(obfsKey)
	var first []byte
	for i := 0; i < 2; i++ {
		buf := make([]byte, hdrLen+1+tagLen)
		pkt := cs.seal(obfs, buf, 1)
		if first == nil {
			first = pkt
		} else if bytes.Equal(first[:4], pkt[:4]) {
			t.Fatal("idx visible on the wire")
		}
	}
}

func TestWrongPSK(t *testing.T) {
	obfs, _ := newBlock(testObfs(t))
	ck, _ := testKeys(t)
	other, _ := testKeys(t)
	ce, _ := newEphemeral()
	init := buildInit(obfs, ck, initMsg{eph: ce.PublicKey().Bytes(), ts: 1, idx: 7})
	mask(obfs, init)
	if _, ok := parseInit(other, init); ok {
		t.Fatal("init accepted with wrong psk")
	}
}

func TestReplayWindow(t *testing.T) {
	var r replayWindow
	for _, c := range []uint64{0, 1, 2, 5, 4, 3} {
		if !r.accept(c) {
			t.Fatalf("rejected fresh %d", c)
		}
	}
	for _, c := range []uint64{0, 3, 5} {
		if r.accept(c) {
			t.Fatalf("accepted duplicate %d", c)
		}
	}
	if !r.accept(5 + windowBits - 1) {
		t.Fatal("jump rejected")
	}
	if r.accept(5) {
		t.Fatal("5 accepted after window moved")
	}
	if !r.accept(6) || r.accept(6) {
		t.Fatal("6 in window should be accepted once")
	}
	if !r.accept(100000) || r.accept(100000-windowBits) {
		t.Fatal("far jump")
	}
	if !r.accept(100000 - windowBits + 1) {
		t.Fatal("oldest in-window counter rejected")
	}
}

func TestParseURL(t *testing.T) {
	k := "ab"
	for len(k) < 64 {
		k += "ab"
	}
	c, err := parseURL("mtun://" + k + "@de.example.com:4200?obfs=" + k + "&ip=10.77.0.2/16&mtu=1400&burst=200&delay=3#Germany%20%C2%B7%20microtun")
	if err != nil || c.Server != "de.example.com:4200" || c.Key != k || c.ObfsKey != k || c.Address != "10.77.0.2/16" || c.MTU != 1400 || c.BurstMax != 200 || c.BurstDelay != duration(3*time.Millisecond) {
		t.Fatalf("%+v %v", c, err)
	}
}
