package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestServerInitReplay(t *testing.T) {
	obfsKey, psk := newKey(), newKey()
	s, err := newServer(&serverConfig{
		common: common{ObfsKey: obfsKey, Address: "10.66.66.1/24"},
		Peers:  []peerConfig{{Name: "a", Key: psk, IP: "10.66.66.2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	defer s.conn.Close()
	from := netip.MustParseAddrPort("127.0.0.1:9")
	p := s.peers[0]

	eph, _ := newEphemeral()
	init := buildInit(s.obfs, p.keys, initMsg{eph: eph.PublicKey().Bytes(), ts: 100, idx: 5})
	mask(s.obfs, init)
	s.handleInit(append([]byte(nil), init...), from)
	first := p.pending
	if first == nil || p.current.Load() != nil {
		t.Fatal("init should create a pending, unconfirmed session")
	}
	s.handleInit(append([]byte(nil), init...), from)
	if p.pending != first || len(s.sessions) != 1 {
		t.Fatal("replayed init was accepted")
	}

	// Data under the pending session confirms it.
	buf := make([]byte, overhead)
	c := &session{remoteIdx: first.localIdx, send: first.recv, born: time.Now()}
	pkt := c.seal(s.obfs, buf, 0)
	mask(s.obfs, pkt)
	sess := s.sessions[beUint32(pkt)]
	if _, ok := sess.open(pkt); !ok {
		t.Fatal("data did not open")
	}
	s.confirm(p, sess)
	if p.current.Load() != first || p.pending != nil {
		t.Fatal("session not confirmed")
	}
}
