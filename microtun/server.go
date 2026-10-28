package main

import (
	"crypto/cipher"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type peer struct {
	name string
	ip   netip.Addr
	keys *pskKeys

	endpoint atomic.Pointer[netip.AddrPort]
	current  atomic.Pointer[session] // used for sending

	mu      sync.Mutex // guards the fields below and session table changes
	lastTS  uint64     // newest accepted init timestamp: older inits are replays
	prev    *session
	pending *session // answered but not yet confirmed by a data packet
}

type server struct {
	cfg   *serverConfig
	obfs  cipher.Block
	tun   *os.File
	conn  *net.UDPConn
	burst burster
	peers []*peer
	byIP  map[netip.Addr]*peer

	mu       sync.RWMutex
	sessions map[uint32]*session
}

func newServer(cfg *serverConfig) (*server, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	obfsKey, err := decodeKey("obfs_key", cfg.ObfsKey)
	if err != nil {
		return nil, err
	}
	s := &server{cfg: cfg, byIP: map[netip.Addr]*peer{}, sessions: map[uint32]*session{}}
	if s.obfs, err = newBlock(obfsKey); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, pc := range cfg.Peers {
		psk, err := decodeKey("peer "+pc.Name+" key", pc.Key)
		if err != nil {
			return nil, err
		}
		if seen[pc.Key] {
			return nil, fmt.Errorf("peer %s: key is used twice", pc.Name)
		}
		seen[pc.Key] = true
		ip, err := netip.ParseAddr(pc.IP)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("peer %s: ip must be an IPv4 address", pc.Name)
		}
		if s.byIP[ip] != nil {
			return nil, fmt.Errorf("peer %s: ip %s is used twice", pc.Name, ip)
		}
		p := &peer{name: pc.Name, ip: ip}
		if p.keys, err = newPSKKeys(psk); err != nil {
			return nil, err
		}
		s.peers = append(s.peers, p)
		s.byIP[ip] = p
	}
	if len(s.peers) == 0 {
		return nil, fmt.Errorf("no peers configured")
	}
	return s, nil
}

func (s *server) run(undo *cleanup) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	if s.conn, err = net.ListenUDP("udp", addr); err != nil {
		return err
	}
	_ = s.conn.SetReadBuffer(4 << 20)
	_ = s.conn.SetWriteBuffer(4 << 20)
	if s.tun, err = openTUN(s.cfg.Tun); err != nil {
		return err
	}
	if err := setupLink(s.cfg.Tun, s.cfg.Address, s.cfg.MTU); err != nil {
		return err
	}
	if s.cfg.NAT {
		if err := setupNAT(s.cfg.Tun, s.cfg.Address, undo); err != nil {
			return err
		}
	}
	s.burst = burster{max: s.cfg.BurstMax, delay: time.Duration(s.cfg.BurstDelay), conn: s.conn}
	log.Printf("server listening on %s, %s %s, %d peers, %d bytes overhead, burst<=%d",
		s.conn.LocalAddr(), s.cfg.Tun, s.cfg.Address, len(s.peers), overhead, s.cfg.BurstMax)

	go s.janitor()
	errc := make(chan error, 2)
	go func() { errc <- s.tunLoop() }()
	go func() { errc <- s.udpLoop() }()
	return <-errc
}

func (s *server) tunLoop() error {
	buf := make([]byte, hdrLen+maxIP+tagLen)
	for {
		n, err := s.tun.Read(buf[hdrLen : hdrLen+maxIP])
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		dst, ok := ipDst(buf[hdrLen : hdrLen+n])
		if !ok {
			continue
		}
		p := s.byIP[dst]
		if p == nil {
			continue
		}
		sess, ep := p.current.Load(), p.endpoint.Load()
		if sess == nil || ep == nil {
			continue
		}
		if pkt := sess.seal(s.obfs, buf, n); pkt != nil {
			s.burst.send(pkt, n, *ep)
		}
	}
}

func (s *server) udpLoop() error {
	buf := make([]byte, maxIP+hdrLen+tagLen)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return fmt.Errorf("udp read: %w", err)
		}
		if n < overhead {
			continue
		}
		pkt := buf[:n]
		mask(s.obfs, pkt)
		idx := beUint32(pkt)
		if idx == 0 {
			s.handleInit(pkt, from)
			continue
		}
		s.mu.RLock()
		sess := s.sessions[idx]
		s.mu.RUnlock()
		if sess == nil {
			continue
		}
		pt, ok := sess.open(pkt)
		if !ok {
			continue
		}
		p := sess.peer
		if p.current.Load() != sess {
			s.confirm(p, sess)
		}
		if ep := p.endpoint.Load(); ep == nil || *ep != from {
			p.endpoint.Store(&from)
			log.Printf("peer %s at %s", p.name, from)
		}
		if len(pt) == 0 {
			s.keepalive(p) // answer so the client can tell a dead server from a quiet one
			continue
		}
		if src, ok := ipSrc(pt); !ok || src != p.ip {
			continue // a client may only send from its own tunnel address
		}
		if _, err := s.tun.Write(pt); err != nil {
			return fmt.Errorf("tun write: %w", err)
		}
	}
}

func (s *server) keepalive(p *peer) {
	sess, ep := p.current.Load(), p.endpoint.Load()
	if sess == nil || ep == nil {
		return
	}
	buf := make([]byte, overhead)
	if pkt := sess.seal(s.obfs, buf, 0); pkt != nil {
		_, _ = s.conn.WriteToUDPAddrPort(pkt, *ep)
	}
}

func (s *server) handleInit(pkt []byte, from netip.AddrPort) {
	var p *peer
	var m initMsg
	for _, c := range s.peers {
		if mm, ok := parseInit(c.keys, pkt); ok {
			p, m = c, mm
			break
		}
	}
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if m.ts <= p.lastTS {
		return // replayed or stale init
	}
	eph, err := newEphemeral()
	if err != nil {
		return
	}
	shared, err := dh(eph, m.eph)
	if err != nil {
		return
	}
	p.lastTS = m.ts

	s.mu.Lock()
	idx := randIdx()
	for s.sessions[idx] != nil {
		idx = randIdx()
	}
	c2s, s2c, err := deriveKeys(shared, p.keys.psk, m.eph, eph.PublicKey().Bytes(), m.idx, idx)
	var sess *session
	if err == nil {
		sess, err = newSession(idx, m.idx, s2c, c2s)
	}
	if err != nil {
		s.mu.Unlock()
		return
	}
	sess.peer = p
	if p.pending != nil {
		delete(s.sessions, p.pending.localIdx)
	}
	p.pending = sess
	s.sessions[idx] = sess
	s.mu.Unlock()

	resp := buildResp(s.obfs, p.keys, respMsg{eph: eph.PublicKey().Bytes(), serverIdx: idx, clientIdx: m.idx}, m.eph, len(pkt))
	_, _ = s.conn.WriteToUDPAddrPort(resp, from)
}

// confirm makes a pending session current once the client has proved it holds
// its keys by sending data with it. A replayed init therefore never displaces
// a working session.
func (s *server) confirm(p *peer, sess *session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending != sess {
		return // data on the previous session: nothing to do
	}
	s.mu.Lock()
	if p.prev != nil {
		delete(s.sessions, p.prev.localIdx)
	}
	s.mu.Unlock()
	if p.current.Load() == nil {
		log.Printf("peer %s connected", p.name)
	}
	p.prev = p.current.Load()
	p.current.Store(sess)
	p.pending = nil
}

func (s *server) janitor() {
	for range time.Tick(5 * time.Second) {
		now := time.Now()
		for _, p := range s.peers {
			p.mu.Lock()
			s.mu.Lock()
			if p.prev != nil && p.prev.expired(now) {
				delete(s.sessions, p.prev.localIdx)
				p.prev = nil
			}
			if p.pending != nil && now.Sub(p.pending.born) > 2*handshakeRetry {
				delete(s.sessions, p.pending.localIdx)
				p.pending = nil
			}
			if cur := p.current.Load(); cur != nil && cur.expired(now) {
				delete(s.sessions, cur.localIdx)
				p.current.Store(nil)
				log.Printf("peer %s idle, session closed", p.name)
			}
			s.mu.Unlock()
			p.mu.Unlock()
		}
	}
}
