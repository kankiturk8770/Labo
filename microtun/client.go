package main

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type client struct {
	cfg   *clientConfig
	obfs  cipher.Block
	keys  *pskKeys
	tun   *os.File
	conn  *net.UDPConn
	burst burster

	server   atomic.Pointer[netip.AddrPort]
	current  atomic.Pointer[session] // used for sending
	previous atomic.Pointer[session] // still accepted until it expires
	lastRecv atomic.Int64            // unix nanos of the last authenticated packet
	lastSend atomic.Int64

	// this run's device id: the panel's server gives each device of a user its own
	// address (and IPv6 when it has it); addr4/addr6 are what the interface has now
	dev          uint64
	addr4, addr6 netip.Addr

	mu       sync.Mutex // guards the handshake in flight
	hsEph    *ecdh.PrivateKey
	hsIdx    uint32
	hsSent   time.Time
	hsFails  int
	lastTS   uint64
	everDone bool
}

func newClient(cfg *clientConfig) (*client, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	obfsKey, err := decodeKey("obfs_key", cfg.ObfsKey)
	if err != nil {
		return nil, err
	}
	psk, err := decodeKey("key", cfg.Key)
	if err != nil {
		return nil, err
	}
	c := &client{cfg: cfg, dev: deviceID(cfg.Device, cfg.Key)}
	if p, err := netip.ParsePrefix(cfg.Address); err == nil {
		c.addr4 = p.Addr()
	}
	if c.obfs, err = newBlock(obfsKey); err != nil {
		return nil, err
	}
	if c.keys, err = newPSKKeys(psk); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *client) resolve() error {
	ua, err := net.ResolveUDPAddr("udp", c.cfg.Server)
	if err != nil {
		return err
	}
	ap := ua.AddrPort()
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	c.server.Store(&ap)
	return nil
}

func (c *client) run(undo *cleanup) error {
	if err := c.resolve(); err != nil {
		return err
	}
	var err error
	// Unconnected socket: ICMP "port unreachable" while the server restarts
	// must not turn into a fatal read error.
	if c.conn, err = net.ListenUDP("udp", nil); err != nil {
		return err
	}
	_ = c.conn.SetReadBuffer(4 << 20)
	_ = c.conn.SetWriteBuffer(4 << 20)
	if c.tun, err = openTUN(c.cfg.Tun); err != nil {
		return err
	}
	if err := setupLink(c.cfg.Tun, c.cfg.Address, c.cfg.MTU); err != nil {
		return err
	}
	if c.cfg.RouteAll {
		if err := setupRouteAll(c.cfg.Tun, c.server.Load().Addr(), c.cfg.DNS, undo); err != nil {
			return err
		}
	}
	c.burst = burster{max: c.cfg.BurstMax, delay: time.Duration(c.cfg.BurstDelay), conn: c.conn}
	log.Printf("client %s -> %s, %s %s, %d bytes overhead, burst<=%d",
		c.conn.LocalAddr(), c.server.Load(), c.cfg.Tun, c.cfg.Address, overhead, c.cfg.BurstMax)

	go c.timers()
	errc := make(chan error, 2)
	go func() { errc <- c.tunLoop() }()
	go func() { errc <- c.udpLoop() }()
	return <-errc
}

func (c *client) tunLoop() error {
	buf := make([]byte, hdrLen+maxIP+tagLen)
	for {
		n, err := c.tun.Read(buf[hdrLen : hdrLen+maxIP])
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		sess := c.current.Load()
		if sess == nil {
			continue // no session yet; the handshake is retried by timers
		}
		if pkt := sess.seal(c.obfs, buf, n); pkt != nil {
			c.burst.send(pkt, n, *c.server.Load())
			c.lastSend.Store(time.Now().UnixNano())
		}
	}
}

func (c *client) udpLoop() error {
	buf := make([]byte, maxIP+hdrLen+tagLen)
	for {
		n, _, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return fmt.Errorf("udp read: %w", err)
		}
		if n < overhead {
			continue
		}
		pkt := buf[:n]
		mask(c.obfs, pkt)
		idx := beUint32(pkt)
		if idx == 0 {
			c.handleResp(pkt)
			continue
		}
		var sess *session
		if s := c.current.Load(); s != nil && s.localIdx == idx {
			sess = s
		} else if s := c.previous.Load(); s != nil && s.localIdx == idx {
			sess = s
		} else {
			continue
		}
		pt, ok := sess.open(pkt)
		if !ok {
			continue
		}
		c.lastRecv.Store(time.Now().UnixNano())
		if len(pt) == 0 {
			continue // keepalive
		}
		if _, err := c.tun.Write(pt); err != nil {
			return fmt.Errorf("tun write: %w", err)
		}
	}
}

func (c *client) sendInit() {
	if c.hsFails >= 2 {
		if err := c.resolve(); err != nil {
			log.Printf("resolve %s: %v", c.cfg.Server, err)
		}
	}
	eph, err := newEphemeral()
	if err != nil {
		return
	}
	ts := uint64(time.Now().UnixNano())
	if ts <= c.lastTS {
		ts = c.lastTS + 1
	}
	c.lastTS = ts
	c.hsEph, c.hsIdx, c.hsSent = eph, randIdx(), time.Now()
	pkt := buildInit(c.obfs, c.keys, initMsg{eph: eph.PublicKey().Bytes(), ts: ts, idx: c.hsIdx, dev: c.dev})
	_, _ = c.conn.WriteToUDPAddrPort(pkt, *c.server.Load())
}

func (c *client) handleResp(pkt []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hsEph == nil {
		return
	}
	ephC := c.hsEph.PublicKey().Bytes()
	m, ok := parseResp(c.keys, pkt, ephC)
	if !ok || m.clientIdx != c.hsIdx {
		return
	}
	shared, err := dh(c.hsEph, m.eph)
	if err != nil {
		return
	}
	c2s, s2c, err := deriveKeys(shared, c.keys.psk, ephC, m.eph, c.hsIdx, m.serverIdx)
	if err != nil {
		return
	}
	sess, err := newSession(c.hsIdx, m.serverIdx, c2s, s2c)
	if err != nil {
		return
	}
	c.hsEph = nil
	c.hsFails = 0
	c.previous.Store(c.current.Load())
	c.current.Store(sess)
	c.lastRecv.Store(time.Now().UnixNano())
	if !c.everDone {
		log.Printf("connected to %s (handshake %s)", c.server.Load(), time.Since(c.hsSent).Round(time.Millisecond))
		c.everDone = true
	}
	if m.v4.IsValid() {
		c.setAddrs(m.v4, m.v6)
	}
	c.sendKeepalive(sess) // confirms the session on the server right away
}

// deviceID is the same on every run of one machine (or for one -device name) and
// never 0 (0 is a v2 client).
func deviceID(name, key string) uint64 {
	if name == "" {
		b, _ := os.ReadFile("/etc/machine-id")
		name = "machine:" + strings.TrimSpace(string(b))
	}
	h := sha256.Sum256([]byte("microtun device|" + key + "|" + name))
	return binary.BigEndian.Uint64(h[:8]) | 1
}

// setAddrs moves the interface to the addresses the server gave this device: the
// link's own address for the first device, another one for a second device.
func (c *client) setAddrs(v4, v6 netip.Addr) {
	tun := c.cfg.Tun
	link, _ := netip.ParsePrefix(c.cfg.Address)
	if v4 != c.addr4 {
		p := netip.PrefixFrom(v4, link.Bits())
		_ = run("ip", "-4", "addr", "flush", "dev", tun)
		if err := run("ip", "addr", "replace", p.String(), "dev", tun); err != nil {
			log.Printf("address %s: %v", v4, err)
			return
		}
		// the tunnel network of the link stays reachable from the new address
		if !p.Masked().Contains(link.Addr()) {
			_ = run("ip", "route", "replace", link.Masked().String(), "dev", tun, "src", v4.String())
		}
		if c.cfg.RouteAll {
			for _, r := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
				_ = run("ip", "route", "replace", r, "dev", tun)
			}
		}
		c.addr4 = v4
		log.Printf("tunnel address %s (given by the server for this device)", p)
	}
	if v6.IsValid() && v6 != c.addr6 {
		if c.addr6.IsValid() {
			_ = run("ip", "-6", "addr", "del", netip.PrefixFrom(c.addr6, 64).String(), "dev", tun)
		}
		if err := run("ip", "-6", "addr", "replace", netip.PrefixFrom(v6, 64).String(), "dev", tun, "nodad"); err != nil {
			log.Printf("IPv6 %s: %v", v6, err)
			return
		}
		if c.cfg.RouteAll {
			for _, r := range []string{"::/1", "8000::/1"} {
				_ = run("ip", "-6", "route", "replace", r, "dev", tun)
			}
		}
		c.addr6 = v6
		log.Printf("tunnel IPv6 %s", v6)
	}
}

func (c *client) sendKeepalive(sess *session) {
	buf := make([]byte, overhead)
	if pkt := sess.seal(c.obfs, buf, 0); pkt != nil {
		_, _ = c.conn.WriteToUDPAddrPort(pkt, *c.server.Load())
		c.lastSend.Store(time.Now().UnixNano())
	}
}

// timers drives handshakes, rekeying, keepalives and dead-server detection.
func (c *client) timers() {
	keepalive := time.Duration(c.cfg.Keepalive)
	for now := time.Now(); ; now = <-time.After(250 * time.Millisecond) {
		cur := c.current.Load()
		if prev := c.previous.Load(); prev != nil && prev.expired(now) {
			c.previous.CompareAndSwap(prev, nil)
		}
		if cur != nil && cur.expired(now) {
			c.current.CompareAndSwap(cur, nil)
			cur = nil
		}

		need := cur == nil || now.Sub(cur.born) >= rekeyAfter
		// We sent something (data or keepalive, which the server answers) and
		// heard nothing back: the server restarted or the path broke. A new
		// handshake is one round trip and keeps the old keys until it succeeds.
		if cur != nil {
			lastRecv := c.lastRecv.Load()
			if c.lastSend.Load() > lastRecv && now.Sub(time.Unix(0, lastRecv)) > deadAfter {
				need = true
			}
		}

		c.mu.Lock()
		if need && (c.hsEph == nil || now.Sub(c.hsSent) >= handshakeRetry) {
			if c.hsEph != nil {
				c.hsFails++
				if c.hsFails == 3 {
					log.Printf("no answer from %s, retrying", c.server.Load())
					c.everDone = false
				}
			}
			c.sendInit()
		}
		c.mu.Unlock()

		if keepalive > 0 && cur != nil && now.Sub(time.Unix(0, c.lastSend.Load())) >= keepalive {
			c.sendKeepalive(cur)
		}
	}
}
