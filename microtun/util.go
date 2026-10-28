package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

func beUint32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

func ipSrc(p []byte) (netip.Addr, bool) {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(p[12:16])), true
	case len(p) >= 40 && p[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(p[8:24])), true
	}
	return netip.Addr{}, false
}

func ipDst(p []byte) (netip.Addr, bool) {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(p[16:20])), true
	case len(p) >= 40 && p[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(p[24:40])), true
	}
	return netip.Addr{}, false
}

// burster sends each datagram and, for small IP packets, the exact same
// datagram again after delay. The receiver's replay window drops whichever
// copy arrives second, so one lost copy costs nothing. Large packets (bulk
// TCP) are sent once so downloads do not double.
type burster struct {
	max   int
	delay time.Duration
	conn  *net.UDPConn
}

func (b *burster) send(pkt []byte, ipLen int, to netip.AddrPort) {
	_, _ = b.conn.WriteToUDPAddrPort(pkt, to)
	if b.max <= 0 || ipLen > b.max {
		return
	}
	if b.delay == 0 {
		_, _ = b.conn.WriteToUDPAddrPort(pkt, to)
		return
	}
	dup := append([]byte(nil), pkt...)
	time.AfterFunc(b.delay, func() { _, _ = b.conn.WriteToUDPAddrPort(dup, to) })
}
