package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
)

type ifreq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

func openTUN(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (run as root, modprobe tun): %w", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNoPI
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	return f, nil
}

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// cleanup collects undo steps for routes/firewall rules we added.
type cleanup []func()

func (c *cleanup) add(f func()) { *c = append(*c, f) }

func (c cleanup) run() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
}

func setupLink(name, addr string, mtu int) error {
	if err := run("ip", "addr", "replace", addr, "dev", name); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up")
}

// setupNAT lets tunnel clients reach the internet through the server.
func setupNAT(tun, addr string, undo *cleanup) error {
	pfx, _ := netip.ParsePrefix(addr)
	subnet := pfx.Masked().String()
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", subnet, "!", "-o", tun, "-j", "MASQUERADE"},
		{"-t", "filter", "FORWARD", "-i", tun, "-j", "ACCEPT"},
		{"-t", "filter", "FORWARD", "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		// Keep TCP segments inside the tunnel MTU for clients without PMTU discovery.
		{"-t", "mangle", "FORWARD", "-o", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	}
	for _, r := range rules {
		table, chain, spec := r[:2], r[2], r[3:]
		cmd := func(op string) []string {
			return append(append(append([]string{"iptables"}, table...), op, chain), spec...)
		}
		if run(cmd("-C")...) == nil {
			continue
		}
		if err := run(cmd("-I")...); err != nil {
			return err
		}
		undo.add(func() { _ = run(cmd("-D")...) })
	}
	return nil
}

// setupRouteAll keeps the server reachable over the old path and sends
// everything else into the tunnel. 0/1 + 128/1 override the default route
// without deleting it, so it comes back when the tunnel goes away.
func setupRouteAll(tun string, server netip.Addr, dns string, undo *cleanup) error {
	fam := "-4"
	if server.Is6() {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", "get", server.String()).Output()
	if err != nil {
		return fmt.Errorf("ip route get %s: %w", server, err)
	}
	f := strings.Fields(string(out))
	route := []string{"ip", fam, "route", "replace", server.String()}
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "via" || f[i] == "dev" {
			route = append(route, f[i], f[i+1])
		}
	}
	if err := run(route...); err != nil {
		return err
	}
	undo.add(func() { _ = run("ip", fam, "route", "del", server.String()) })
	for _, r := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "replace", r, "dev", tun); err != nil {
			return err
		}
	}
	if dns != "" {
		if _, err := exec.LookPath("resolvectl"); err != nil {
			log.Printf("dns: resolvectl not found; set %s as resolver yourself", dns)
		} else if err := errors.Join(run("resolvectl", "dns", tun, dns), run("resolvectl", "domain", tun, "~.")); err != nil {
			log.Printf("dns: %v", err)
		}
	}
	return nil
}
