// Package klinkmobile is the gomobile entry point for the Android app. It is
// bound to a .aar with `gomobile bind` and exposes a tiny API the Kotlin
// VpnService calls: Start takes the VPN TUN file descriptor and a profile,
// runs the KLINK SOCKS core (genuine Chrome TLS fingerprint, shared with the
// desktop client) plus an in-process tun2socks that routes every packet from
// the TUN through it; Stop tears both down.
//
// All device traffic — TCP, UDP and DNS — is captured by the VpnService TUN
// and handed to tun2socks, so nothing bypasses the tunnel. The app excludes
// only its own UID from the VPN (addDisallowedApplication), so the client's
// own upstream sockets to the server are the single intended exception and do
// not loop back through the tunnel.
package klinkmobile

import (
	"errors"
	"sync"

	"klink/internal/klinkclient"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const localSocks = "127.0.0.1:7390"

var (
	mu      sync.Mutex
	current *klinkclient.Client
	running bool
)

// Start brings up the tunnel. Provide either subURL (a panel subscription
// link) or the manual fields (serverAddr/sessionHex/masterHex/sni). tunFd is
// the file descriptor from VpnService.establish().
func Start(tunFd int, subURL, serverAddr, sessionHex, masterHex, sni string) error {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return errors.New("already running")
	}

	cfg := klinkclient.Config{
		ServerAddr: serverAddr,
		SessionHex: sessionHex,
		MasterHex:  masterHex,
		SNI:        sni,
		PaddingMax: 64,
	}
	if subURL != "" {
		resolved, err := klinkclient.ResolveFromSub(subURL)
		if err != nil {
			return err
		}
		cfg = resolved
	}

	client, err := klinkclient.New(cfg)
	if err != nil {
		return err
	}
	go func() { _ = client.ListenAndServe(localSocks) }()

	key := &engine.Key{
		Device:   "fd://" + itoa(tunFd),
		Proxy:    "socks5://" + localSocks,
		LogLevel: "warning",
		MTU:      1500,
	}
	engine.Insert(key)
	engine.Start()

	current = client
	running = true
	return nil
}

// Stop tears down tun2socks and the SOCKS core.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	engine.Stop()
	if current != nil {
		_ = current.Close()
		current = nil
	}
	running = false
}

// IsRunning reports whether the tunnel is active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// itoa avoids importing strconv into the bound surface for one small use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
