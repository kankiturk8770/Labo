// microtun is a small, low-latency TUN-over-UDP VPN for games: 28 bytes per
// packet (WireGuard 32), an X25519+PSK handshake with forward secrecy, a hidden
// header, and optional duplicate sending of small packets against loss.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const version = "2.0.0"

func usage() {
	fmt.Fprintf(os.Stderr, `microtun %s

  microtun server -c server.json
  microtun client -c client.json
  microtun client -url 'mtun://KEY@HOST:PORT?obfs=…&ip=…' [-route-all=false]
  microtun gen -endpoint SERVER_IP:51820 [-clients 1] [-out .]
  microtun genkey
`, version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "server", "client":
		fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		path := fs.String("c", os.Args[1]+".json", "config file")
		link := fs.String("url", "", "client: an mtun:// link from the Kanki panel instead of -c")
		routeAll := fs.Bool("route-all", true, "client with -url: send all IPv4 traffic through the tunnel")
		_ = fs.Parse(os.Args[2:])
		if *link != "" {
			cfg, err := parseURL(*link)
			if err != nil {
				log.Fatal(err)
			}
			cfg.RouteAll = *routeAll
			runClient(cfg)
			return
		}
		runMode(os.Args[1], *path)
	case "gen":
		gen(os.Args[2:])
	case "genkey":
		fmt.Println(newKey())
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		usage()
	}
}

func runClient(cfg *clientConfig) {
	c, err := newClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	runWith(c.run)
}

func runMode(mode, path string) {
	var runner func(*cleanup) error
	if mode == "server" {
		var cfg serverConfig
		if err := loadJSON(path, &cfg); err != nil {
			log.Fatal(err)
		}
		s, err := newServer(&cfg)
		if err != nil {
			log.Fatal(err)
		}
		runner = s.run
	} else {
		var cfg clientConfig
		if err := loadJSON(path, &cfg); err != nil {
			log.Fatal(err)
		}
		c, err := newClient(&cfg)
		if err != nil {
			log.Fatal(err)
		}
		runner = c.run
	}
	runWith(runner)
}

func runWith(runner func(*cleanup) error) {
	var undo cleanup
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	errc := make(chan error, 1)
	go func() { errc <- runner(&undo) }()
	select {
	case err := <-errc:
		undo.run()
		log.Fatal(err)
	case s := <-sig:
		log.Printf("%s, exiting", s)
		undo.run()
	}
}

func newKey() string {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(k)
}

// gen writes a ready server.json plus one client-N.json per client.
func gen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "server public IP:port, as clients will dial it")
	clients := fs.Int("clients", 1, "number of client configs")
	subnet := fs.String("subnet", "10.66.66.0/24", "tunnel subnet (server takes .1)")
	out := fs.String("out", ".", "output directory")
	burst := fs.Int("burst-max", 300, "duplicate IP packets up to this size; 0 = off")
	_ = fs.Parse(args)
	if *endpoint == "" {
		log.Fatal("-endpoint is required, for example -endpoint 203.0.113.10:51820")
	}
	ap, err := netip.ParseAddrPort(*endpoint)
	if err != nil {
		log.Fatalf("-endpoint: %v", err)
	}
	pfx, err := netip.ParsePrefix(*subnet)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() > 30 {
		log.Fatal("-subnet must be an IPv4 prefix of /30 or larger")
	}
	pfx = pfx.Masked()
	base := common{
		ObfsKey:    newKey(),
		Tun:        "mgt0",
		MTU:        1420,
		BurstMax:   *burst,
		BurstDelay: duration(2 * time.Millisecond),
	}
	srvIP := pfx.Addr().Next()
	srv := serverConfig{common: base, Listen: fmt.Sprintf(":%d", ap.Port()), NAT: true}
	srv.Address = netip.PrefixFrom(srvIP, pfx.Bits()).String()
	ip := srvIP
	for i := 1; i <= *clients; i++ {
		ip = ip.Next()
		if !pfx.Contains(ip) {
			log.Fatal("subnet too small for that many clients")
		}
		name := fmt.Sprintf("client%d", i)
		key := newKey()
		srv.Peers = append(srv.Peers, peerConfig{Name: name, Key: key, IP: ip.String()})
		cc := clientConfig{common: base, Server: ap.String(), Key: key,
			Keepalive: duration(10 * time.Second), RouteAll: true, DNS: "1.1.1.1"}
		cc.Address = netip.PrefixFrom(ip, pfx.Bits()).String()
		writeJSON(filepath.Join(*out, name+".json"), cc)
	}
	writeJSON(filepath.Join(*out, "server.json"), srv)
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", path)
}
