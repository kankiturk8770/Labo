package main

import (
	"flag"
	"log"

	"klink/internal/klinkclient"
)

func main() {
	subURL := flag.String("sub", "", "Subscription URL from KLINK Panel (auto-syncs SNI & keys)")
	serverAddr := flag.String("server", "127.0.0.1:443", "KLINK Server Address (Edge IP or Foreign IP)")
	sessionHex := flag.String("session", "", "16-byte Session ID in hex")
	masterHex := flag.String("key", "", "32-byte Master Key in hex")
	sniDomain := flag.String("sni", "www.aparat.com", "Domestic SNI domain to mimic")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 listen address")
	flag.Parse()

	cfg := klinkclient.Config{
		ServerAddr: *serverAddr,
		SessionHex: *sessionHex,
		MasterHex:  *masterHex,
		SNI:        *sniDomain,
		PaddingMax: 64,
	}

	// A subscription link overrides the manual flags with live panel settings.
	if *subURL != "" {
		resolved, err := klinkclient.ResolveFromSub(*subURL)
		if err != nil {
			log.Fatalf("[KLINK-CLIENT] subscription error: %v", err)
		}
		cfg = resolved
		log.Printf("[KLINK-CLIENT] Synced from Panel -> Masquerade: %s | Server: %s", cfg.SNI, cfg.ServerAddr)
	}

	if cfg.SessionHex == "" || cfg.MasterHex == "" {
		log.Println("[KLINK-CLIENT] Usage: klink-client -sub https://SERVER:8443/sub/TOKEN -socks 127.0.0.1:1080")
		return
	}

	client, err := klinkclient.New(cfg)
	if err != nil {
		log.Fatalf("[KLINK-CLIENT] init error: %v", err)
	}
	log.Printf("[KLINK-CLIENT] Local SOCKS5 on %s -> Pipe to %s (SNI: %s)", *socksAddr, cfg.ServerAddr, cfg.SNI)
	if err := client.ListenAndServe(*socksAddr); err != nil {
		log.Fatalf("[KLINK-CLIENT] serve error: %v", err)
	}
}
