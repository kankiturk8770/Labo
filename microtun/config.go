package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"
)

type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = duration(v)
	return nil
}

func (d duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Fields both sides share.
type common struct {
	ObfsKey    string   `json:"obfs_key"`    // same on the server and all its clients
	Tun        string   `json:"tun"`         // interface name
	Address    string   `json:"address"`     // tunnel address with prefix, 10.66.66.1/24
	MTU        int      `json:"mtu"`         // 1420 fits IPv4 and IPv6 outer paths
	BurstMax   int      `json:"burst_max"`   // send IP packets up to this size twice; 0 = off
	BurstDelay duration `json:"burst_delay"` // delay before the second copy
}

type peerConfig struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	IP   string `json:"ip"` // the client's tunnel IPv4; packets from it must use this source
}

type serverConfig struct {
	common
	Listen string       `json:"listen"`
	NAT    bool         `json:"nat"` // enable forwarding + MASQUERADE for the tunnel subnet
	Peers  []peerConfig `json:"peers"`
}

type clientConfig struct {
	common
	Server    string   `json:"server"`    // host:port
	Key       string   `json:"key"`       // this client's PSK
	Keepalive duration `json:"keepalive"` // 0 = off; also drives dead-server detection
	RouteAll  bool     `json:"route_all"` // send all IPv4 traffic through the tunnel
	DNS       string   `json:"dns"`       // set via resolvectl when route_all is on
}

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func decodeKey(name, s string) ([]byte, error) {
	k, err := hex.DecodeString(s)
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("%s must be 64 hex characters (32 bytes)", name)
	}
	return k, nil
}

func (c *common) check() error {
	if c.Tun == "" {
		c.Tun = "mgt0"
	}
	if len(c.Tun) >= 16 {
		return fmt.Errorf("tun name too long")
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	if c.MTU < 576 || c.MTU > maxIP-overhead {
		return fmt.Errorf("mtu out of range")
	}
	if _, err := netip.ParsePrefix(c.Address); err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if c.BurstMax < 0 || c.BurstDelay < 0 {
		return fmt.Errorf("burst settings cannot be negative")
	}
	return nil
}
