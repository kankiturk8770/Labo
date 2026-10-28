package main

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// parseURL reads an mtun:// link as the Kanki panel makes it:
// mtun://KEY@host:port?obfs=HEX&ip=10.77.0.2/16&mtu=1420&burst=300&delay=2#name
func parseURL(s string) (*clientConfig, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "mtun" || u.User == nil || u.Host == "" {
		return nil, fmt.Errorf("not an mtun:// link")
	}
	q := u.Query()
	num := func(k string, def int) int {
		if v, err := strconv.Atoi(q.Get(k)); err == nil {
			return v
		}
		return def
	}
	c := &clientConfig{
		Server:    u.Host,
		Key:       u.User.Username(),
		Keepalive: duration(10 * time.Second),
		DNS:       "1.1.1.1",
	}
	c.ObfsKey = q.Get("obfs")
	c.Address = q.Get("ip")
	c.MTU = num("mtu", 1420)
	c.BurstMax = num("burst", 300)
	c.BurstDelay = duration(time.Duration(num("delay", 2)) * time.Millisecond)
	return c, nil
}
