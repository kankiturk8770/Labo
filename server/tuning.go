package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Defaults match the supplied gateway exactly. Routing and authentication do
// not depend on these operational tuning values.
type Tuning struct {
	ReadHeaderTimeout     time.Duration
	ServerIdleTimeout     time.Duration
	MaxHeaderBytes        int
	TLSMinVersion         uint16
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	UpstreamIdleTimeout   time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
}

func defaultTuning() Tuning {
	return Tuning{10 * time.Second, 120 * time.Second, 64 << 10, tls.VersionTLS12, 256, 64, 90 * time.Second, 10 * time.Second, time.Second}
}

var activeTuning = defaultTuning()

func loadTuning() (Tuning, error) {
	t := defaultTuning()
	for _, field := range []struct {
		name string
		dst  *time.Duration
	}{
		{"EDGE_READ_HEADER_TIMEOUT", &t.ReadHeaderTimeout},
		{"EDGE_SERVER_IDLE_TIMEOUT", &t.ServerIdleTimeout},
		{"EDGE_UPSTREAM_IDLE_TIMEOUT", &t.UpstreamIdleTimeout},
		{"EDGE_TLS_HANDSHAKE_TIMEOUT", &t.TLSHandshakeTimeout},
		{"EDGE_EXPECT_CONTINUE_TIMEOUT", &t.ExpectContinueTimeout},
	} {
		v, e := durationEnv(field.name, *field.dst)
		if e != nil {
			return t, e
		}
		*field.dst = v
	}
	for _, field := range []struct {
		name     string
		dst      *int
		min, max int
	}{
		{"EDGE_MAX_HEADER_BYTES", &t.MaxHeaderBytes, 1024, 16777216},
		{"EDGE_MAX_IDLE_CONNS", &t.MaxIdleConns, 1, 1000000},
		{"EDGE_MAX_IDLE_CONNS_PER_HOST", &t.MaxIdleConnsPerHost, 1, 1000000},
	} {
		if raw := os.Getenv(field.name); raw != "" {
			v, e := strconv.Atoi(raw)
			if e != nil || v < field.min || v > field.max {
				return t, fmt.Errorf("%s must be between %d and %d", field.name, field.min, field.max)
			}
			*field.dst = v
		}
	}
	switch envOrDefault("EDGE_TLS_MIN_VERSION", "1.2") {
	case "1.2":
		t.TLSMinVersion = tls.VersionTLS12
	case "1.3":
		t.TLSMinVersion = tls.VersionTLS13
	default:
		return t, fmt.Errorf("EDGE_TLS_MIN_VERSION must be 1.2 or 1.3")
	}
	return t, nil
}
