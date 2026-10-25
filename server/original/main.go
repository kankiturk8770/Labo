package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	signatureHeader = "X-Signature"
	timestampHeader = "X-Signature-Timestamp"
)

// Config contains validated process configuration.
type Config struct {
	ListenAddress    string
	CertificateFile  string
	PrivateKeyFile   string
	HMACSecret       []byte
	DecoyOrigin      *url.URL
	InternalBackends []*url.URL
	SignatureMaxSkew time.Duration
	ShutdownTimeout  time.Duration
}

// Gateway routes valid requests to the internal pool. All other requests
// follow the same decoy-proxy path without revealing validation failures.
type Gateway struct {
	validator *SignatureValidator
	internal  *BackendPool
	decoy     *httputil.ReverseProxy
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g.validator.Valid(r) {
		g.internal.ServeHTTP(w, r)
		return
	}

	g.decoy.ServeHTTP(w, r)
}

// SignatureValidator authenticates this canonical byte sequence:
//
//	Unix timestamp + "\n" +
//	HTTP method + "\n" +
//	Request URI + "\n" +
//	Sec-WebSocket-Key
//
// X-Signature contains the hexadecimal HMAC-SHA-256 result. For ordinary
// HTTP requests, Sec-WebSocket-Key is normally empty.
type SignatureValidator struct {
	secret  []byte
	maxSkew time.Duration
	now     func() time.Time
}

func (v *SignatureValidator) Valid(r *http.Request) bool {
	timestampText := strings.TrimSpace(r.Header.Get(timestampHeader))
	signatureText := strings.TrimSpace(r.Header.Get(signatureHeader))

	if timestampText == "" || signatureText == "" {
		return false
	}

	// Accept both "<hex>" and "sha256=<hex>".
	signatureText = strings.TrimPrefix(signatureText, "sha256=")

	providedMAC, err := hex.DecodeString(signatureText)
	if err != nil || len(providedMAC) != sha256.Size {
		return false
	}

	unixTimestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil {
		return false
	}

	delta := v.now().Sub(time.Unix(unixTimestamp, 0))
	if delta < 0 {
		delta = -delta
	}

	if delta > v.maxSkew {
		return false
	}

	canonical := timestampText + "\n" +
		r.Method + "\n" +
		r.URL.RequestURI() + "\n" +
		r.Header.Get("Sec-WebSocket-Key")

	mac := hmac.New(sha256.New, v.secret)
	_, _ = mac.Write([]byte(canonical))
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(providedMAC, expectedMAC)
}

// BackendPool performs lock-free round-robin selection. Each backend owns a
// separate ReverseProxy, so concurrent requests never share mutable targets.
type BackendPool struct {
	proxies []*httputil.ReverseProxy
	next    atomic.Uint64
}

func NewBackendPool(
	backends []*url.URL,
	transport http.RoundTripper,
) (*BackendPool, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("internal backend pool is empty")
	}

	pool := &BackendPool{
		proxies: make([]*httputil.ReverseProxy, 0, len(backends)),
	}

	for _, backend := range backends {
		pool.proxies = append(
			pool.proxies,
			newReverseProxy(backend, transport, false),
		)
	}

	return pool, nil
}

func (p *BackendPool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	index := (p.next.Add(1) - 1) % uint64(len(p.proxies))
	p.proxies[index].ServeHTTP(w, r)
}

// newReverseProxy creates an origin-specific proxy. It preserves the request
// method, path, query, body, WebSocket upgrade headers, and end-to-end headers.
func newReverseProxy(
	target *url.URL,
	transport http.RoundTripper,
	decoy bool,
) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director

	proxy.Director = func(out *http.Request) {
		originalHost := out.Host

		baseDirector(out)

		// Select the upstream virtual host. This is required by most public
		// origins and is independent of the gateway's incoming Host header.
		out.Host = target.Host

		// Never forward gateway authentication material upstream.
		out.Header.Del(signatureHeader)
		out.Header.Del(timestampHeader)

		// Discard untrusted forwarding metadata supplied by the client.
		out.Header.Del("Forwarded")
		out.Header.Del("X-Forwarded-Host")
		out.Header.Del("X-Forwarded-Proto")

		if decoy {
			// A nil X-Forwarded-For entry tells ReverseProxy not to append
			// the client address. Client and edge topology are not disclosed.
			out.Header["X-Forwarded-For"] = nil
			return
		}

		// For internal services, delete spoofed X-Forwarded-For and allow
		// ReverseProxy to construct it from the actual peer address.
		out.Header.Del("X-Forwarded-For")
		out.Header.Set("X-Forwarded-Host", originalHost)
		out.Header.Set("X-Forwarded-Proto", "https")
	}

	proxy.Transport = transport

	// Deliberately no ModifyResponse: response bodies and end-to-end headers
	// are not rewritten by application code.
	proxy.ErrorHandler = func(
		w http.ResponseWriter,
		r *http.Request,
		err error,
	) {
		log.Printf(
			"upstream proxy error: target=%s method=%s path=%s err=%v",
			target.Host,
			r.Method,
			r.URL.Path,
			err,
		)

		http.Error(
			w,
			http.StatusText(http.StatusBadGateway),
			http.StatusBadGateway,
		)
	}

	return proxy
}

func main() {
	if err := run(); err != nil {
		log.Printf("edge gateway terminated: %v", err)
		os.Exit(1)
	}
}

func run() error {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	internalTransport := newUpstreamTransport("")
	defer internalTransport.CloseIdleConnections()

	// Pin outgoing decoy TLS SNI to the decoy origin hostname. Certificate
	// verification remains enabled and uses the system CA pool.
	decoyTransport := newUpstreamTransport(cfg.DecoyOrigin.Hostname())
	defer decoyTransport.CloseIdleConnections()

	decoyProxy := newReverseProxy(
		cfg.DecoyOrigin,
		decoyTransport,
		true,
	)

	internalPool, err := NewBackendPool(
		cfg.InternalBackends,
		internalTransport,
	)
	if err != nil {
		return err
	}

	gateway := &Gateway{
		validator: &SignatureValidator{
			secret:  cfg.HMACSecret,
			maxSkew: cfg.SignatureMaxSkew,
			now:     time.Now,
		},
		internal: internalPool,
		decoy:    decoyProxy,
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           gateway,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,

		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},

		// No ReadTimeout or WriteTimeout: either could terminate legitimate
		// long-lived WebSocket or streaming connections.
	}

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf(
			"listening on %s; internal_backends=%d decoy=%s",
			cfg.ListenAddress,
			len(cfg.InternalBackends),
			cfg.DecoyOrigin.Redacted(),
		)

		serverErrors <- server.ListenAndServeTLS(
			cfg.CertificateFile,
			cfg.PrivateKeyFile,
		)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("HTTPS server: %w", err)

	case sig := <-signals:
		log.Printf("received %s; starting graceful shutdown", sig)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		cfg.ShutdownTimeout,
	)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	log.Printf("shutdown complete")
	return nil
}

// newUpstreamTransport returns a transport suitable for HTTP, HTTPS, and
// HTTP/1.1 WebSocket upgrades. An empty serverName allows Go to derive TLS
// SNI independently for each internal backend.
func newUpstreamTransport(serverName string) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 64
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second

	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	return transport
}

func loadConfig() (Config, error) {
	var cfg Config

	cfg.ListenAddress = envOrDefault("EDGE_ADDR", ":8443")

	var err error

	cfg.CertificateFile, err = requiredEnv("EDGE_CERT_FILE")
	if err != nil {
		return Config{}, err
	}

	cfg.PrivateKeyFile, err = requiredEnv("EDGE_KEY_FILE")
	if err != nil {
		return Config{}, err
	}

	secret, err := requiredEnv("EDGE_HMAC_SECRET")
	if err != nil {
		return Config{}, err
	}
	if len(secret) < 32 {
		return Config{}, fmt.Errorf(
			"EDGE_HMAC_SECRET must contain at least 32 bytes",
		)
	}
	cfg.HMACSecret = []byte(secret)

	decoyAddress, err := requiredEnv("EDGE_DECOY_ORIGIN")
	if err != nil {
		return Config{}, err
	}

	cfg.DecoyOrigin, err = parseTarget(decoyAddress)
	if err != nil {
		return Config{}, fmt.Errorf("EDGE_DECOY_ORIGIN: %w", err)
	}

	allowInsecureDecoy := strings.EqualFold(
		os.Getenv("EDGE_ALLOW_INSECURE_DECOY"),
		"true",
	)

	if cfg.DecoyOrigin.Scheme == "http" && !allowInsecureDecoy {
		return Config{}, fmt.Errorf(
			"decoy origin must use HTTPS; set " +
				"EDGE_ALLOW_INSECURE_DECOY=true only for local testing",
		)
	}

	backendList, err := requiredEnv("EDGE_INTERNAL_BACKENDS")
	if err != nil {
		return Config{}, err
	}

	for _, entry := range strings.Split(backendList, ",") {
		target, parseErr := parseTarget(entry)
		if parseErr != nil {
			return Config{}, fmt.Errorf(
				"internal backend %q: %w",
				entry,
				parseErr,
			)
		}

		cfg.InternalBackends = append(cfg.InternalBackends, target)
	}

	if len(cfg.InternalBackends) == 0 {
		return Config{}, fmt.Errorf("no internal backends configured")
	}

	cfg.SignatureMaxSkew, err = durationEnv(
		"EDGE_SIGNATURE_MAX_SKEW",
		5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}

	cfg.ShutdownTimeout, err = durationEnv(
		"EDGE_SHUTDOWN_TIMEOUT",
		30*time.Second,
	)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func parseTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}

	target, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	switch target.Scheme {
	case "ws":
		target.Scheme = "http"
	case "wss":
		target.Scheme = "https"
	case "http", "https":
	default:
		return nil, fmt.Errorf(
			"unsupported scheme %q; use http, https, ws, or wss",
			target.Scheme,
		)
	}

	if target.Host == "" {
		return nil, fmt.Errorf("target has no host")
	}
	if target.User != nil {
		return nil, fmt.Errorf("credentials in target URLs are not supported")
	}
	if target.Fragment != "" {
		return nil, fmt.Errorf("target must not contain a fragment")
	}

	return target, nil
}

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(
	name string,
	fallback time.Duration,
) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}

	return duration, nil
}
