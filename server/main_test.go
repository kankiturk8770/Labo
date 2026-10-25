package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func signed(r *http.Request, ts int64) {
	stamp := strconv.FormatInt(ts, 10)
	r.Header.Set(timestampHeader, stamp)
	h := hmac.New(sha256.New, testSecret)
	h.Write([]byte(stamp + "\n" + r.Method + "\n" + r.URL.RequestURI() + "\n" + r.Header.Get("Sec-WebSocket-Key")))
	r.Header.Set(signatureHeader, hex.EncodeToString(h.Sum(nil)))
}
func validator() *SignatureValidator {
	return &SignatureValidator{testSecret, 5 * time.Minute, func() time.Time { return time.Unix(1700000000, 0) }}
}
func TestSignatureContract(t *testing.T) {
	tests := []struct {
		name string
		edit func(*http.Request)
		ok   bool
	}{
		{"valid", func(r *http.Request) {}, true},
		{"prefix", func(r *http.Request) { r.Header.Set(signatureHeader, "sha256="+r.Header.Get(signatureHeader)) }, true},
		{"missing", func(r *http.Request) { r.Header.Del(signatureHeader) }, false},
		{"bad hex", func(r *http.Request) { r.Header.Set(signatureHeader, "zz") }, false},
		{"expired", func(r *http.Request) { signed(r, 1699999699) }, false},
		{"future", func(r *http.Request) { signed(r, 1700000301) }, false},
		{"boundary", func(r *http.Request) { signed(r, 1699999700) }, true},
		{"method", func(r *http.Request) { r.Method = "POST" }, false},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=2" }, false},
		{"websocket key", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "changed") }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://edge.test/path%2Fpart?x=1", nil)
			signed(r, 1700000000)
			tt.edit(r)
			if got := validator().Valid(r); got != tt.ok {
				t.Fatalf("valid=%v want %v", got, tt.ok)
			}
		})
	}
}
func makeGateway(t *testing.T, backends []string, decoy string) *Gateway {
	t.Helper()
	urls := []*url.URL{}
	for _, s := range backends {
		u, e := url.Parse(s)
		if e != nil {
			t.Fatal(e)
		}
		urls = append(urls, u)
	}
	tr := newUpstreamTransport("")
	t.Cleanup(tr.CloseIdleConnections)
	pool, e := NewBackendPool(urls, tr)
	if e != nil {
		t.Fatal(e)
	}
	du, _ := url.Parse(decoy)
	return &Gateway{validator(), pool, newReverseProxy(du, tr, true)}
}
func TestRoutingFallbackAndRoundRobin(t *testing.T) {
	servers := []*httptest.Server{}
	for _, name := range []string{"a", "b", "decoy"} {
		n := name
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, n) }))
		defer s.Close()
		servers = append(servers, s)
	}
	g := makeGateway(t, []string{servers[0].URL, servers[1].URL}, servers[2].URL)
	for i, want := range []string{"a", "b", "decoy", "a"} {
		r := httptest.NewRequest("GET", "https://edge.test/", nil)
		if i != 2 {
			signed(r, 1700000000)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Body.String() != want {
			t.Fatalf("got %s want %s", w.Body.String(), want)
		}
	}
}
func TestForwardingContract(t *testing.T) {
	type received struct {
		host, path, query, body, method string
		headers                         http.Header
	}
	ch := make(chan received, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- received{r.Host, r.URL.EscapedPath(), r.URL.RawQuery, string(b), r.Method, r.Header.Clone()}
		w.Header().Set("X-Response-Test", "kept")
		io.WriteString(w, "response")
	}))
	defer upstream.Close()
	g := makeGateway(t, []string{upstream.URL}, upstream.URL)
	for _, auth := range []bool{true, false} {
		r := httptest.NewRequest("POST", "https://public.test/a%2Fb?q=%2F", strings.NewReader("exact body\x00"))
		r.RemoteAddr = "192.0.2.1:3456"
		r.Header.Set("X-Forwarded-For", "spoof")
		r.Header.Set("Forwarded", "spoof")
		r.Header.Set("X-Forwarded-Host", "spoof")
		r.Header.Set("X-End-To-End", "kept")
		if auth {
			signed(r, 1700000000)
		} else {
			r.Header.Set(signatureHeader, "bad")
			r.Header.Set(timestampHeader, "bad")
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		got := <-ch
		if got.body != "exact body\x00" || got.method != "POST" || got.path != "/a%2Fb" || got.query != "q=%2F" {
			t.Fatalf("request changed: %#v", got)
		}
		if got.headers.Get(signatureHeader) != "" || got.headers.Get(timestampHeader) != "" || got.headers.Get("Forwarded") != "" {
			t.Fatal("credential or spoofed metadata leaked")
		}
		if auth {
			if got.headers.Get("X-Forwarded-For") != "192.0.2.1" || got.headers.Get("X-Forwarded-Host") != "public.test" || got.headers.Get("X-Forwarded-Proto") != "https" {
				t.Fatal(got.headers)
			}
		} else if got.headers.Get("X-Forwarded-For") != "" || got.headers.Get("X-Forwarded-Host") != "" {
			t.Fatal("decoy topology leaked")
		}
		if got.headers.Get("X-End-To-End") != "kept" || w.Header().Get("X-Response-Test") != "kept" || w.Body.String() != "response" {
			t.Fatal("end-to-end data changed")
		}
	}
}
func TestWebSocketBidirectional(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buf.Flush()
		io.Copy(conn, buf)
	}))
	defer backend.Close()
	frontend := httptest.NewServer(makeGateway(t, []string{backend.URL}, backend.URL))
	defer frontend.Close()
	u, _ := url.Parse(frontend.URL)
	conn, e := net.DialTimeout("tcp", u.Host, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	r, _ := http.NewRequest("GET", frontend.URL+"/socket", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	signed(r, 1700000000)
	r.Write(conn)
	rd := bufio.NewReader(conn)
	resp, e := http.ReadResponse(rd, r)
	if e != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade failed: %v %#v", e, resp)
	}
	payload := []byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}
	if _, e = conn.Write(payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(rd, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != string(payload) {
		t.Fatal("upgraded bytes changed")
	}
}
func TestStreaming(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
		io.WriteString(w, "second\n")
	}))
	defer backend.Close()
	frontend := httptest.NewServer(makeGateway(t, []string{backend.URL}, backend.URL))
	defer frontend.Close()
	r, _ := http.NewRequest("GET", frontend.URL, nil)
	signed(r, 1700000000)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	first, e := bufio.NewReader(resp.Body).ReadString('\n')
	if e != nil || first != "first\n" {
		t.Fatalf("stream buffered: %q %v", first, e)
	}
}
func TestTuningDefaultsAndValidation(t *testing.T) {
	for _, key := range []string{"EDGE_READ_HEADER_TIMEOUT", "EDGE_SERVER_IDLE_TIMEOUT", "EDGE_MAX_HEADER_BYTES", "EDGE_TLS_MIN_VERSION", "EDGE_MAX_IDLE_CONNS", "EDGE_MAX_IDLE_CONNS_PER_HOST", "EDGE_UPSTREAM_IDLE_TIMEOUT", "EDGE_TLS_HANDSHAKE_TIMEOUT", "EDGE_EXPECT_CONTINUE_TIMEOUT"} {
		t.Setenv(key, "")
	}
	got, e := loadTuning()
	if e != nil || got != (Tuning{10 * time.Second, 120 * time.Second, 64 << 10, tls.VersionTLS12, 256, 64, 90 * time.Second, 10 * time.Second, time.Second}) {
		t.Fatal("defaults changed", got, e)
	}
	t.Setenv("EDGE_MAX_HEADER_BYTES", "131072")
	got, e = loadTuning()
	if e != nil || got.MaxHeaderBytes != 131072 {
		t.Fatal(got, e)
	}
	t.Setenv("EDGE_MAX_HEADER_BYTES", "0")
	if _, e = loadTuning(); e == nil {
		t.Fatal("accepted bad limit")
	}
}
func TestTargetAndEmptyPool(t *testing.T) {
	if _, e := NewBackendPool(nil, nil); e == nil {
		t.Fatal("empty pool accepted")
	}
	for _, raw := range []string{"ftp://host", "https://user:pass@host", "https://host/#fragment", ""} {
		if _, e := parseTarget(raw); e == nil {
			t.Fatal("accepted", raw)
		}
	}
	u, e := parseTarget("wss://example.com/path")
	if e != nil || u.Scheme != "https" {
		t.Fatal(u, e)
	}
}
