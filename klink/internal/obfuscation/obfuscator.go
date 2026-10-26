package obfuscation

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ProfileType string

const (
	ProfileRandom   ProfileType = "random"
	ProfileTLSMimic ProfileType = "tls-mimic"
)

type CertMetadata struct {
	Domain        string   `json:"domain"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	SANs          []string `json:"sans"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	Fingerprint   string   `json:"fingerprint"`
	TLSVersion    string   `json:"tls_version"`
	CipherSuite   string   `json:"cipher_suite"`
	RemoteRealIP  string   `json:"remote_real_ip"`
	LastVerified  string   `json:"last_verified"`
	StatusHealthy bool     `json:"status_healthy"`
}

type DynamicConfig struct {
	Profile        ProfileType  `json:"profile"`
	MimicDomain    string       `json:"mimic_domain"`
	FallbackAddr   string       `json:"fallback_addr"`
	UpstreamTunnel string       `json:"upstream_tunnel"` // آدرس سرور خارج (آلمان) برای لوله‌کشی نامرئی
	UpstreamSecret string       `json:"upstream_secret"`
	PaddingMax     int          `json:"padding_max"`
	CertInfo       CertMetadata `json:"cert_info"`
}

type Obfuscator struct {
	mu            sync.RWMutex
	cfg           DynamicConfig
	divertedCount uint64
}

func NewObfuscator(cfg DynamicConfig) *Obfuscator {
	o := &Obfuscator{cfg: cfg}
	if o.cfg.PaddingMax <= 0 || o.cfg.PaddingMax > 250 {
		o.cfg.PaddingMax = 64
	}
	return o
}

func (o *Obfuscator) GetConfig() DynamicConfig {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.cfg
}

func (o *Obfuscator) GetDivertedCount() uint64 {
	return atomic.LoadUint64(&o.divertedCount)
}

// بروزرسانی زنده تنظیمات از طریق پنل مدیریت بدون ریستارت سرور
func (o *Obfuscator) UpdateConfig(newCfg DynamicConfig) CertMetadata {
	if newCfg.PaddingMax <= 0 || newCfg.PaddingMax > 250 {
		newCfg.PaddingMax = 64
	}
	if newCfg.FallbackAddr == "" && newCfg.MimicDomain != "" {
		newCfg.FallbackAddr = newCfg.MimicDomain + ":443"
	}
	meta := ProbeTargetTLS(newCfg.MimicDomain, newCfg.FallbackAddr)
	newCfg.CertInfo = meta

	o.mu.Lock()
	o.cfg = newCfg
	o.mu.Unlock()
	return meta
}

// ارتباط زنده با سایت داخلی (مثلاً آپارات یا آنتن) و دریافت گواهی TLS، زنجیره Issuer و فینگرپینت واقعی آن
func ProbeTargetTLS(domain, fallbackAddr string) CertMetadata {
	meta := CertMetadata{
		Domain:       domain,
		LastVerified: time.Now().Format("2006-01-02 15:04:05"),
	}
	target := fallbackAddr
	if target == "" {
		target = domain + ":443"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		meta.StatusHealthy = false
		meta.Subject = "خطا در دریافت گواهی از " + target + ": " + err.Error()
		return meta
	}
	defer conn.Close()

	state := conn.ConnectionState()
	meta.RemoteRealIP = conn.RemoteAddr().String()
	meta.TLSVersion = tls.VersionName(state.Version)
	meta.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		meta.Subject = cert.Subject.CommonName
		meta.Issuer = cert.Issuer.CommonName
		meta.SANs = cert.DNSNames
		meta.NotBefore = cert.NotBefore.Format("2006-01-02")
		meta.NotAfter = cert.NotAfter.Format("2006-01-02")
		fp := sha256.Sum256(cert.Raw)
		meta.Fingerprint = hex.EncodeToString(fp[:16])
		meta.StatusHealthy = true
	}
	return meta
}

// بسته‌بندی دوطرفه یکسان (Symmetric TLS 1.3 Application Data Record 0x17 0x03 0x03)
func (o *Obfuscator) Wrap(payload []byte) []byte {
	o.mu.RLock()
	profile := o.cfg.Profile
	maxPad := o.cfg.PaddingMax
	o.mu.RUnlock()

	if maxPad <= 0 {
		maxPad = 64
	}
	var padLenBuf [1]byte
	_, _ = rand.Read(padLenBuf[:])
	padLen := int(padLenBuf[0]) % maxPad

	padding := make([]byte, padLen)
	_, _ = rand.Read(padding)

	innerLen := 1 + len(payload) + padLen
	inner := make([]byte, innerLen)
	inner[0] = byte(padLen)
	copy(inner[1:1+len(payload)], payload)
	copy(inner[1+len(payload):], padding)

	if profile == ProfileTLSMimic {
		record := make([]byte, 5+len(inner))
		record[0] = 0x17 // TLS Application Data
		record[1] = 0x03 // TLS 1.2 / 1.3 record layer
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(len(inner)))
		copy(record[5:], inner)
		return record
	}

	out := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(inner)))
	copy(out[2:], inner)
	return out
}

func (o *Obfuscator) Unwrap(data []byte) ([]byte, error) {
	o.mu.RLock()
	profile := o.cfg.Profile
	o.mu.RUnlock()

	var inner []byte
	if profile == ProfileTLSMimic {
		if len(data) < 6 || data[0] != 0x17 || data[1] != 0x03 || data[2] != 0x03 {
			return nil, errors.New("invalid tls mimic record")
		}
		recLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recLen {
			return nil, errors.New("short tls record")
		}
		inner = data[5 : 5+recLen]
	} else {
		if len(data) < 3 {
			return nil, errors.New("short random frame")
		}
		recLen := int(binary.BigEndian.Uint16(data[0:2]))
		if len(data) < 2+recLen {
			return nil, errors.New("incomplete random frame")
		}
		inner = data[2 : 2+recLen]
	}

	padLen := int(inner[0])
	if len(inner) < 1+padLen {
		return nil, errors.New("corrupted padding length")
	}
	return inner[1 : len(inner)-padLen], nil
}

// ساخت ClientHello واقعی با SNI دامنه انتخاب‌شده در پنل و تزریق تگ مخفی KLINK در فیلد Random
func (o *Obfuscator) BuildClientHelloSNI(authToken [32]byte) []byte {
	o.mu.RLock()
	sni := o.cfg.MimicDomain
	o.mu.RUnlock()

	sniBytes := []byte(sni)
	extSNILen := len(sniBytes) + 5
	extTotalLen := extSNILen + 4

	var body []byte
	body = append(body, 0x03, 0x03)       // Version TLS 1.2
	body = append(body, authToken[:]...)  // 32-byte Random containing KLINK encrypted probe-proof token
	body = append(body, 0x20)             // Session ID length = 32
	fakeSess := make([]byte, 32)
	_, _ = rand.Read(fakeSess)
	body = append(body, fakeSess...)
	body = append(body, 0x00, 0x02, 0x13, 0x02) // CipherSuite: TLS_CHACHA20_POLY1305_SHA256
	body = append(body, 0x01, 0x00)             // Compression: null

	// Extensions (Server Name Indication - SNI)
	var extBuf [11]byte
	binary.BigEndian.PutUint16(extBuf[0:2], uint16(extTotalLen))
	binary.BigEndian.PutUint16(extBuf[2:4], 0x0000) // Extension: server_name
	binary.BigEndian.PutUint16(extBuf[4:6], uint16(extSNILen))
	binary.BigEndian.PutUint16(extBuf[6:8], uint16(len(sniBytes)+3))
	extBuf[8] = 0x00 // Hostname type
	binary.BigEndian.PutUint16(extBuf[9:11], uint16(len(sniBytes)))

	body = append(body, extBuf[:]...)
	body = append(body, sniBytes...)

	hsLen := len(body)
	hs := make([]byte, 4+hsLen)
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(hsLen >> 16)
	hs[2] = byte(hsLen >> 8)
	hs[3] = byte(hsLen)
	copy(hs[4:], body)

	record := make([]byte, 5+len(hs))
	record[0] = 0x16 // Handshake record
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hs)))
	copy(record[5:], hs)
	return record
}

// لوله‌کشی شفاف و دوطرفه به سایت واقعی داخلی (آپارات/آنتن):
// فیلترچی، مرورگر عادی یا اسکنر، دقیقاً گواهی TLS و محتوای واقعی سایت داخلی را از همان کانکشن تحویل می‌گیرد!
func (o *Obfuscator) DivertToDomesticSite(clientConn net.Conn, initialBytes []byte) {
	defer clientConn.Close()
	atomic.AddUint64(&o.divertedCount, 1)

	o.mu.RLock()
	fallback := o.cfg.FallbackAddr
	o.mu.RUnlock()

	if fallback == "" {
		return
	}

	targetConn, err := net.DialTimeout("tcp", fallback, 5*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	if len(initialBytes) > 0 {
		_, _ = targetConn.Write(initialBytes)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		if cc, ok := clientConn.(*net.TCPConn); ok {
			_ = cc.CloseWrite()
		}
	}()
	wg.Wait()
}

func (o *Obfuscator) RunSelfTest() map[string]any {
	cfg := o.GetConfig()
	meta := ProbeTargetTLS(cfg.MimicDomain, cfg.FallbackAddr)
	upstreamOK := false
	upstreamLatency := "-"

	if cfg.UpstreamTunnel != "" {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", cfg.UpstreamTunnel, 3*time.Second)
		if err == nil {
			upstreamOK = true
			upstreamLatency = fmt.Sprintf("%d ms", time.Since(t0).Milliseconds())
			c.Close()
		}
	}

	return map[string]any{
		"mimic_domain":      cfg.MimicDomain,
		"fallback_addr":     cfg.FallbackAddr,
		"tls_cert_verified": meta.StatusHealthy,
		"cert_subject":      meta.Subject,
		"cert_issuer":       meta.Issuer,
		"cert_fingerprint":  meta.Fingerprint,
		"remote_real_ip":    meta.RemoteRealIP,
		"upstream_configured": cfg.UpstreamTunnel != "",
		"upstream_reachable":  upstreamOK,
		"upstream_latency":    upstreamLatency,
		"diverted_probes":     o.GetDivertedCount(),
	}
}
