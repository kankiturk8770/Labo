package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// panelCertDir returns the directory where the panel's self-signed TLS
// certificate is stored. It follows KLINK_DB_PATH so the cert lives next to
// the database, and falls back to /opt/klink.
func panelCertDir() string {
	if db := os.Getenv("KLINK_DB_PATH"); db != "" {
		if d := filepath.Dir(db); d != "" && d != "." {
			return d
		}
	}
	return "/opt/klink"
}

// ensurePanelCert returns paths to a TLS certificate and key for the panel,
// generating a long-lived self-signed certificate on first run and reusing it
// afterwards. The certificate covers localhost and every local IP address so
// the panel can be reached over HTTPS by IP without a domain or external CA.
func ensurePanelCert(dir string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dir, "panel-cert.pem")
	keyFile = filepath.Join(dir, "panel-key.pem")

	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "KLINK Panel"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           localIPs(),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", "", err
	}
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return "", "", err
	}
	if err = certOut.Close(); err != nil {
		return "", "", err
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	if err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		keyOut.Close()
		return "", "", err
	}
	if err = keyOut.Close(); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// localIPs returns loopback plus every non-loopback interface address, so the
// self-signed certificate validates for whichever IP the admin connects to.
func localIPs() []net.IP {
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ips = append(ips, ipnet.IP)
		}
	}
	return ips
}
