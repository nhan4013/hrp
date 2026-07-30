// Package mitm issues the development certificate authority and the per-host
// leaf certificates that let hrp terminate TLS inside a CONNECT tunnel.
//
// The CA is a *development* CA: whoever holds its private key can sign for any
// host. It is generated locally, written with 0600 permissions, and must never
// be committed or shared.
package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// caValidity is long enough that trusting the CA once is a one-time setup.
const caValidity = 10 * 365 * 24 * time.Hour

// leafValidity keeps a minted certificate usable across long dev sessions
// without re-minting. Browsers cap leaf validity only for publicly trusted
// roots, so a private CA can go past their 398-day limit.
const leafValidity = 365 * 24 * time.Hour

// CA signs leaf certificates for the hosts a client CONNECTs to. Leaf minting
// is lazy and cached: RSA key generation costs a noticeable fraction of a
// second, so each hostname pays it once per process, not once per connection.
type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
	keyPEM  []byte

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// GenerateCA creates a fresh self-signed RSA CA. RSA rather than ECDSA: every
// TLS stack trusts an RSA 2048 CA, which is exactly what a MITM CA needs from
// clients it has never met.
func GenerateCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "hrp development CA", Organization: []string{"hrp"}},
		NotBefore:             now.Add(-time.Hour), // tolerate clock skew on the client
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse own CA certificate: %w", err)
	}

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		leafs:   make(map[string]*tls.Certificate),
	}, nil
}

// LoadCA reads a CA certificate and key written by WriteTo.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA certificate %s: no CERTIFICATE PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate %s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA key %s: no PEM block", keyPath)
	}
	key, err := parseRSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key %s: %w", keyPath, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA certificate %s: basic constraints say it is not a CA", certPath)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM, keyPEM: keyPEM, leafs: make(map[string]*tls.Certificate)}, nil
}

// EnsureCA loads the CA when both files exist, and otherwise generates one and
// persists it. generated reports which happened, so the caller can tell the
// user a new CA needs trusting.
func EnsureCA(certPath, keyPath string) (ca *CA, generated bool, err error) {
	ca, err = LoadCA(certPath, keyPath)
	if err == nil {
		return ca, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	ca, err = GenerateCA()
	if err != nil {
		return nil, false, err
	}
	if err := ca.WriteTo(certPath, keyPath); err != nil {
		return nil, false, err
	}
	return ca, true, nil
}

// WriteTo persists the CA. The key gets 0600: it can sign for any host, so it
// is the one secret this tool actually holds.
func (ca *CA) WriteTo(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create CA dir: %w", err)
	}
	if err := os.WriteFile(certPath, ca.certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate %s: %w", certPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return fmt.Errorf("create CA dir: %w", err)
	}
	if err := os.WriteFile(keyPath, ca.keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key %s: %w", keyPath, err)
	}
	return nil
}

// CertPEM is the certificate to hand to clients so they trust the tunnel.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// Leaf returns a certificate valid for host, minting and caching it on first
// use. host may carry a port (CONNECT sends authority form, "example.com:443"),
// which certificates know nothing about, so it is stripped. An IP literal gets
// an IP SAN, a DNS name a DNS SAN — clients verify them differently.
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil, errors.New("mint leaf certificate: empty host")
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert, ok := ca.leafs[name]; ok {
		return cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", name, err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse own leaf for %s: %w", name, err)
	}

	cert := &tls.Certificate{
		// Send the CA certificate alongside the leaf: the chain is complete
		// even for clients that build paths strictly, at one extra kilobyte.
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	ca.leafs[name] = cert
	return cert, nil
}

// parseRSAPrivateKey accepts PKCS1 (what WriteTo emits) and PKCS8 (what most
// other tools emit), so a user-supplied CA key works either way.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("neither PKCS1 nor PKCS8: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS8 key is %T, want an RSA key", parsed)
	}
	return key, nil
}

// randomSerial returns a positive 128-bit serial number. Random rather than
// sequential: two leafs minted a second apart must not collide.
func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// crypto/rand failing is a broken system, and a zero serial is worse.
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return serial
}
