package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func verifyLeaf(t *testing.T, ca *CA, leaf *tls.Certificate, dnsName string) {
	t.Helper()
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   dnsName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("leaf does not verify for %q: %v", dnsName, err)
	}
}

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !ca.cert.IsCA {
		t.Error("cert is not a CA")
	}
	if ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("cert cannot sign certificates")
	}
	if got := time.Until(ca.cert.NotAfter); got < 9*365*24*time.Hour {
		t.Errorf("CA lifetime suspiciously short: %v", got)
	}
	if len(ca.CertPEM()) == 0 {
		t.Error("empty cert PEM")
	}
}

func TestLeafForDNSHost(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// CONNECT sends authority form; the port must not leak into the SAN list.
	leaf, err := ca.Leaf("Example.COM:443")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	cert := leaf.Leaf
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", cert.DNSNames)
	}
	verifyLeaf(t, ca, leaf, "example.com")

	// A different name must not verify against this leaf.
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.com"}); err == nil {
		t.Error("leaf verifies for other.com, want failure")
	}
}

func TestLeafForIPHost(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	leaf, err := ca.Leaf("127.0.0.1:8443")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	// An IP literal needs an IP SAN; a DNS SAN holding digits does not count.
	if len(leaf.Leaf.IPAddresses) != 1 || leaf.Leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", leaf.Leaf.IPAddresses)
	}
	verifyLeaf(t, ca, leaf, "127.0.0.1")
}

// RSA key generation is the expensive part; a repeated host must reuse the
// certificate it already minted.
func TestLeafIsCached(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	first, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	second, err := ca.Leaf("example.com:443")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if first != second {
		t.Error("same host minted twice")
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	keyPath := filepath.Join(t.TempDir(), "ca-key.pem")
	if err := ca.WriteTo(certPath, keyPath); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key permissions = %o, want 600: the key signs for any host", got)
	}

	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	leaf, err := loaded.Leaf("example.com")
	if err != nil {
		t.Fatalf("Leaf from loaded CA: %v", err)
	}
	verifyLeaf(t, loaded, leaf, "example.com")
}

func TestEnsureCAGeneratesOnce(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	keyPath := filepath.Join(t.TempDir(), "ca-key.pem")

	ca, generated, err := EnsureCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	if !generated {
		t.Error("first call: generated = false, want true")
	}
	again, generated, err := EnsureCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if generated {
		t.Error("second call regenerated the CA: clients would lose trust")
	}
	// Same CA: a leaf minted by one verifies against the other's pool.
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	verifyLeaf(t, again, leaf, "example.com")
}

func TestLoadRejectsNonCA(t *testing.T) {
	// A leaf certificate posing as the CA file must be refused: minting leafs
	// with it would fail in ways that look like client bugs.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	keyPath := filepath.Join(t.TempDir(), "ca-key.pem")
	if err := ca.WriteTo(certPath, keyPath); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Swap the CA certificate for the leaf's PEM.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	if err := os.WriteFile(certPath, leafPEM, 0o644); err != nil {
		t.Fatalf("overwrite cert: %v", err)
	}
	if _, err := LoadCA(certPath, keyPath); err == nil {
		t.Error("LoadCA accepted a non-CA certificate")
	}
}
