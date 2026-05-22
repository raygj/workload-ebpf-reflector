package extract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// generateSVID creates a self-signed X.509 certificate with a SPIFFE URI SAN.
func generateSVID(t *testing.T, spiffeID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// generateCertNoSPIFFE creates a cert with a non-SPIFFE URI SAN.
func generateCertNoSPIFFE(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://example.com/not-spiffe")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseSPIFFEFromDER(t *testing.T) {
	der := generateSVID(t, "spiffe://prod.example.com/agent/deploy")
	id, err := ParseSPIFFEFromDER(der)
	if err != nil {
		t.Fatalf("ParseSPIFFEFromDER: %v", err)
	}
	if id == nil {
		t.Fatal("expected SPIFFE identity, got nil")
	}
	if id.TrustDomain != "prod.example.com" {
		t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, "prod.example.com")
	}
	if id.Path != "/agent/deploy" {
		t.Errorf("Path = %q, want %q", id.Path, "/agent/deploy")
	}
	if id.Raw != "spiffe://prod.example.com/agent/deploy" {
		t.Errorf("Raw = %q, want %q", id.Raw, "spiffe://prod.example.com/agent/deploy")
	}
}

func TestParseSPIFFEFromDERVaultPKI(t *testing.T) {
	// Simulate a Vault PKI-issued SVID
	der := generateSVID(t, "spiffe://vault.prod/ns/default/sa/web-server")
	id, err := ParseSPIFFEFromDER(der)
	if err != nil {
		t.Fatalf("ParseSPIFFEFromDER: %v", err)
	}
	if id.TrustDomain != "vault.prod" {
		t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, "vault.prod")
	}
	if id.Path != "/ns/default/sa/web-server" {
		t.Errorf("Path = %q, want %q", id.Path, "/ns/default/sa/web-server")
	}
}

func TestParseSPIFFEFromDERNoSPIFFE(t *testing.T) {
	der := generateCertNoSPIFFE(t)
	id, err := ParseSPIFFEFromDER(der)
	if err != nil {
		t.Fatalf("ParseSPIFFEFromDER: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil for non-SPIFFE cert, got %+v", id)
	}
}

func TestParseSPIFFEFromDERInvalidDER(t *testing.T) {
	_, err := ParseSPIFFEFromDER([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid DER, got nil")
	}
}

func TestParseSPIFFEFromURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantTD  string
		wantP   string
		wantErr bool
	}{
		{"valid", "spiffe://example.com/workload", "example.com", "/workload", false},
		{"deep path", "spiffe://prod/ns/default/sa/web", "prod", "/ns/default/sa/web", false},
		{"root path", "spiffe://example.com/", "example.com", "/", false},
		{"not spiffe", "https://example.com/foo", "", "", true},
		{"empty", "", "", "", true},
		{"no trust domain", "spiffe:///path", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseSPIFFEFromURI(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.TrustDomain != tt.wantTD {
				t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, tt.wantTD)
			}
			if id.Path != tt.wantP {
				t.Errorf("Path = %q, want %q", id.Path, tt.wantP)
			}
		})
	}
}
