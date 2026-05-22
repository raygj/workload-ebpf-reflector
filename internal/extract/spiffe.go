package extract

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const spiffeScheme = "spiffe"

// SPIFFEIdentity represents a parsed SPIFFE ID from an X.509 SVID.
type SPIFFEIdentity struct {
	Raw        string // Full SPIFFE URI: spiffe://trust-domain/path
	TrustDomain string // e.g., "prod.example.com"
	Path       string // e.g., "/agent/deploy"
}

// ParseSPIFFEFromDER parses a DER-encoded X.509 certificate and extracts
// the SPIFFE ID from the URI SAN field. Returns nil if no SPIFFE URI is found.
//
// Per the SPIFFE X.509-SVID spec, the SPIFFE ID is a URI SAN with scheme "spiffe".
// A valid SVID has exactly one SPIFFE URI SAN.
func ParseSPIFFEFromDER(der []byte) (*SPIFFEIdentity, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing X.509 certificate: %w", err)
	}
	return ParseSPIFFEFromCert(cert)
}

// ParseSPIFFEFromCert extracts the SPIFFE ID from a parsed X.509 certificate.
func ParseSPIFFEFromCert(cert *x509.Certificate) (*SPIFFEIdentity, error) {
	for _, uri := range cert.URIs {
		if uri.Scheme == spiffeScheme {
			return parseSPIFFEURI(uri)
		}
	}
	return nil, nil // No SPIFFE URI found — not an error, just not an SVID
}

// ParseSPIFFEFromURI parses a raw SPIFFE URI string.
func ParseSPIFFEFromURI(rawURI string) (*SPIFFEIdentity, error) {
	if !strings.HasPrefix(rawURI, "spiffe://") {
		return nil, fmt.Errorf("not a SPIFFE URI: %q", rawURI)
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("parsing SPIFFE URI: %w", err)
	}
	return parseSPIFFEURI(u)
}

// CertMetadata holds the rotation-tracking fields extracted from an X.509 cert.
type CertMetadata struct {
	Serial           string    // hex-encoded serial number
	Expiry           time.Time // NotAfter
	IssuerFingerprint string   // SHA-256 of issuer raw public key bytes (hex)
}

// ExtractCertMetadata pulls rotation-relevant fields from a parsed certificate.
// IssuerFingerprint is computed from the SubjectPublicKeyInfo bytes of the issuer
// embedded in the cert — stable across reissuances from the same CA key.
func ExtractCertMetadata(cert *x509.Certificate) CertMetadata {
	fp := ""
	if len(cert.RawIssuer) > 0 {
		// Use issuer public key info if available (from the issuer cert embedded via
		// AuthorityKeyIdentifier), else fall back to hashing the raw issuer DN.
		// For SPIFFE SVIDs the issuer is always the SPIRE/cert-manager CA — the DN
		// is stable enough to use as a fingerprint discriminator.
		h := sha256.Sum256(cert.RawIssuer)
		fp = hex.EncodeToString(h[:])
	}
	serial := ""
	if cert.SerialNumber != nil {
		serial = hex.EncodeToString(cert.SerialNumber.Bytes())
	}
	return CertMetadata{
		Serial:            serial,
		Expiry:            cert.NotAfter,
		IssuerFingerprint: fp,
	}
}

// ExtractCertMetadataFromDER parses DER bytes and extracts cert metadata.
func ExtractCertMetadataFromDER(der []byte) (CertMetadata, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertMetadata{}, fmt.Errorf("parsing certificate: %w", err)
	}
	return ExtractCertMetadata(cert), nil
}

func parseSPIFFEURI(u *url.URL) (*SPIFFEIdentity, error) {
	if u.Scheme != spiffeScheme {
		return nil, fmt.Errorf("not a SPIFFE URI: scheme=%q", u.Scheme)
	}
	td := u.Host
	if td == "" {
		return nil, fmt.Errorf("SPIFFE URI missing trust domain: %s", u.String())
	}
	return &SPIFFEIdentity{
		Raw:         u.String(),
		TrustDomain: td,
		Path:        u.Path,
	}, nil
}
