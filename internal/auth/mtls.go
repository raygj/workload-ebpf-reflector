package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// TLSConfig holds paths to TLS material for gRPC mTLS (ADR-013).
type TLSConfig struct {
	CACertFile   string // path to PEM-encoded CA cert
	CertFile     string // path to PEM-encoded leaf cert
	KeyFile      string // path to PEM-encoded private key
}

// Enabled reports whether all three paths are set.
func (c TLSConfig) Enabled() bool {
	return c.CACertFile != "" && c.CertFile != "" && c.KeyFile != ""
}

// ServerCredentials returns gRPC server credentials that require client cert
// from the configured CA and extract the peer SPIFFE SAN for node ID binding.
func (c TLSConfig) ServerCredentials() (credentials.TransportCredentials, error) {
	cert, ca, err := c.load()
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca,
		MinVersion:   tls.VersionTLS13,
	}
	return credentials.NewTLS(tlsCfg), nil
}

// ClientCredentials returns gRPC client credentials that present a cert and
// verify the server cert against the configured CA.
func (c TLSConfig) ClientCredentials(serverName string) (credentials.TransportCredentials, error) {
	cert, ca, err := c.load()
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
	return credentials.NewTLS(tlsCfg), nil
}

// PeerSPIFFEID extracts the first spiffe:// URI SAN from a verified peer cert
// as returned by grpc.Peer / credentials.AuthInfo.
func PeerSPIFFEID(tlsInfo credentials.TLSInfo) string {
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ""
	}
	cert := chains[0][0]
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return uri.String()
		}
	}
	return ""
}

// PeerCN returns the Common Name of the verified peer leaf certificate.
func PeerCN(tlsInfo credentials.TLSInfo) string {
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ""
	}
	return chains[0][0].Subject.CommonName
}

func (c TLSConfig) load() (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("loading cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(c.CACertFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("reading CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, fmt.Errorf("parsing CA cert: no valid certs found")
	}
	return cert, pool, nil
}
