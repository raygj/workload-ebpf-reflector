// Package auth_test exercises the Sprint 13 authentication controls end-to-end:
// gRPC mTLS (RT-001, RT-002) and HTTP bearer token (RT-003).
package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
	"github.com/raygj/workload-ebpf-reflector/internal/auth"
	"github.com/raygj/workload-ebpf-reflector/internal/session"
	"github.com/raygj/workload-ebpf-reflector/internal/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ── cert helpers ──────────────────────────────────────────────────────────────

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	dir     string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	return &testCA{cert: cert, key: key, certPEM: certPEM, dir: dir}
}

func (ca *testCA) issue(t *testing.T, cn, spiffeID string) auth.TLSConfig {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var uris []*url.URL
	if spiffeID != "" {
		u, _ := url.Parse(spiffeID)
		uris = []*url.URL{u}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := filepath.Join(ca.dir, cn+".crt")
	keyFile := filepath.Join(ca.dir, cn+".key")
	os.WriteFile(certFile, certPEM, 0600)
	os.WriteFile(keyFile, keyPEM, 0600)

	return auth.TLSConfig{
		CACertFile: filepath.Join(ca.dir, "ca.crt"),
		CertFile:   certFile,
		KeyFile:    keyFile,
	}
}

// ── test stack ────────────────────────────────────────────────────────────────

type authStack struct {
	sessionMap  *session.Map
	grpcAddr    string
	grpcServer  *grpc.Server
	apiHandler  http.Handler
	teardown    func()
}

func newAuthStack(t *testing.T, serverTLS auth.TLSConfig) *authStack {
	t.Helper()
	logger := slogDiscard()
	sm := session.NewMap(60 * time.Second)
	handler := func(ev *apiv1.ReflectorEvent) { sm.HandleEvent(ev) }

	var grpcOpts []grpc.ServerOption
	if serverTLS.Enabled() {
		creds, err := serverTLS.ServerCredentials()
		if err != nil {
			t.Fatalf("ServerCredentials: %v", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	} else {
		grpcOpts = append(grpcOpts, grpc.Creds(insecure.NewCredentials()))
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpcOpts...)
	apiv1.RegisterReflectorServiceServer(srv, stream.NewServer(handler, logger))
	go func() { _ = srv.Serve(lis) }()

	return &authStack{
		sessionMap: sm,
		grpcAddr:   lis.Addr().String(),
		grpcServer: srv,
		apiHandler: session.NewAPI(sm).Handler(),
		teardown:   func() { srv.Stop() },
	}
}

func (s *authStack) httpGET(path string, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.apiHandler.ServeHTTP(w, req)
	return w
}

// ── RT-001: gRPC mTLS ────────────────────────────────────────────────────────

func TestGRPCMTLSRejectsUnauthenticatedClient(t *testing.T) {
	ca := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector-map")
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	// Connect with insecure credentials — server requires mTLS.
	conn, err := grpc.NewClient(stack.grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	if err == nil {
		t.Fatal("expected connection error for unauthenticated client, got nil")
	}
}

func TestGRPCMTLSRejectsWrongCA(t *testing.T) {
	ca := newTestCA(t)
	wrongCA := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector-map")
	clientTLS := wrongCA.issue(t, "reflector", "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector")
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	creds, err := clientTLS.ClientCredentials("reflector-map")
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	conn, err := grpc.NewClient(stack.grpcAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	streamClient, err := apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	if err != nil {
		return // connection-level rejection — pass
	}
	// Send one event to force the TLS handshake to complete
	_ = streamClient.Send(&apiv1.ReflectorEvent{
		NodeId: "attacker", Timestamp: timestamppb.Now(),
		EventType: apiv1.ReflectorEvent_CONNECTION_OPEN,
	})
	time.Sleep(100 * time.Millisecond)
	// If we got here without error the test fails on the node_id check
	entries := stack.sessionMap.QueryAll("", "", "", "")
	for _, e := range entries {
		if e.NodeID == "attacker" {
			t.Error("wrong-CA client event accepted — mTLS not enforcing CA chain")
		}
	}
}

func TestGRPCMTLSAcceptsVerifiedClient(t *testing.T) {
	ca := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector-map")
	clientTLS := ca.issue(t, "reflector", "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector")
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	creds, err := clientTLS.ClientCredentials("reflector-map")
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	conn, err := grpc.NewClient(stack.grpcAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	if err := s.Send(&apiv1.ReflectorEvent{
		NodeId: "payload-node-id", Timestamp: timestamppb.Now(),
		EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
		SourceAddr:     "10.0.0.1:1234", DestAddr: "vault.prod:8200", Protocol: "tcp",
		SourceIdentity: "spiffe://prod.example.com/ns/app/sa/worker",
		IdentityType:   apiv1.ReflectorEvent_SPIFFE, Pid: 1234,
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_ = s.CloseSend()
	time.Sleep(100 * time.Millisecond)

	entries := stack.sessionMap.QueryAll("", "", "", "")
	if len(entries) == 0 {
		t.Fatal("expected session map entry, got none")
	}
}

// ── RT-002: node_id from peer cert ───────────────────────────────────────────

func TestNodeIDDerivedFromPeerCert(t *testing.T) {
	ca := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector-map")
	spiffeID := "spiffe://cluster.local/ns/ebpf-reflector/sa/reflector"
	clientTLS := ca.issue(t, "reflector", spiffeID)
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	creds, _ := clientTLS.ClientCredentials("reflector-map")
	conn, _ := grpc.NewClient(stack.grpcAddr, grpc.WithTransportCredentials(creds))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _ := apiv1.NewReflectorServiceClient(conn).StreamEvents(ctx)
	s.Send(&apiv1.ReflectorEvent{
		NodeId:         "attacker-forged-node-id", // this must be ignored
		Timestamp:      timestamppb.Now(),
		EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
		SourceAddr:     "10.0.0.1:5555", DestAddr: "db.prod:5432", Protocol: "tcp",
		SourceIdentity: "spiffe://prod.example.com/ns/app/sa/worker",
		IdentityType:   apiv1.ReflectorEvent_SPIFFE, Pid: 5555,
	})
	s.CloseSend()
	time.Sleep(100 * time.Millisecond)

	entries := stack.sessionMap.QueryAll("", "", "", "")
	if len(entries) == 0 {
		t.Fatal("expected session map entry")
	}
	got := entries[0].NodeID
	if got == "attacker-forged-node-id" {
		t.Errorf("node_id taken from payload — forgery not prevented; got %q", got)
	}
	if got != spiffeID {
		t.Errorf("node_id = %q, want %q (cert SPIFFE SAN)", got, spiffeID)
	}
}

// ── RT-003: HTTP bearer token ─────────────────────────────────────────────────

func TestHTTPBearerTokenRejectsNoToken(t *testing.T) {
	t.Setenv("REFLECTOR_API_TOKEN", "test-secret")
	ca := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "")
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	wrapped := auth.TokenMiddleware(stack.apiHandler, slogDiscard())
	req := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestHTTPBearerTokenAcceptsCorrectToken(t *testing.T) {
	t.Setenv("REFLECTOR_API_TOKEN", "test-secret")
	ca := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "")
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	wrapped := auth.TokenMiddleware(stack.apiHandler, slogDiscard())
	req := httptest.NewRequest("GET", "/sessions", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	var entries []session.Entry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Errorf("decode: %v", err)
	}
}

func TestHTTPBearerTokenUnsetIsNoOp(t *testing.T) {
	os.Unsetenv("REFLECTOR_API_TOKEN")
	ca := newTestCA(t)
	serverTLS := ca.issue(t, "reflector-map", "")
	stack := newAuthStack(t, serverTLS)
	defer stack.teardown()

	wrapped := auth.TokenMiddleware(stack.apiHandler, slogDiscard())
	req := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 (no-op when unset), got %d", w.Code)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
