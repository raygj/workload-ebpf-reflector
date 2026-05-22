package policy_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/raygj/workload-ebpf-reflector/internal/policy"
)

func newEval(t *testing.T, policyPath string) *policy.Evaluator {
	t.Helper()
	ev, err := policy.New(policyPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return ev
}

func TestDefaultPolicyAllowsKnownTrustDomain(t *testing.T) {
	ev := newEval(t, "")
	result := ev.Eval(context.Background(), policy.Input{
		SPIFFEID: "spiffe://cluster.local/ns/default/sa/my-agent",
		SrcAddr:  "10.0.0.1:12345",
		DstAddr:  "10.0.0.2:443",
	})
	if !result.Allow {
		t.Errorf("expected allow=true for known trust domain, got reason=%q", result.Reason)
	}
}

func TestDefaultPolicyDeniesUnknownTrustDomain(t *testing.T) {
	ev := newEval(t, "")
	result := ev.Eval(context.Background(), policy.Input{
		SPIFFEID: "spiffe://evil.corp/ns/default/sa/attacker",
		SrcAddr:  "10.0.0.1:12345",
		DstAddr:  "10.0.0.2:443",
	})
	if result.Allow {
		t.Errorf("expected deny for unknown trust domain, got allow=true")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason on deny")
	}
}

func TestDefaultPolicyDeniesEmptySPIFFEID(t *testing.T) {
	ev := newEval(t, "")
	result := ev.Eval(context.Background(), policy.Input{
		SPIFFEID: "",
		SrcAddr:  "10.0.0.1:12345",
		DstAddr:  "10.0.0.2:443",
	})
	if result.Allow {
		t.Errorf("expected deny for empty SPIFFE ID, got allow=true")
	}
}

func TestCustomPolicyFileOverridesDefault(t *testing.T) {
	// Write a permissive policy that allows everything including empty SPIFFE IDs.
	f, err := os.CreateTemp(t.TempDir(), "policy-*.rego")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`package reflector.policy
default allow := true
default reason := "allow-all-test"
`)
	_ = f.Close()

	ev := newEval(t, f.Name())
	result := ev.Eval(context.Background(), policy.Input{SPIFFEID: ""})
	if !result.Allow {
		t.Errorf("custom allow-all policy should allow empty SPIFFE ID, got reason=%q", result.Reason)
	}
}

func TestMissingPolicyFileFallsBackToDefault(t *testing.T) {
	// A nonexistent path should fall back to the embedded default without error.
	ev := newEval(t, "/nonexistent/policy.rego")
	result := ev.Eval(context.Background(), policy.Input{
		SPIFFEID: "spiffe://cluster.local/ns/default/sa/ok",
	})
	if !result.Allow {
		t.Errorf("fallback default should allow known trust domain, got reason=%q", result.Reason)
	}
}
