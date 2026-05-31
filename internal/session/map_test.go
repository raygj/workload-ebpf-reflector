package session

import (
	"testing"
	"time"

	apiv1 "github.com/raygj/workload-ebpf-reflector/api/v1"
)

func TestSessionMapConnectionOpen(t *testing.T) {
	m := NewMap(30 * time.Second)

	ev := NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN)
	m.HandleEvent(ev)

	entries := m.QueryAll("", "", "", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != "active" {
		t.Errorf("Status = %q, want active", entries[0].Status)
	}
	if entries[0].Identity != "spiffe://prod/agent/deploy" {
		t.Errorf("Identity = %q, want spiffe://prod/agent/deploy", entries[0].Identity)
	}
	if entries[0].IdentityType != "spiffe" {
		t.Errorf("IdentityType = %q, want spiffe", entries[0].IdentityType)
	}
}

func TestSessionMapConnectionClose(t *testing.T) {
	m := NewMap(30 * time.Second)

	open := NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN)
	m.HandleEvent(open)

	close := NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"", apiv1.ReflectorEvent_CONNECTION_CLOSE)
	m.HandleEvent(close)

	entries := m.QueryAll("", "", "closed", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 closed entry, got %d", len(entries))
	}
}

func TestSessionMapQueryByIdentity(t *testing.T) {
	m := NewMap(30 * time.Second)

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5001", "10.0.0.3:9090", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.5:6000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/scan", apiv1.ReflectorEvent_CONNECTION_OPEN))

	deployConns := m.QueryAll("spiffe://prod/agent/deploy", "", "", "")
	if len(deployConns) != 2 {
		t.Errorf("expected 2 connections for agent/deploy, got %d", len(deployConns))
	}

	scanConns := m.QueryAll("spiffe://prod/agent/scan", "", "", "")
	if len(scanConns) != 1 {
		t.Errorf("expected 1 connection for agent/scan, got %d", len(scanConns))
	}
}

func TestSessionMapQueryByDestination(t *testing.T) {
	m := NewMap(30 * time.Second)

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "vault.prod:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.5:6000", "vault.prod:8200", "tcp",
		"spiffe://prod/agent/scan", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5001", "kafka.prod:9092", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))

	vaultConns := m.QueryAll("", "vault.prod:8200", "", "")
	if len(vaultConns) != 2 {
		t.Errorf("expected 2 connections to vault, got %d", len(vaultConns))
	}
}

func TestSessionMapDataExchangeUpdatesBytes(t *testing.T) {
	m := NewMap(30 * time.Second)

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))

	dataEv := NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"", apiv1.ReflectorEvent_DATA_EXCHANGE)
	dataEv.BytesTx = 4096
	dataEv.BytesRx = 1024
	m.HandleEvent(dataEv)

	entries := m.QueryAll("", "", "", "")
	if entries[0].BytesTx != 4096 {
		t.Errorf("BytesTx = %d, want 4096", entries[0].BytesTx)
	}
}

func TestSessionMapStreamResumedMarksStale(t *testing.T) {
	m := NewMap(30 * time.Second)

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-2", "10.0.0.5:6000", "10.0.0.3:9090", "tcp",
		"spiffe://prod/agent/scan", apiv1.ReflectorEvent_CONNECTION_OPEN))

	// Node-1 reconnects — its entries go stale, node-2 unaffected
	m.HandleEvent(&apiv1.ReflectorEvent{
		NodeId:    "node-1",
		EventType: apiv1.ReflectorEvent_STREAM_RESUMED,
	})

	stale := m.QueryAll("", "", "stale", "")
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale entry, got %d", len(stale))
	}
	if stale[0].NodeID != "node-1" {
		t.Errorf("stale entry NodeID = %q, want node-1", stale[0].NodeID)
	}

	active := m.QueryAll("", "", "active", "")
	if len(active) != 1 {
		t.Fatalf("expected 1 active entry, got %d", len(active))
	}
}

func TestSessionMapSweep(t *testing.T) {
	m := NewMap(10 * time.Millisecond) // very short TTL for testing

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))

	// Close one connection
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"", apiv1.ReflectorEvent_CONNECTION_CLOSE))

	time.Sleep(20 * time.Millisecond)
	m.Sweep()

	// Closed entry should be removed after TTL
	entries := m.QueryAll("", "", "", "")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after sweep, got %d", len(entries))
	}
}

func TestSessionMapSweepEvictsStaleEntries(t *testing.T) {
	m := NewMap(10 * time.Millisecond)

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))

	// Let it go past staleTTL — first sweep transitions active→stale
	time.Sleep(15 * time.Millisecond)
	m.Sweep()

	stale := m.QueryAll("", "", "stale", "")
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale entry after first sweep, got %d", len(stale))
	}

	// Let it go past 2×staleTTL — second sweep must delete the stale entry
	time.Sleep(20 * time.Millisecond)
	m.Sweep()

	entries := m.QueryAll("", "", "", "")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after stale eviction sweep, got %d", len(entries))
	}
}

func TestSessionMapStats(t *testing.T) {
	m := NewMap(30 * time.Second)

	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.1:5001", "10.0.0.3:9090", "tcp",
		"spiffe://prod/agent/deploy", apiv1.ReflectorEvent_CONNECTION_OPEN))
	m.HandleEvent(NewTestEvent("node-1", "10.0.0.5:6000", "10.0.0.2:8200", "tcp",
		"spiffe://prod/agent/scan", apiv1.ReflectorEvent_CONNECTION_OPEN))

	stats := m.GetStats()
	if stats.Active != 3 {
		t.Errorf("Active = %d, want 3", stats.Active)
	}
	if stats.Identities != 2 {
		t.Errorf("Identities = %d, want 2", stats.Identities)
	}
}

func TestSessionMapOTELEvent(t *testing.T) {
	m := NewMap(30 * time.Second)

	ev := &apiv1.ReflectorEvent{
		NodeId:         "node-1",
		EventType:      apiv1.ReflectorEvent_CONNECTION_OPEN,
		SourceAddr:     "10.0.0.10:54321",
		DestAddr:       "collector.example.com:4318",
		Protocol:       "tcp",
		IdentityType:   apiv1.ReflectorEvent_OTEL,
		OtelService:    "payment-service",
		OtelSignalType: "traces",
		OtelSpanCount:  5,
		Pid:            1234,
	}
	m.HandleEvent(ev)

	entries := m.QueryAll("", "", "", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.IdentityType != "otel" {
		t.Errorf("IdentityType = %q, want otel", e.IdentityType)
	}
	if e.Identity != "payment-service" {
		t.Errorf("Identity = %q, want payment-service", e.Identity)
	}
	if e.OTELService != "payment-service" {
		t.Errorf("OTELService = %q, want payment-service", e.OTELService)
	}
	if e.OTELSignalType != "traces" {
		t.Errorf("OTELSignalType = %q, want traces", e.OTELSignalType)
	}
	if e.OTELSpanCount != 5 {
		t.Errorf("OTELSpanCount = %d, want 5", e.OTELSpanCount)
	}
}

func TestSessionMapOTELDataExchangeUpdates(t *testing.T) {
	m := NewMap(30 * time.Second)

	open := &apiv1.ReflectorEvent{
		NodeId:       "node-1",
		EventType:    apiv1.ReflectorEvent_CONNECTION_OPEN,
		SourceAddr:   "10.0.0.10:54321",
		DestAddr:     "collector.example.com:4318",
		Protocol:     "tcp",
		IdentityType: apiv1.ReflectorEvent_OTEL,
		OtelService:  "trace-producer",
		OtelSignalType: "traces",
		OtelSpanCount: 2,
	}
	m.HandleEvent(open)

	// DATA_EXCHANGE with updated span count
	exchange := &apiv1.ReflectorEvent{
		NodeId:         "node-1",
		EventType:      apiv1.ReflectorEvent_DATA_EXCHANGE,
		SourceAddr:     "10.0.0.10:54321",
		DestAddr:       "collector.example.com:4318",
		Protocol:       "tcp",
		IdentityType:   apiv1.ReflectorEvent_OTEL,
		OtelService:    "trace-producer",
		OtelSignalType: "traces",
		OtelSpanCount:  10,
	}
	m.HandleEvent(exchange)

	entries := m.QueryAll("", "", "", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].OTELSpanCount != 10 {
		t.Errorf("OTELSpanCount after DATA_EXCHANGE = %d, want 10", entries[0].OTELSpanCount)
	}
}
