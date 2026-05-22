# Architecture: From Observability to Wire-Speed Enforcement

This document traces the single engineering thread that runs from "a client-side reflector can help with observability" to "a SPIFFE Firewall that stops an attack before the application decides."

---

## The Problem

Agents make MCP tool calls, API requests, and service-to-service connections that no existing system records completely. A proxy-based approach adds latency and requires agent modification. A sidecar injects operational complexity. SIEM logs arrive after the fact — if they arrive at all.

The gap: **nobody sees the TLS handshake at the kernel, before the application makes a decision.**

That gap is where identity lives.

---

## The Kernel Insight

Every TLS connection calls `d2i_X509` inside the TLS library. That function parses the peer certificate from DER bytes — and it fires *before the application's callback sees the cert*. The SPIFFE URI SAN is in those bytes.

eBPF uprobes let you attach to that function in any process, on any node, without modifying the application. This is the observation point no proxy can match: kernel-level, per-process, zero application modification, zero data plane latency.

```
TLS library (libssl/libcrypto)
  d2i_X509() ←── uprobe fires HERE
    │
    └── cert DER bytes → SPIFFE URI SAN extracted
          before the application callback runs
```

This insight drove every subsequent architecture decision.

---

## Stage 1: Crawl — Observe

**Goal:** A CISO watching the session map sees every identity-bearing connection in real time.

### What Was Built

```
┌─────────────────────────────────────────┐
│  Node (reflector DaemonSet)             │
│                                         │
│  kprobes: tcp_connect, inet_csk_accept  │
│  uprobes: SSL_write, SSL_read           │
│       │                                 │
│       ▼                                 │
│  Extract:                               │
│    5-tuple (src IP, dst IP, ports, PID) │
│    SPIFFE ID (from TLS cert SAN)        │
│    JWT claims (from Authorization hdr)  │
│    MCP tool name (from JSON-RPC body)   │
│    OTel OTLP signals (passthrough)      │
│       │                                 │
│       ▼                                 │
│  gRPC stream ───────────────────────────┼──► reflector-map sidecar
└─────────────────────────────────────────┘         │
                                                     ▼
                                            GET /sessions
                                            GET /stats
                                            GET /metrics
```

### Key Decisions

| Decision | Why |
|---|---|
| **Go + cilium/ebpf** ([ADR-001](../adr/ADR-001-go-cilium-ebpf.md)) | Pure Go toolchain, no CGo, proven at scale (Cilium, Tetragon) |
| **Reflect-only crawl scope** ([ADR-002](../adr/ADR-002-reflect-only-crawl-scope.md)) | Observe before enforcing. Earn trust with evidence. |
| **Standalone sidecar over NHI-PAM-Tool** ([ADR-003](../adr/ADR-003-grpc-stream-standalone-sidecar.md)) | NHI-PAM-Tool has no inbound telemetry API. The sidecar is the right target. |
| **uprobe on TLS library** ([ADR-004](../adr/ADR-004-spiffe-extraction-uprobe-tls.md)) | Cilium does not extract SPIFFE in eBPF — it uses numeric label identity. The uprobe is novel and necessary. |

### What Crawl Delivers

The session map is a live, queryable identity record for every connection on the node. No proxy. No sidecar injection into workloads. No agent modification. The query is `GET /sessions?identity=spiffe://prod/...` and you see: who connected to what, when, how many bytes, which JWT was presented.

---

## Stage 2: Walk — The SPIFFE Firewall

**Goal:** Block a connection from an untrusted trust domain before the application processes it. Zero latency. Zero application modification. Wire speed.

### The Critical Engineering Problem

SPIFFE identity lives in the TLS certificate. But `SSL_write` and `SSL_read` only capture application data — not the certificate bytes. The uprobe fires on `d2i_X509`, which parses the *peer* certificate during the handshake.

The challenge: which `libcrypto.so.3` instance in which process? A DaemonSet running as root can't blindly attach to every TLS library in every container. It needs to find the right library, in the right process, and attach only to that.

**Solution (Sprint 6):** Scan `/proc/<pid>/maps` for every running process on the node. Find the mapped path for `libcrypto.so`. Resolve symlinks to get the real path. Attach the uprobe to that specific library instance. When a new process starts (polled via /proc), attach to its library too.

This is the per-process libcrypto attachment problem, solved without modifying kernel code, without a sidecar in the workload pod, and without kernel version dependencies.

### ADR-006: The d2i_X509 Uprobe

Before committing to this approach, an integration test was built and run:

```bash
make test-adr006
# → Docker container, privileged, pid=host
# → Generates SPIFFE SVID (EC P-256, URI SAN)
# → Starts openssl s_server with mTLS
# → Loads cert_hook eBPF program, attaches to libcrypto.so.3
# → Triggers openssl s_client handshakes
# → Validates: SPIFFE ID captured from DER bytes before app sees cert
# → Result: PASS
```

The integration test answered: **yes, `d2i_X509` fires in the handshake path, before the server application callback, and the DER bytes contain the peer SPIFFE ID.** This is the foundation of the walk stage.

### What Walk Adds

```
TLS handshake begins
  → d2i_X509 uprobe fires (kernel, per-process library attachment)
    → SPIFFE URI SAN extracted from DER bytes
      → OPA evaluates: "evil.corp" ∉ trusted_domains
        → POLICY_VIOLATION event generated
          → TC deny map entry inserted for this 5-tuple

The kernel drops subsequent packets. The application never decides.
```

| Layer | What Happens | Where |
|---|---|---|
| uprobe | `d2i_X509` fires, DER bytes captured, SPIFFE SAN parsed | kernel / per-process |
| OPA | `trusted_domains` rule evaluated in-process | userspace, per-event |
| TC | Deny map entry inserted; ingress/egress packets dropped | kernel, wire speed |
| gRPC | POLICY_VIOLATION event streamed to reflector-map | userspace stream |
| Session map | Violation recorded with SPIFFE ID + 5-tuple + timestamp | reflector-map sidecar |

### The Evil.Corp Demo

The walk-stage demo deploys:
- A test server with a legitimate SPIFFE cert (`spiffe://prod.local/...`)
- A test client with an `evil.corp` cert (`spiffe://evil.corp/...`)
- The reflector DaemonSet with default OPA policy (`trusted_domains = ["prod.local"]`)

Result: 3 handshake attempts → 3 `POLICY_VIOLATION` events → 3 TC deny map entries → connection blocked at the kernel. The server application log shows zero accepted connections.

```
| Claim                              | Evidence                                            |
|------------------------------------|-----------------------------------------------------|
| Kernel-level SPIFFE extraction     | 3/3 handshakes intercepted, correct SPIFFE ID       |
| OPA policy at kernel boundary      | untrusted-trust-domain rule fired per handshake     |
| Per-handshake detection            | One violation per handshake, PID tracked            |
| Zero application modification      | Vanilla TLS workloads — no SDK, no sidecar          |
```

---

## Stage 3: Run — Intelligence at the Kernel

Walk proves the observation and enforcement primitives. Run adds intelligence on top of the stream those primitives produce.

### Behavioral Fingerprinting (Shipped — Sprint 14)

The session map now builds per-identity behavioral profiles:

- **5-minute rolling windows**, max 12 (1 hour of history)
- **Deviation dimensions:** connection rate (z-score), destination novelty (Jaccard), byte volume (z-score)
- **Composite score** `[0.0, 1.0]`: 0 = baseline, 1 = maximum anomaly

Query: `GET /profile?identity=spiffe://prod/ns/payments/sa/processor`

```json
{
  "spiffe_id": "spiffe://prod/ns/payments/sa/processor",
  "deviation": {
    "score": 0.72,
    "connection_score": 0.85,
    "novel_dests": ["s3.amazonaws.com:443"],
    "anomalies": ["connection rate 8× baseline"]
  }
}
```

The SPIFFE Firewall handles **known-bad** (wrong trust domain, OPA deny). Behavioral fingerprinting handles **unknown-bad** — the zero-day, the compromised credential, the agent that went rogue. No policy rule catches "this workload suddenly exfiltrating 4GB at 3am." Behavioral deviation does.

### Cert Rotation Anomaly Detection (Shipped — Sprint 11)

Every `d2i_X509` call is tracked. The reflector learns the expected rotation interval for each SPIFFE path (minimum 3 observations to establish baseline) and classifies each rotation:

| Class | Meaning | Signal |
|---|---|---|
| `CERT_ROTATION_NORMAL` | Scheduled, expected interval, same issuer | Background event |
| `CERT_ROTATION_EARLY` | Rotated before 75% of expected lifetime | Possible credential compromise |
| `CERT_ROTATION_ISSUER` | Issuer fingerprint changed | Possible CA compromise |
| `CERT_ROTATION_DOMAIN` | Trust domain changed on same workload path | Possible identity hijack |

These events appear in the same gRPC stream and session map as connection events. No separate pipeline. No additional instrumentation.

### Attestation API (Shipped — Sprint 10)

Any external policy engine can ask: "Is this connection's SPIFFE ID consistent with what the kernel observed?"

```
GET /attest?pid=<pid>&src=<ip:port>&dst=<ip:port>
→ { "spiffe_id": "...", "confidence": "kernel", "observed_at": "..." }
```

`confidence: "kernel"` — the SPIFFE ID was extracted from the TLS certificate at the kernel boundary, via `d2i_X509` uprobe, before the application saw the cert.

`confidence: "jwt-only"` — no kernel-level cert observation for this connection. The API is fail-open: it never returns 500, and a miss does not block the caller.

This makes the reflector a **kernel identity oracle** — a Policy Information Point (PIP) for Vault OIDC, OPA, SIEM correlation, and any system that needs to verify "was this connection's identity actually at the kernel, or just claimed in a header?"

### Looking Ahead

| Capability | Stage | What It Unlocks |
|---|---|---|
| Multi-cluster TC enforcement | Walk+ (Sprint 13) | Cross-node traffic enforcement on physical NIC (closes CNI bridge gap) |
| Kafka Wire Protocol visibility | Run | SPIFFE + topic name + producer/consumer role — identity record no Kafka broker produces |
| SSF cross-cluster federation | Run | Security events gossiped across clusters; compromised identity quarantined cluster-wide |
| ML anomaly scoring + SOAR | Run | Supervised model on rotation/behavioral features; SOAR recommendation → human confirms → TC deny |

---

## Architecture Principles

**Observe at the kernel. Correlate in the session map. Surface to the audit layer.**

Three principles govern every decision:

1. **Zero application modification.** Agents are unmodified. The kernel is the observation point, not a sidecar or SDK.

2. **Fewer parts.** Every dependency justifies its existence (ADR-001 principle). Seven Go dependencies for the entire system.

3. **Enforcement is a consequence, not a design.** The reflector observes and streams. Policy says what's allowed. TC executes the deny. These are three separate, composable layers.

---

## Component Map

```
cmd/
  reflector/          eBPF DaemonSet — loads programs, streams events
  reflector-map/      Session map sidecar — receives stream, serves HTTP API
  test-workload/      Traffic generator — mTLS + JWT + MCP tool calls
internal/
  ebpf/               eBPF program loading + /proc/maps scanner
  extract/            Identity extraction: SPIFFE, JWT, MCP, OTLP, NHI-PAM-Tool session tokens
  policy/             OPA evaluator (in-process, loaded from ConfigMap)
  session/            Session map, profile tracker, rotation tracker
  stream/             gRPC client (reflector) + server (sidecar)
  forward/            OTLP re-forward to any collector
  metrics/            Prometheus metrics + health endpoints
api/v1/               Protobuf definitions for the gRPC stream
policy/               default.rego — OPA policy (trusted_domains rule)
deploy/
  daemonset/          Kubernetes DaemonSet + SCC manifests
  sidecar/            Kubernetes Deployment + Service + ServiceMonitor
  demo/               Evil.corp demo workloads
```
