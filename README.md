# workload-ebpf-reflector

![CI](https://github.com/raygj/workload-ebpf-reflector/actions/workflows/ci.yml/badge.svg)

Your agents are making MCP tool calls, API requests, and service-to-service connections that nobody sees. No proxy intercepts them. No session broker records them. Your SIEM gets logs after the target system processes the request — if it logs at all. You have zero real-time visibility into machine-to-machine identity behavior.

## What This Is

An eBPF-based identity observation and enforcement layer deployed as a DaemonSet on Kubernetes. It intercepts TLS handshakes at the kernel, extracts SPIFFE identity from the certificate, evaluates OPA policy, and blocks untrusted trust domains — all before the application processes the connection. Zero data plane latency. No agent modification. No payload decryption.

> **The Reflector intercepts TLS handshakes at the kernel, extracts SPIFFE identity from the certificate, evaluates OPA policy, and blocks untrusted trust domains — all before the application processes the connection. Zero application modification. Zero user-space proxy. Wire speed.**

```
TLS handshake begins
  → d2i_X509 uprobe fires (kernel)
    → SPIFFE URI SAN extracted from cert
      → OPA evaluates: "evil.corp" ∉ trusted_domains
        → POLICY VIOLATION logged
          → Deny map entry inserted for TC drop

The application never decides. The kernel decides.
```

| Claim | Evidence |
|---|---|
| Kernel-level SPIFFE extraction | 3/3 handshakes intercepted, correct SPIFFE ID extracted |
| OPA policy at the kernel boundary | `untrusted-trust-domain` rule fired per handshake |
| Per-handshake detection | One violation per handshake, PID tracked |
| Zero application modification | Vanilla TLS workloads — no SDK, no sidecar |

**Stage:** WALK — SPIFFE Firewall. Observe, evaluate, enforce.

## Starfly Fabrics

Reflector is the **sense layer** in the [Starfly Fabrics ecosystem](https://starfly.dev/1.0/docs/ecosystem/) — kernel-level visibility that complements the Starfly identity PEP without touching exchange or revocation.

| Layer | Repo | Role |
|-------|------|------|
| **Reflector** (this repo) | [workload-ebpf-reflector](https://github.com/raygj/workload-ebpf-reflector) | Observe SPIFFE, JWT, MCP at the wire |
| **Starfly** | [project-starfly-fabrics](https://github.com/raygj/project-starfly-fabrics) | Mint WIMSE, enforce delegation, revoke |

Reflector does not mint WIMSE. Starfly does not load eBPF programs. Compose when you want ground-truth platform senses alongside PEP audit.

- [Reflector — ecosystem docs](https://starfly.dev/1.0/docs/ecosystem/reflector/)
- [Credential patterns — SPIFFE / SPIRE](https://starfly.dev/1.0/docs/integrators/credential-patterns/#spiffe--spire)
- [Operations dashboard](https://starfly.dev/1.0/docs/integrators/dashboard/) — NOC view for fabric metrics

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  Node (DaemonSet: reflector)                                    │
│                                                                 │
│  eBPF kprobes  (tcp_connect, inet_csk_accept)                   │
│  eBPF uprobes  (SSL_write, SSL_read, d2i_X509)                  │
│  eBPF TC       (ingress + egress drop at wire speed)            │
│       │                                                         │
│       ▼                                                         │
│  Extract: 5-tuple, SPIFFE, JWT, MCP tool name                   │
│       │                                                         │
│       ▼                                                         │
│  OPA policy eval → POLICY_VIOLATION → TC deny map              │
│       │                                                         │
│       ▼                                                         │
│  Ring buffer → gRPC stream ──────────────────────────────────── │──► reflector-map (sidecar)
│                                                                 │         │
└─────────────────────────────────────────────────────────────────┘         ▼
                                                               Session Map + Violations
                                                               ┌──────────────────┐
                                                               │ GET /sessions    │
                                                               │ GET /stats       │
                                                               │ GET /metrics     │
                                                               │ GET /healthz     │
                                                               └──────────────────┘
```

The reflector sees every identity-bearing connection. Policy violations fire at the kernel boundary. The sidecar maintains a live, queryable session map. The session map is standalone and works on any Kubernetes cluster (OCP, Talos, vanilla K8s).

## Quick Start (Lab)

```bash
make lab-demo     # build images, start Docker Compose, query session map
make lab-down     # teardown
```

Or manually:
```bash
docker compose up -d
curl localhost:9101/sessions | jq    # all observed connections
curl localhost:9101/stats | jq       # active/closed/stale counts
curl localhost:9091/healthz          # sidecar health
curl localhost:9091/metrics          # prometheus metrics
```

## Project Structure

```
cmd/
  reflector/              eBPF DaemonSet binary
  reflector-map/          Session map sidecar binary
  test-workload/          Traffic generator (mTLS + JWT + MCP)
internal/
  ebpf/                   eBPF program loading (kprobes + uprobes)
  extract/                Identity extraction (SPIFFE, JWT, MCP, 5-tuple)
  stream/                 gRPC client/server
  session/                Session map + HTTP query API
  metrics/                Prometheus metrics + health checks
api/v1/                   Protobuf definitions
deploy/
  daemonset/              K8s DaemonSet + SCC manifests
  sidecar/                K8s Deployment + Service + ServiceMonitor
  dashboards/             Perses dashboard (dashboard-as-code)
seed-idea/                Run-stage vision documents (north star, not sprint scope)
adr/                      Architecture Decision Records (8 accepted)
backlog.md                Prioritized product backlog
sprints/                  Sprint review records (0-9, crawl + walk complete)
```

## Architecture Decisions

| ADR | Decision |
|-----|----------|
| [001](adr/ADR-001-go-cilium-ebpf.md) | Go + cilium/ebpf (pure Go, no CGo) |
| [002](adr/ADR-002-reflect-only-crawl-scope.md) | Reflect-only mode as crawl scope |
| [003](adr/ADR-003-grpc-stream-standalone-sidecar.md) | Standalone sidecar (NHI-PAM-Tool has no inbound telemetry API) |
| [004](adr/ADR-004-spiffe-extraction-uprobe-tls.md) | SPIFFE via eBPF uprobe on TLS library |
| [005](adr/ADR-005-observability-prometheus-crawl-otel-walk.md) | Prometheus + Perses for crawl, OTel for walk |
| [006](adr/ADR-006-openssl-offset-strategy.md) | OpenSSL offsets: hardcode crawl, solve walk |
| [007](adr/ADR-007-otlp-capture-reforward.md) | OTLP signal capture + re-forward — raw HTTP, no SDK |
| [008](adr/ADR-008-opa-policy-engine.md) | In-process OPA for policy evaluation; TC/XDP for enforcement |

## Stats

- 45 tests, 92.7% coverage, race detector on
- 0 lint issues, 0 CVEs
- ~3,000 LOC Go + ~300 LOC eBPF C
- 7 dependencies

## Maturity Arc

| Stage | What it does | Status |
|-------|-------------|--------|
| **Crawl** | Observe: kernel-level identity capture, session map, SPIFFE/JWT/MCP/OTLP extraction | ✅ Shipped |
| **Walk** | Reflex: per-process libcrypto attachment, OPA policy gate, TC enforcement at wire speed | ✅ Shipped |
| **Run** | Intelligence: AI on the metadata stream, SSF gossip, multi-cluster | 🔲 Future |

The run-stage vision and architecture seeds are in `seed-idea/`.

## Extending the Reflector

The reflector is designed to be extended at three layers. You do not need to modify the eBPF programs to add new capability — the Go extraction pipeline and policy engine are the right extension points.

### Add an OPA Policy Rule

Edit `policy/default.rego` or mount a custom policy via ConfigMap. The evaluator loads policy from the file path at startup and falls back to the built-in default if the file is absent.

```rego
# Allow only prod and staging trust domains
trusted_domains := {"prod.example.com", "staging.example.com"}

allow {
    spiffe_trust_domain(input.spiffe_id) == trusted_domains[_]
}
```

The OPA input for each event is `{"spiffe_id": "spiffe://...", "src": "ip:port", "dst": "ip:port"}`. A DENY result produces a `POLICY_VIOLATION` event and inserts a TC deny map entry.

### Add a Protocol Extractor

New protocol parsers live in `internal/extract/`. The entry point is `ExtractIdentitiesFromTLS(ev *TLSDataEvent) IdentityResult` in `internal/extract/tls_event.go`. Add your extractor there alongside the existing JWT, MCP, OTLP, and NHI-PAM-Tool session token parsers.

Extractor contract: receive `[]byte` (TLS plaintext, up to 4096 bytes), return a typed result or nil. No blocking, no allocation of unbounded structures.

Current extractors:
- `ExtractJWTFromHTTP` — `Authorization: Bearer <jwt>` headers
- `ExtractMCPToolFromHTTP` — JSON-RPC `tools/call` method + tool name
- `ExtractOTLPFromTLS` — OTLP/HTTP and OTLP/gRPC signal detection
- `ExtractBoundaryTokenFromHTTP` — NHI-PAM-Tool session/auth tokens

### Query the Session Map API

The `reflector-map` sidecar exposes a REST API on port 9101 (default). No authentication in v1 — deploy behind your network policy.

| Endpoint | Description |
|---|---|
| `GET /sessions` | All observed sessions (JSON array) |
| `GET /sessions?identity=spiffe://...` | Filter by SPIFFE ID |
| `GET /sessions?dest=host:port` | Filter by destination |
| `GET /stats` | Active/stale/closed counts |
| `GET /attest?pid=<pid>&src=<ip:port>&dst=<ip:port>` | Kernel identity oracle — returns SPIFFE ID + confidence |
| `GET /profile?identity=spiffe://...` | Behavioral profile + deviation score for an identity |
| `GET /metrics` | Prometheus metrics |
| `GET /healthz` | Health check |

### Use the Attestation API as a Policy Information Point

Any external system can verify: "Was this connection's SPIFFE identity observed at the kernel, or just claimed in a header?"

```bash
curl 'http://reflector-map:9101/attest?pid=1234&src=10.0.0.5:54321&dst=10.0.0.10:8200'
# → {"spiffe_id":"spiffe://prod/ns/payments/sa/processor","confidence":"kernel","observed_at":"..."}
```

`confidence: "kernel"` — the SPIFFE ID was extracted via `d2i_X509` uprobe before the application saw the cert.
`confidence: "jwt-only"` — no kernel observation for this connection. The API never returns 5xx and never blocks the caller.

Integration patterns: Vault OIDC OBO secrets engine, OPA external data, SIEM enrichment, custom admission webhooks.

### Consume the gRPC Stream Directly

The reflector streams `ReflectorEvent` protos from `api/v1/reflector.proto` over a bidirectional gRPC stream. Any consumer that implements the server side of the stream receives every identity event in real time.

```protobuf
service ReflectorStream {
    rpc Stream(stream ReflectorEvent) returns (stream StreamAck);
}
```

Event types: `CONNECTION_OPEN`, `CONNECTION_CLOSE`, `DATA_EXCHANGE`, `POLICY_VIOLATION`, `CERT_ROTATION_*`, `OTLP_CAPTURE`.

---

## Roadmap

The crawl and walk stages are shipped. The run stage adds intelligence on top of the observation and enforcement primitives.

**1. Multi-cluster TC enforcement**
Single-node Kubernetes routes pod-to-pod traffic through the CNI bridge, bypassing `eth0` — TC enforcement never fires. On a multi-node cluster, cross-node traffic traverses the physical NIC and TC fires naturally. The next milestone provisions a two-node cluster on physical hardware and validates that POLICY_VIOLATION + TC drop fires on cross-node traffic at the physical interface.

**2. Kafka Wire Protocol visibility**
The TLS hooks already capture the Kafka Wire Protocol plaintext on port 9093. A parser in `internal/extract/kafka.go` would extract `client_id` and `topic_name` from Produce and Fetch requests — correlated with the SPIFFE ID from the same handshake. This produces an identity record no Kafka broker can: SPIFFE ID + JWT subject + Kafka client ID + topic name + producer/consumer role. SASL/OAUTHBEARER JWT is already captured today with no additional code.

**3. Cert rotation anomaly detection at scale**
Cert rotation tracking is shipped (Sprint 11). The next step is feeding rotation anomaly events (`CERT_ROTATION_EARLY`, `CERT_ROTATION_ISSUER`) into a supervised ML scorer trained on normal rotation patterns. The scorer produces a confidence-weighted recommendation; a SOAR integration surfaces it to an operator for confirmation before TC enforcement fires. The reflector stays thin — the ML layer is a consumer of the gRPC stream, not embedded in the DaemonSet.

**4. SSF cross-cluster event federation**
POLICY_VIOLATION and cert rotation anomaly events are worth sharing across clusters. Security Signal Format (SSF/RFC 8935) provides a standard envelope for signed security events. A lightweight aggregator receives SSF events from all reflector nodes, deduplicates, and maintains a cluster-wide identity event feed. If a compromised SPIFFE identity fires a violation in cluster A, cluster B applies elevated scrutiny before the identity pivots.

**5. Behavioral fingerprinting in production**
Sprint 14 ships the behavioral profile infrastructure: per-identity rolling windows, z-score deviation on connection rate and byte volume, Jaccard novelty on destination set. The run-stage goal is running this on 30+ days of production traffic to validate that the baseline model is stable enough to surface real anomalies without false-positive noise. The SPIFFE Firewall handles known-bad. Behavioral fingerprinting handles unknown-bad — the zero-day, the compromised credential, the agent that went rogue.

---

## License

See [LICENSE](LICENSE).
