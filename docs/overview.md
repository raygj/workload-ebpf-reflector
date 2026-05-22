# Visual Overview

---

## What It Is

```
  Linux Kernel
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │  tcp_connect  inet_csk_accept  SSL_write  SSL_read  d2i_X509               │
  └──────────────────────────────┬──────────────────────────────────────────────┘
                                 │ eBPF hooks (kprobes + uprobes)
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                     workload-ebpf-reflector  (DaemonSet, one pod per node) │
  │                                                                             │
  │  ┌─────────────────────────────────────────────────────────────────────┐   │
  │  │  Observe                                                            │   │
  │  │                                                                     │   │
  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
  │  │  │   SPIFFE ID  │  │  JWT claims  │  │  MCP tool    │             │   │
  │  │  │  (d2i_X509   │  │  (Auth hdr)  │  │  name        │             │   │
  │  │  │   uprobe)    │  │              │  │  (JSON-RPC)  │             │   │
  │  │  └──────────────┘  └──────────────┘  └──────────────┘             │   │
  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
  │  │  │  OTLP signals│  │  NHI-PAM-Tool│  │  5-tuple     │             │   │
  │  │  │  (re-forward)│  │  session tkn │  │  + PID       │             │   │
  │  │  └──────────────┘  └──────────────┘  └──────────────┘             │   │
  │  └─────────────────────────────────────────────────────────────────────┘   │
  │                                    │                                        │
  │            ┌───────────────────────┼───────────────────────┐               │
  │            ▼                       ▼                       ▼               │
  │  ┌─────────────────┐  ┌────────────────────┐  ┌─────────────────────┐     │
  │  │    Enforce      │  │     Fingerprint     │  │   Track             │     │
  │  │                 │  │                     │  │                     │     │
  │  │  OPA policy     │  │  Per-identity       │  │  Cert rotation      │     │
  │  │  evaluation     │  │  behavioral         │  │  state machine      │     │
  │  │       │         │  │  profiles           │  │  NORMAL / EARLY /   │     │
  │  │       ▼         │  │  (conn rate,        │  │  ISSUER / DOMAIN    │     │
  │  │  TC deny map    │  │  dest novelty,      │  │                     │     │
  │  │  (wire speed)   │  │  byte volume)       │  │                     │     │
  │  └─────────────────┘  └────────────────────┘  └─────────────────────┘     │
  │                                    │                                        │
  │                                    ▼                                        │
  │                         ┌─────────────────────┐                            │
  │                         │   gRPC event stream │                            │
  │                         └─────────────────────┘                            │
  └─────────────────────────────────────┬───────────────────────────────────────┘
                                        │
                                        ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         reflector-map  (sidecar)                           │
  │                                                                             │
  │  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────────┐ │
  │  │  Session Map    │  │  Attestation    │  │  Behavioral Profile        │ │
  │  │                 │  │  API            │  │  API                       │ │
  │  │  GET /sessions  │  │  GET /attest    │  │  GET /profile              │ │
  │  │  GET /stats     │  │  confidence:    │  │  deviation score           │ │
  │  │  GET /metrics   │  │  kernel|jwt     │  │  novel destinations        │ │
  │  └─────────────────┘  └─────────────────┘  └────────────────────────────┘ │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Integration Patterns

```
                         ┌────────────────────────────────────┐
                         │          reflector-map             │
                         │       Session Map Sidecar          │
                         └──────┬──────────┬──────────┬───────┘
                                │          │          │
              ┌─────────────────┘          │          └──────────────────┐
              │                            │                             │
              ▼                            ▼                             ▼
  ┌───────────────────────┐   ┌────────────────────────┐   ┌────────────────────────┐
  │  Policy Decision      │   │  Audit & Observability  │   │  Identity Verification │
  │  Point (PDP)          │   │                         │   │                        │
  │                       │   │  ┌──────────────────┐  │   │  ┌──────────────────┐  │
  │  ┌─────────────────┐  │   │  │   SIEM / SOC     │  │   │  │  Vault OIDC OBO  │  │
  │  │  OPA external   │  │   │  │                  │  │   │  │  secrets engine  │  │
  │  │  data source    │  │   │  │  GET /sessions   │  │   │  │                  │  │
  │  │                 │  │   │  │  correlate with  │  │   │  │  GET /attest     │  │
  │  │  GET /attest    │  │   │  │  network logs    │  │   │  │  confirm kernel  │  │
  │  │  enrich policy  │  │   │  └──────────────────┘  │   │  │  identity before │  │
  │  │  decisions      │  │   │                         │   │  │  issuing secret  │  │
  │  └─────────────────┘  │   │  ┌──────────────────┐  │   │  └──────────────────┘  │
  │                       │   │  │  Prometheus /    │  │   │                        │
  │  ┌─────────────────┐  │   │  │  Grafana /Perses │  │   │  ┌──────────────────┐  │
  │  │  Admission      │  │   │  │                  │  │   │  │  Custom policy   │  │
  │  │  webhook        │  │   │  │  GET /metrics    │  │   │  │  engine          │  │
  │  │                 │  │   │  └──────────────────┘  │   │  │                  │  │
  │  │  verify SPIFFE  │  │   │                         │   │  │  GET /attest     │  │
  │  │  at admission   │  │   │  ┌──────────────────┐  │   │  │  as PIP input    │  │
  │  └─────────────────┘  │   │  │  Anomaly alerts  │  │   │  └──────────────────┘  │
  └───────────────────────┘   │  │                  │  │   └────────────────────────┘
                              │  │  GET /profile    │  │
              ┌───────────────┘  │  score > 0.7     │  └──────────────────┐
              │                  └──────────────────┘                     │
              ▼                                                            ▼
  ┌───────────────────────┐                                ┌──────────────────────────┐
  │  Event Stream         │                                │  Protocol Visibility     │
  │  Consumers            │                                │                          │
  │                       │                                │  TLS + Kafka port 9093   │
  │  ┌─────────────────┐  │                                │                          │
  │  │  ML anomaly     │  │                                │  ┌──────────────────┐   │
  │  │  scorer         │  │                                │  │  Kafka Wire      │   │
  │  │                 │  │                                │  │  Protocol        │   │
  │  │  gRPC stream    │  │                                │  │  parser          │   │
  │  │  → feature vec  │  │                                │  │  (roadmap)       │   │
  │  │  → confidence   │  │                                │  │                  │   │
  │  └─────────────────┘  │                                │  │  SPIFFE ID +     │   │
  │                       │                                │  │  topic name +    │   │
  │  ┌─────────────────┐  │                                │  │  client_id +     │   │
  │  │  SOAR platform  │  │                                │  │  produce|fetch   │   │
  │  │                 │  │                                │  └──────────────────┘   │
  │  │  CERT_ROTATION  │  │                                └──────────────────────────┘
  │  │  POLICY_VIOLATION│ │
  │  │  → playbook     │  │
  │  └─────────────────┘  │
  └───────────────────────┘
```

---

## Enforcement Flow

```
  Workload A                      Kernel                       Workload B
  (evil.corp cert)                                             (prod.local server)
       │                             │                               │
       │──── TCP SYN ───────────────►│                               │
       │                             │                               │
       │◄─── TCP SYN-ACK ────────────│                               │
       │                             │                               │
       │──── TLS ClientHello ───────►│                               │
       │                             │  d2i_X509 uprobe fires        │
       │                             │  DER bytes captured           │
       │                             │  SPIFFE SAN extracted:        │
       │                             │  "spiffe://evil.corp/..."     │
       │                             │           │                   │
       │                             │           ▼                   │
       │                             │  OPA eval: evil.corp          │
       │                             │  ∉ trusted_domains            │
       │                             │  → POLICY_VIOLATION           │
       │                             │           │                   │
       │                             │           ▼                   │
       │                             │  TC deny map ← 5-tuple        │
       │                             │  inserted                     │
       │                             │                               │
       │◄─── DROP (no response) ─────│                               │
       │                                                             │
       │                             (Workload B never sees the connection)
```
