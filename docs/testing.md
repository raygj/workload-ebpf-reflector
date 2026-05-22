# Testing

## Summary

| Type | Count | Coverage | Race Detector | Result |
|---|---|---|---|---|
| Unit | 45 tests across 15 files | 92.7% | ✅ on | All pass |
| Integration | 1 (ADR-006 eBPF uprobe) | — | — | PASS |
| System | 1 (evil.corp SPIFFE Firewall demo) | — | — | 3/3 violations |

---

## Unit Tests

Run with: `go test -race ./...`

### Identity Extraction (`internal/extract/`)

| Test | What It Verifies |
|---|---|
| `TestParseSPIFFEFromDER` | SPIFFE URI SAN extracted correctly from X.509 DER bytes |
| `TestParseSPIFFEFromDERVaultPKI` | SPIFFE extraction works with Vault PKI-issued certs |
| `TestParseSPIFFEFromDERNoSPIFFE` | Non-SPIFFE cert returns nil cleanly |
| `TestParseSPIFFEFromDERInvalidDER` | Malformed DER returns error, no panic |
| `TestParseSPIFFEFromURI` | URI string parsing: trust domain, namespace, service account |
| `TestExtractJWTFromHTTP` | JWT extracted from `Authorization: Bearer` header |
| `TestExtractJWTFromHTTPCaseInsensitive` | Header name matching is case-insensitive |
| `TestDecodeJWTPayload` | Base64url payload decoded, `sub`/`iss` claims parsed |
| `TestDecodeJWTPayloadInvalid` | Malformed JWT returns error, no panic |
| `TestExtractMCPToolFromHTTPToolsCall` | MCP `tools/call` JSON-RPC method + tool name extracted |
| `TestExtractMCPToolFromHTTPDirectMethod` | Direct method name extracted when not wrapped |
| `TestExtractMCPToolFromHTTPNotJSON` | Non-JSON body returns nil, no panic |
| `TestParseMCPRequestToolsCallWithName` | Tool name correctly parsed from `tools/call` params |
| `TestExtractOTLPFromTLS_TracesHTTP` | OTel trace export over HTTP/JSON recognized |
| `TestExtractOTLPFromTLS_GRPCTraces` | OTel trace export over gRPC recognized |
| `TestExtractOTLPFromTLS_MultipleBatches` | Multiple OTLP payloads in single TLS write handled |
| `TestExtractOTLPFromTLS_Truncated` | Truncated payload (>4096 bytes) handled gracefully |
| `TestExtractBoundaryAuthToken` | `at_` prefixed token identified as auth token type |
| `TestExtractBoundarySessionToken` | `s_` prefixed token identified as session token type |
| `TestExtractBoundaryOpaqueUUID` | Hex-and-dash UUID format identified as opaque token |
| `TestExtractBoundaryTokenNotAJWT` | JWT (3-part dot-separated) not misclassified as NHI-PAM-Tool session token |
| `TestParseTLSDataEvent` | TLS data event header parsed: PID, data length, content |
| `TestExtractIdentitiesFromTLSWithJWT` | JWT extracted from TLS payload via combined extractor |
| `TestExtractIdentitiesFromTLSWithMCP` | MCP tool name extracted via combined extractor |
| `TestExtractIdentitiesFromTLSWithBoth` | JWT + MCP extracted together, no interference |

### eBPF / Process Scanner (`internal/ebpf/`)

| Test | What It Verifies |
|---|---|
| `TestScanMapsFileExtractsLibCrypto` | `/proc/<pid>/maps` parsed, libcrypto.so path extracted |
| `TestScanMapsFileSkipsNonLibCrypto` | Non-crypto mapped libs ignored |
| `TestScanMapsFileMissingFile` | Missing `/proc/maps` returns error, no panic |
| `TestScanProcForLibCryptoDoesNotError` | Live scan of `/proc` on the host completes without error |

### OPA Policy (`internal/policy/`)

| Test | What It Verifies |
|---|---|
| `TestDefaultPolicyAllowsKnownTrustDomain` | SPIFFE ID in `trusted_domains` → ALLOW |
| `TestDefaultPolicyDeniesUnknownTrustDomain` | SPIFFE ID not in `trusted_domains` → DENY + POLICY_VIOLATION |
| `TestDefaultPolicyDeniesEmptySPIFFEID` | Empty SPIFFE ID → DENY |
| `TestCustomPolicyFileOverridesDefault` | Custom policy ConfigMap overrides built-in default |
| `TestMissingPolicyFileFallsBackToDefault` | Missing policy file falls back to default, no crash |

### Session Map (`internal/session/`)

| Test | What It Verifies |
|---|---|
| `TestSessionMapConnectionOpen` | `CONNECTION_OPEN` event creates a session entry |
| `TestSessionMapConnectionClose` | `CONNECTION_CLOSE` marks entry as closed |
| `TestSessionMapQueryByIdentity` | `/sessions?identity=spiffe://...` filters correctly |
| `TestSessionMapQueryByDestination` | `/sessions?dest=host:port` filters correctly |
| `TestSessionMapDataExchangeUpdatesBytes` | `DATA_EXCHANGE` increments tx/rx byte counters |
| `TestSessionMapSweep` | Expired entries (> staleTTL) marked stale |
| `TestSessionMapSweepEvictsStaleEntries` | Stale entries evicted after 2× staleTTL (memory leak fix) |
| `TestSessionMapStats` | `/stats` returns correct active/stale/closed counts |
| `TestSessionMapOTELEvent` | OTLP capture events recorded in session map |
| `TestAPIGetAllSessions` | `GET /sessions` returns all entries as JSON |
| `TestAPIStats` | `GET /stats` returns counts JSON |
| `TestAPIAttestKernelConfidence` | Known connection → `confidence: "kernel"` |
| `TestAPIAttestMissReturnsJWTOnly` | Unknown connection → `confidence: "jwt-only"` (fail-open) |
| `TestAPIAttestExpiredReturnsJWTOnly` | Connection older than AttestationTTL → `confidence: "jwt-only"` |

### Behavioral Fingerprinting (`internal/session/profile_test.go`)

| Test | What It Verifies |
|---|---|
| `TestProfileTrackerFirstObservationNoDeviation` | Single observation: no deviation score (insufficient baseline) |
| `TestProfileTrackerNormalBehaviorLowDeviation` | Consistent behavior over baseline windows: score < 0.1 |
| `TestProfileTrackerConnectionSpike` | 20× connection rate burst: score > 0.3, connection_score > 0.3 |
| `TestProfileTrackerNovelDestination` | New destination not in baseline: dest_score > 0, novel_dests populated |
| `TestProfileTrackerWindowHistoryCapped` | Window history capped at max (12), no unbounded growth |
| `TestProfileAPIEndpoint` | `GET /profile?identity=...` returns 404 for unknown, 400 for missing param |

### Cert Rotation Tracking (`internal/session/rotation_test.go`)

| Test | What It Verifies |
|---|---|
| `TestRotationTrackerFirstObservationIsNotARotation` | First cert seen: `RotationFirstSeen`, not an anomaly |
| `TestRotationTrackerSameCertIsNotARotation` | Same serial seen again: not classified as a rotation |
| `TestRotationTrackerNormalScheduledRotation` | Cert rotates on expected schedule: `RotationNormal` |
| `TestRotationTrackerEarlyRotation` | Cert rotates before 75% of expected lifetime: `RotationEarly` |
| `TestRotationTrackerIssuerChange` | New cert has different issuer fingerprint: `RotationIssuerChange` |
| `TestRotationTrackerDomainChange` | Trust domain changes on same workload path: `RotationDomainChange` |
| `TestRotationTrackerHistoryCappedAtK` | History capped at K=10 per SPIFFE path |
| `TestRotationTrackerLearnedIntervalNormalAfterBaseline` | After 3 observations, normal rotation classified correctly |

### gRPC Stream (`internal/stream/`)

| Test | What It Verifies |
|---|---|
| `TestStreamClientServerIntegration` | Client sends events; server receives, decodes, and acknowledges them end-to-end |

### OTLP Forwarder (`internal/forward/`)

| Test | What It Verifies |
|---|---|
| `TestForwarder_ForwardTraces` | OTLP trace payload forwarded to target collector |
| `TestForwarder_SkipsTruncated` | Truncated payloads skipped, not forwarded |
| `TestForwarder_HTTPErrorReturnsError` | Non-200 response from collector surfaces as error |
| `TestForwarder_MetricsPath` | Metrics payload routed to `/v1/metrics` path |

---

## System Test: SPIFFE Firewall Demo

**What it tests:** End-to-end: eBPF uprobe → OPA policy evaluation → TC enforcement on a live Kubernetes cluster.

**Cluster:** Talos Linux on commodity hardware (single-node for walk demo; multi-node with cross-node TC enforcement in Sprint 13).

**Run:**
```bash
kubectl apply -f deploy/demo/evil-demo.yaml
kubectl logs -n ebpf-reflector -l app=reflector -f | grep POLICY_VIOLATION
```

**What it does:**
1. Deploys test server with `spiffe://prod.local/...` cert
2. Deploys test client with `spiffe://evil.corp/...` cert (untrusted trust domain)
3. Client attempts 3 TLS handshakes to server

**Pass condition:**

| Check | Expected | Actual |
|---|---|---|
| POLICY_VIOLATION events | 3 (one per handshake) | 3 ✅ |
| SPIFFE ID extracted | `spiffe://evil.corp/ns/test/sa/evil-client` | Correct ✅ |
| OPA rule fired | `untrusted-trust-domain` | ✅ |
| TC deny map entries | 3 (per-flow drop) | ✅ |
| Server application log | 0 accepted connections | ✅ |

**Result:** PASS — The SPIFFE Firewall blocks the connection before the application processes it.

---

## Known Test Gaps

| Gap | Risk | Plan |
|---|---|---|
| Multi-kernel testing | uprobe behavior varies across kernel versions; tested on one kernel | Kernel matrix in pilot-ready milestone |
| DaemonSet restart behavior | Session map, behavioral baselines, and TC deny map behavior on pod restart unknown | Sprint 15 candidate |
| OpenSSL version matrix | Offset hardcoding (ADR-006) breaks on different OpenSSL versions | Dynamic resolution via `/proc/maps` symbol lookup in walk+ |
| Load testing | 2Mi memory at lab scale; behavior at 10K connections/sec untested | Pre-pilot requirement |
