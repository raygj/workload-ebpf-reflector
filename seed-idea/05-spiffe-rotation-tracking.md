# Seed: Cert Rotation as a First-Class Observable

**Stage:** Run
**Maturity:** [EXPERIMENTAL]
**Theme:** SPIFFE cert rotation events are anomaly signals hiding in plain sight

---

## The Observation

SPIFFE SVIDs rotate on a schedule. cert-manager issues short-lived certs (24h by default, often configured to 1h in high-security environments). Every rotation triggers a `d2i_X509` call — which the reflector already intercepts.

Normal rotation: cert rotates every N hours, same trust domain, same path, new serial number.  
Abnormal rotation: cert rotates unexpectedly, trust domain changes, path changes, or the new cert is issued by an unexpected CA.

The reflector sees all of this. No other system does — not at the kernel, not before the application processes the cert.

## The Idea

**Rotation tracking per SPIFFE path.** For each `spiffe://<trust-domain>/ns/<ns>/sa/<sa>`, track:
- Last observed cert serial number
- Last observed cert expiry
- Expected rotation interval (learned from history)
- Issuer fingerprint

**Rotation anomaly signals:**
- Early rotation (cert changed before expected expiry) → possible credential compromise or forced revocation
- Trust domain change on same workload path → possible identity hijack or misconfiguration
- Unexpected issuer fingerprint → possible CA compromise or out-of-band cert issuance
- Rotation frequency spike → possible SVID replay or cert stuffing attack
- Rotation from a new node (same SPIFFE ID seen on unexpected node) → possible lateral movement

**Event types to add to the stream:**
```
CERT_ROTATION_NORMAL   — scheduled, expected, same issuer
CERT_ROTATION_EARLY    — before expected expiry [ANOMALY]
CERT_ROTATION_ISSUER   — issuer fingerprint changed [ANOMALY]
CERT_ROTATION_DOMAIN   — trust domain changed [ANOMALY]
```

## What's Already True

The reflector already captures every `d2i_X509` call. The DER bytes are available. Serial number, expiry, and issuer fingerprint are all parseable from the DER — `internal/extract/spiffe.go` already does the heavy lifting. This feature is mostly a state machine layered over what's already flowing.

## The Subtle Value

SPIFFE rotation tracking catches things that OPA policy cannot. OPA knows: "is this SPIFFE ID allowed?" It doesn't know: "did this SPIFFE ID just rotate 3 hours early on a node where it's never been seen?" That's a behavioral signal, not a policy signal. It's the difference between a firewall rule and an IDS.

## First Principles Questions

- **Where does rotation state live?** In-memory per-reflector-instance is fast but loses state on restart. The session map (reflector-map sidecar) is the right place — it already tracks identity events. Extend the session map with a cert history per SPIFFE path.
- **How do you learn the expected rotation interval?** First N observations build the baseline. After that, deviations are anomalies. N=3 is probably enough for a 24h cert (3 days of data).
- **What's the TTL on cert history?** Keep the last K certs per SPIFFE path. K=10 is probably fine. Beyond that, the history is too stale to be useful.
- **False positives.** A legitimate cert rotation will always look "early" if the workload restarts and the old cert hasn't expired. Filter by: is this the same node? Is this the same PID? Did a restart event precede it?

## Connections

- Requires: cert DER parsing (done in extract/spiffe.go), session map (done)
- Feeds: behavioral fingerprinting (seed-01) — rotation anomalies are anomaly features
- Feeds: SSF gossip (seed-02) — cert rotation anomalies are worth gossiping cross-cluster
- ADR needed: cert history data model, anomaly thresholds, false-positive suppression strategy
