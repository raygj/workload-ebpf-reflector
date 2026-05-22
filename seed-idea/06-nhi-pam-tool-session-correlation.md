# Seed: NHI-PAM-Tool Session Correlation

**Stage:** Run
**Maturity:** [VISION]
**Theme:** Correlate reflector identity observations with NHI-PAM-Tool session tokens

---

## The Problem

NHI-PAM-Tool brokers access to targets. It issues a session token, the agent uses it to connect, NHI-PAM-Tool records the session. But NHI-PAM-Tool's session record says: "session started at T, target vault:8200, credentials from Vault dynamic secrets." It does not say: which SPIFFE ID was in the TLS handshake. It does not say: what JWT was sent in the Authorization header. It does not say: which MCP tools were called during this session.

The reflector sees all of that. NHI-PAM-Tool sees the session NHI-PAM-Tool (pun intended). The gap between them is the gap in the audit trail.

## The Idea

**Session token as a correlation key.** When an agent connects through NHI-PAM-Tool to a target, the session token appears in the HTTP headers (as `Authorization: Bearer <NHI-PAM-Tool-session-token>` or in the mTLS client cert SAN). The reflector's TLS hook already captures HTTP headers. The reflector's cert hook captures the client cert.

Extract the NHI-PAM-Tool session token → join with SPIFFE ID + MCP tool calls → produce a correlated audit record:

```
NHI-PAM-Tool session: sess_01abc...
  SPIFFE ID:     spiffe://prod/ns/agents/sa/deploy-bot
  Connected at:  2026-05-04T01:22:25Z
  Target:        vault:8200
  JWT subject:   deploy-bot@ci.example.com  
  MCP tools:     secrets/read, secrets/write
  Bytes tx/rx:   14,200 / 8,400
  Policy:        ALLOW (trusted domain, authorized tools)
```

This is the audit record a CISO actually wants. Not "NHI-PAM-Tool says a session happened." Not "SIEM says some bytes moved." A correlated, identity-rich record with zero application modification.

## Why This Is Architecturally Interesting

NHI-PAM-Tool has no inbound telemetry API (ADR-003 finding). You cannot push identity metadata into NHI-PAM-Tool. But you CAN correlate externally — the session token is observable on the wire. The reflector is a passive observer. The correlation happens in the session map.

This is the pattern: **observe at the kernel, correlate in the session map, surface to the audit layer.** The agent doesn't know. NHI-PAM-Tool doesn't know. The audit record is richer than either system could produce alone.

## First Principles Questions

- **Session token format.** NHI-PAM-Tool session tokens are opaque UUIDs by default. They're sent as Bearer tokens in HTTP. The reflector's JWT extractor already scans Authorization headers — extend it to detect NHI-PAM-Tool token format.
- **Correlation latency.** The reflector sees the token, the NHI-PAM-Tool control plane has the session record. Correlation requires querying the NHI-PAM-Tool API. What's the right timing? At connection time (immediately) or at session close (full picture)?
- **NHI-PAM-Tool API access.** The reflector would need a NHI-PAM-Tool API token to look up session records. That's a new dependency and a new trust relationship. Design carefully — the reflector's own SPIFFE ID is its credential.
- **Privacy.** Session token correlation reveals which agents are connecting to which targets. That's the point. But it also means the reflector has access to sensitive access patterns. Key management and access control on the session map become more important.

## The Minimal Version

Before building the full correlation pipeline: extract NHI-PAM-Tool session tokens from captured HTTP headers and add them as a field in the session map. No NHI-PAM-Tool API call needed. Just: "this SPIFFE ID connection had this session token in its headers." Let the operator join that with NHI-PAM-Tool audit logs manually. That's a one-sprint feature that immediately adds value.

## Connections

- Requires: JWT/header extractor (done), session map (done)
- New dependency: NHI-PAM-Tool API client (optional, for full correlation)
- Feeds: audit log enrichment, SIEM integration
- ADR needed: NHI-PAM-Tool API access model, session token extraction approach, privacy controls
