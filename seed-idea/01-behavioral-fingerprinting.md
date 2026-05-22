# Seed: Behavioral Fingerprinting — AI on the Identity Metadata Stream

**Stage:** Run
**Maturity:** [VISION]
**Theme:** Turn the metadata stream into an anomaly detector

---

## The Problem

A SPIFFE ID tells you who is connecting. It doesn't tell you whether that behavior is normal.

`spiffe://prod/ns/payments/sa/processor` connecting to `vault:8200` is expected.
`spiffe://prod/ns/payments/sa/processor` connecting to `s3.amazonaws.com:443` at 3am is worth a question.
`spiffe://prod/ns/payments/sa/processor` connecting to `s3.amazonaws.com:443` AND exfiltrating 4GB over the next 20 minutes is an incident.

No firewall rule catches the third case. The IP and port are fine. The SPIFFE ID is valid. The policy says allow. The kernel says allow. But something is wrong — and the only way to know is behavioral.

## What the Reflector Already Produces

Every connection event in the stream carries:
- SPIFFE identity (who)
- 5-tuple (where, when)
- Byte counters (how much)
- JWT claims (acting as)
- MCP tool names (doing what)
- Policy decisions (was it allowed)
- Timestamps at nanosecond precision

This is enough to build a behavioral model per identity. The reflector is already the collection layer. Run stage adds the inference layer.

## The Idea

**Per-identity behavioral baseline.** For each SPIFFE ID observed over N days, build a model of:
- Normal destination IPs/ports
- Normal connection timing (time-of-day, burst pattern)
- Normal byte volumes per session
- Normal MCP tool call sequences
- Normal JWT claim patterns

**Anomaly scoring.** Score each new session against the baseline. Surface high-score sessions to the session map as `ANOMALY` events — same stream, same proto, just a new event type.

**No block by default.** Anomalies are signals, not verdicts. Let OPA decide whether to block based on the score. This keeps the inference layer separate from the enforcement layer.

## First Principles Questions

- **Where does the model live?** In-process (Go, embedded ONNX) keeps it at wire speed. Sidecar (Python) is easier to iterate but adds a hop. Separate service loses the latency advantage.
- **Online vs. offline?** Online learning (update the model per observation) is powerful but hard to do correctly. Offline training (batch, nightly, rolled out as a model update) is safer for v1.
- **What's the false-positive cost?** An anomaly that blocks a legitimate agent is an incident. False positives erode trust. v1 should observe-only, not block.
- **What's the feature set?** Destination IP alone is weak (CDNs, shared infrastructure). Connection timing + byte volume + MCP tool sequence is stronger. Sequence modeling (transformer on tool call traces) is run-stage-run.

## Why This Matters in 3 Years

Agents will be the primary workload in most production environments. They will make thousands of connections per minute, generate millions of spans, and call hundreds of tools. No human can review this in real time. The SPIFFE Firewall handles known-bad. Behavioral fingerprinting handles unknown-bad — the zero-day, the compromised credential, the agent that went rogue.

The reflector is the only system positioned to build this model at the kernel level, across all agents, without modifying any agent code.

## Connections

- Feeds: MCP enforcement middleware (seed-04)
- Blocked by: need N days of baseline data — requires crawl/walk to be running in production first
- ADR needed: inference engine choice (embedded vs. sidecar vs. service)

---

## The Pitch

> "No human can review this in real time. The SPIFFE Firewall handles known-bad. Behavioral fingerprinting handles unknown-bad — the zero-day, the compromised credential, the agent that went rogue."

Known-bad: blocked at the handshake by OPA policy.
Unknown-bad: flagged by deviation from behavioral baseline.
Wire speed. No interception. No data plane latency. The kernel already did the work.
