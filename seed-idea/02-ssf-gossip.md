# Seed: SSF Gossip — Security Signal Format Federation

**Stage:** Run
**Maturity:** [VISION]
**Theme:** Make reflector nodes talk to each other across clusters

---

## The Problem

The reflector sees everything on its node. It doesn't see what's happening two nodes over, or in the cluster across the WAN link. A compromised identity that hops clusters is invisible to any single reflector instance.

Security Signal Format (SSF) is an IETF standard (RFC 8935 / draft-ietf-secevent-subject-identifiers) for sharing security events between services — think structured, signed, push-based security telemetry. It's designed for exactly this: "here's something I saw, you should know about it."

## The Idea

**Each reflector node is an SSF publisher.** POLICY_VIOLATION events, anomaly scores above threshold, and cert rotation events are signed as Security Event Tokens (SETs) and gossiped to a federation endpoint.

**A lightweight aggregator** (could be the reflector-map sidecar extended, or a new `reflector-fed` binary) receives SSF events from all nodes, deduplicates, and maintains a cluster-wide and cross-cluster identity event feed.

**Cross-cluster correlation.** If `spiffe://prod/ns/payments/sa/processor` fires a POLICY_VIOLATION in cluster A, cluster B knows about it within seconds — and can apply a temporary elevated-scrutiny policy while the incident is investigated.

```
Cluster A                           Cluster B
  reflector-node-1 ─── SSF SET ──►  reflector-fed
  reflector-node-2 ─── SSF SET ──►      │
                                         ▼
                                   cross-cluster
                                   identity feed
                                         │
                                    Cluster B OPA
                                    (elevated policy)
```

## First Principles Questions

- **Trust model.** SSF events are signed. Who is the signing authority? Cert-manager + SPIFFE SVID for the reflector itself — the reflector has an identity too.
- **Gossip vs. hub.** Full gossip (every node talks to every node) doesn't scale. Hub-and-spoke (nodes → aggregator) is simpler but the aggregator is a SPOF. Hierarchical (per-cluster aggregator, cross-cluster federation) is the right topology.
- **What gets gossiped?** Not all events — that's too much. Policy violations, anomaly scores above threshold, cert rotation anomalies. Normal connection events stay local.
- **Latency requirement.** Cross-cluster SSF doesn't need sub-millisecond. 1-10 seconds is fine. This is not the enforcement path — OPA at the kernel is. SSF is the correlation path.

## Why This Matters in 3 Years

In a world with hundreds of agentic workloads running across dozens of clusters, the attack surface is the identity graph. A single-node SPIFFE Firewall sees its slice. SSF federation gives you the graph. An identity that is trusted in cluster A but behaving anomalously in cluster B can be quarantined before it pivots.

The IETF is standardizing this. The tooling will mature. The reflector is positioned to be an SSF publisher with zero application modification — because the data is already at the kernel.

## Connections

- Requires: behavioral fingerprinting (seed-01) for meaningful anomaly events to gossip
- Enables: MCP enforcement middleware cross-cluster policy (seed-04)
- ADR needed: SSF event schema, signing authority, federation topology
