# Seed: Multi-Cluster Identity Mesh

**Stage:** Run
**Maturity:** [VISION]
**Theme:** One policy, many clusters — SPIFFE identity is the universal key

---

## The Problem

SPIFFE trust domains are scoped to a cluster. `spiffe://cluster-a.local/ns/payments/sa/processor` is different from `spiffe://cluster-b.local/ns/payments/sa/processor` even if they're running the same code. Cross-cluster policy today is: configure both clusters separately, hope they stay in sync, and have no runtime correlation between them.

The reflector currently runs per-node in a single cluster. Walk stage proves the pattern. Run stage extends it.

## The Idea

**Federated trust domains.** Use SPIFFE Federation (SPIRE's federation feature, or cert-manager's trust bundle federation) to establish cross-cluster trust. `spiffe://prod.example.com/...` becomes a stable, cluster-independent identity. The reflector extracts this federation-aware SPIFFE ID and evaluates it against a policy that understands cross-cluster identity.

**Shared policy bundle.** OPA policy is currently ConfigMap-mounted per-cluster. Run stage: policy is a signed bundle served from a central policy server (OPA Bundle API). All reflector instances — across all clusters — pull the same policy. A policy change applies everywhere within the bundle refresh interval.

**Cross-cluster session map.** The reflector-map sidecar today is per-cluster. A federated session map aggregates across clusters — one query to see all sessions for `spiffe://prod.example.com/ns/payments/sa/processor` regardless of which cluster it ran in.

```
                    Policy Bundle Server
                    (OPA Bundle API, signed)
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         Cluster A    Cluster B    Cluster C
         reflector    reflector    reflector
              │          │          │
              └──────────┴──────────┘
                         │
                  Federated Session Map
                  (cross-cluster identity graph)
```

## Lab Path

The HP Xeon pair is the right hardware for this. Two physical nodes, each running a Talos cluster (or a two-node single cluster), each running a reflector DaemonSet. The extra NICs provide the physical network separation. This is also the fix for the TC `eth0` enforcement gap — on a two-node cluster, cross-node traffic is physical and TC enforcement fires naturally.

**Immediate lab step:** Set up the two-node Talos cluster on the HP Xeon pair. Even without full federation, this validates the multi-node TC enforcement story and gives a better demo topology.

## First Principles Questions

- **Trust bundle management.** SPIRE handles this natively. cert-manager trust bundles are simpler but less mature for federation. Which is right for this stack?
- **Policy bundle freshness.** OPA's bundle API supports polling. How often? 60 seconds is safe for policy that doesn't change often. Emergency revocation needs an out-of-band path (GOAWAY + reconnect trigger).
- **Session map storage.** In-memory per-cluster is fine for crawl/walk. Federated needs a backing store. etcd (reuse K8s) or a purpose-built time-series KV?
- **What's the query model?** "Show me all connections from this SPIFFE ID across all clusters in the last hour" is the run-stage query. That's a time-series join, not a simple map lookup.

## Why This Matters in 3 Years

Enterprise Kubernetes is multi-cluster by default. Platform teams run 10-50 clusters. Agentic workloads span them without thinking about cluster boundaries. A SPIFFE Firewall that only sees one cluster is like a firewall that only covers one subnet. Multi-cluster is table stakes for production identity security.

## Connections

- Requires: SSF gossip (seed-02) for cross-cluster event correlation
- Lab path: HP Xeon pair → two-node Talos cluster → per-node reflector → federated session map
- ADR needed: trust bundle federation approach, policy bundle server, session map storage
