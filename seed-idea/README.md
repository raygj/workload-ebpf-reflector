# Run-Stage Vision Seeds

This directory contains architectural seeds for the **run stage** — the post-walk horizon where the reflector evolves from a SPIFFE Firewall into an active intelligence layer for agentic workloads.

These are **not sprint scope**. They are directional bets, research seeds, and first-principles questions that should inform ADRs when the time comes. Read them as north star, not backlog.

## Seeds

| File | Theme |
|------|-------|
| [01-behavioral-fingerprinting.md](01-behavioral-fingerprinting.md) | AI anomaly detection on the identity metadata stream |
| [02-ssf-gossip.md](02-ssf-gossip.md) | Security Signal Format federation across nodes and clusters |
| [03-multi-cluster.md](03-multi-cluster.md) | Multi-cluster identity mesh — one policy, many clusters |
| [05-spiffe-rotation-tracking.md](05-spiffe-rotation-tracking.md) | Cert rotation as a first-class observable — anomaly signal for compromise |
| [06-nhi-pam-tool-session-correlation.md](06-nhi-pam-tool-session-correlation.md) | Correlating reflector sessions with NHI-PAM-Tool session tokens |
| [07-kafka-protocol-visibility.md](07-kafka-protocol-visibility.md) | Kafka Wire Protocol parsing — topic-level identity for producers and consumers |

## What "Run" Means

```
Crawl:  Eyes.    Observe identity, stream to session map.
Walk:   Reflex.  OPA gate at the kernel, TC drop at wire speed.
Run:    Brain.   AI on the stream, federation across clusters, 
                  correlation with control plane.
```

The reflector's output — SPIFFE IDs, 5-tuples, JWT claims, MCP tool names, policy violations — is a structured signal that no other system produces. Run stage is about what you do with that signal at scale.
