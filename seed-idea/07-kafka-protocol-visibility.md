# Seed: Kafka Wire Protocol Visibility

**Stage:** Run
**Maturity:** [EXPERIMENTAL]
**Theme:** Topic-level identity for Kafka/Confluent — who is producing and consuming what, at the kernel

---

## The Observation

Kafka is the nervous system of modern data pipelines. Agents produce events to topics. Consumers read them. The Kafka cluster brokers the flow — but it cannot see who the producer *really is* in a zero-trust sense. It sees a client ID and a SASL credential. It does not see the SPIFFE ID of the workload that made the TLS connection.

The reflector already intercepts the TLS handshake. For Confluent Cloud and any Kafka deployment with TLS enabled (port 9093), the `SSL_write`/`SSL_read` hooks capture the Kafka Wire Protocol plaintext. The bytes are there. Nobody is reading them.

## What's Already Working

**Confluent Cloud SASL/OAUTHBEARER is already partially observable.** The SASL authentication exchange sends a JWT Bearer token over TLS. Our existing JWT extractor fires on it — the operator sees the JWT `sub` in the session map today, with no additional code.

What's missing is the Kafka-specific layer on top: topic names, producer/consumer role, `client_id`, and message metadata.

## The Kafka Wire Protocol

Kafka uses a length-prefixed binary protocol. Every request starts with:

```
[4 bytes] message length
[2 bytes] API key      → which operation (Produce=0, Fetch=1, Metadata=3, ...)
[2 bytes] API version
[4 bytes] correlation ID
[2 bytes] client_id length
[N bytes] client_id    ← application-set identity string
```

After the header, the payload varies by API key:

- **Produce (API key 0):** `topic_name`, partition, record batch bytes
- **Fetch (API key 1):** `topic_name`, partition, fetch offset
- **Metadata (API key 3):** list of requested topic names (empty = all topics)

All of this is available in the `SSL_write` plaintext captured by the TLS hook. A Kafka protocol parser in `internal/extract/kafka.go` would extract:

- `client_id` — application-configured identity (e.g. `payment-processor-v2`)
- API key → operation type (produce, consume, admin)
- Topic names — what data is being produced to / consumed from
- Partition — which shard

## The Signal

Combined with what the reflector already sees:

```
SPIFFE ID:    spiffe://prod/ns/payments/sa/processor   (from d2i_X509 uprobe)
JWT subject:  payments-processor@ci.example.com        (from SASL/OAUTHBEARER)
Kafka client: payment-processor-v2                     (from Wire Protocol header)
Operation:    Produce                                   (API key 0)
Topic:        payments.transactions                     (from Produce request)
Partition:    3
```

That's a correlated identity record no Kafka broker produces. Confluent Cloud audit logs show "client_id X produced to topic Y." They do not show the SPIFFE ID of the workload. They cannot — that's in the TLS handshake, not the application layer.

## Anomaly Signals

The behavioral fingerprinting layer (seed-01, now shipped as Sprint 14) gains new dimensions:

- **Topic novelty:** `payment-processor` suddenly producing to `user.pii` — not in baseline
- **Role flip:** consumer client suddenly producing (read→write privilege escalation)
- **Topic volume spike:** 10× normal message rate on a sensitive topic
- **New partition:** workload writing to a partition it's never touched

These are behavioral signals that OPA cannot express. OPA knows "is this SPIFFE ID allowed to write to this topic?" It does not know "has this SPIFFE ID *ever* written to this topic before, and is this volume normal?"

## First Principles Questions

- **Binary protocol parsing in the eBPF ring buffer path.** The Kafka Wire Protocol is length-prefixed and relatively simple to parse in Go userspace. The challenge is fragmentation: a single SSL_write may contain partial frames, or multiple frames. The parser needs to handle incomplete frames gracefully (discard vs. accumulate).
- **Port 9092 (plaintext Kafka) is invisible.** The SSL hooks only fire on TLS connections. Plaintext Kafka traffic is not captured. This is a deliberate non-goal — plaintext Kafka in production is a security misconfiguration, not a supported target.
- **MAX_CAPTURE_BYTES.** A Kafka Produce request with large messages may exceed 4096 bytes. The client_id and topic name are in the first ~50 bytes of the request, well within the capture window. A truncated payload still yields the most valuable fields.
- **API version negotiation.** Kafka clients negotiate the highest mutually supported API version via the ApiVersions request (API key 18). The field offsets shift slightly between versions. A minimal parser should handle versions 0–3 of Produce and Fetch, which cover >95% of production deployments.
- **Confluent Schema Registry.** Schema Registry calls are HTTP over TLS to a different port (8081/8082). The existing OTLP/HTTP extractor won't match, but a simple HTTP path detector (`/subjects/`, `/schemas/`) could extract schema subject names — another identity-rich signal.

## The Minimal Version

One sprint. Target: extract `client_id` and `topic_name` from Produce and Fetch requests. No version negotiation, no partial frame handling. Happy path only.

```go
type KafkaRequest struct {
    APIKey    uint16
    ClientID  string
    Topics    []string
    Operation string // "produce", "fetch", "metadata", "other"
}

func ExtractKafkaFromTLS(data []byte) (*KafkaRequest, error)
```

Wire into `ExtractIdentitiesFromTLS` alongside JWT and MCP. Surface in session map as `kafka_client_id` and `kafka_topics`. Add to behavioral profile topic set.

## Connections

- Requires: TLS hook (done), ExtractIdentitiesFromTLS pipeline (done)
- Existing: SASL/OAUTHBEARER JWT already captured by JWT extractor today
- Feeds: behavioral fingerprinting (Sprint 14) — topic set as a new profile dimension
- Feeds: session map — `kafka_client_id`, `kafka_topics` fields on Entry
- Feeds: attestation API — Kafka producer/consumer identity corroborated at kernel
- ADR needed: Kafka protocol parser scope (which API keys, which versions), partial frame strategy
