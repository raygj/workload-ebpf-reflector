package reflector.policy

# default.rego — walk-stage identity policy for the eBPF reflector.
#
# Input shape:
#   input.spiffe_id   string  — e.g. "spiffe://cluster.local/ns/foo/sa/bar"
#   input.src_addr    string  — source IP:port
#   input.dst_addr    string  — destination IP:port
#   input.pid         number  — process ID on the node
#
# Output:
#   allow  bool    — true = permitted, false = violation
#   reason string  — human-readable rule name surfaced in POLICY_VIOLATION events

default allow := true
default reason := "default-allow"

# Deny workloads with no SPIFFE identity (empty string means cert had no SPIFFE SAN).
deny contains "missing-spiffe-identity" if {
    input.spiffe_id == ""
}

# Deny SPIFFE IDs from untrusted trust domains.
# Update trusted_domains to match your cluster's trust anchors.
trusted_domains := {"cluster.local"}

deny contains "untrusted-trust-domain" if {
    id := input.spiffe_id
    id != ""
    not any_trusted(id)
}

any_trusted(id) if {
    some domain in trusted_domains
    startswith(id, concat("", ["spiffe://", domain, "/"]))
}

# Final allow/reason derivation — deny wins if any deny rule fires.
allow := false if {
    count(deny) > 0
}

reason := concat(", ", deny) if {
    count(deny) > 0
}

# result bundles allow + reason into a single object for the evaluator query.
result := {"allow": allow, "reason": reason}
