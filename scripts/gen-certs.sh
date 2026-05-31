#!/usr/bin/env bash
# gen-certs.sh — generates a local CA and mTLS certs for dev/POC use (ADR-013).
# In production, replace with SPIRE Workload API.
#
# Usage: scripts/gen-certs.sh [output-dir]
# Default output-dir: certs/

set -euo pipefail

OUTDIR="${1:-certs}"
mkdir -p "$OUTDIR"

# ── CA ────────────────────────────────────────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$OUTDIR/ca.key" -out "$OUTDIR/ca.crt" \
  -days 3650 -nodes \
  -subj "/CN=reflector-dev-ca/O=mcp-ebpf-reflector" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# ── reflector-map (server) cert ───────────────────────────────────────────────
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$OUTDIR/reflector-map.key" -out "$OUTDIR/reflector-map.csr" \
  -nodes -subj "/CN=reflector-map/O=mcp-ebpf-reflector"

openssl x509 -req -in "$OUTDIR/reflector-map.csr" \
  -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
  -out "$OUTDIR/reflector-map.crt" -days 365 \
  -extfile <(printf 'subjectAltName=URI:spiffe://cluster.local/ns/ebpf-reflector/sa/reflector-map\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth')

# ── reflector (client / DaemonSet) cert ──────────────────────────────────────
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$OUTDIR/reflector.key" -out "$OUTDIR/reflector.csr" \
  -nodes -subj "/CN=reflector/O=mcp-ebpf-reflector"

openssl x509 -req -in "$OUTDIR/reflector.csr" \
  -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
  -out "$OUTDIR/reflector.crt" -days 365 \
  -extfile <(printf 'subjectAltName=URI:spiffe://cluster.local/ns/ebpf-reflector/sa/reflector\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth')

# Clean up CSRs
rm -f "$OUTDIR"/*.csr "$OUTDIR"/*.srl

echo ""
echo "Certs written to $OUTDIR/:"
ls -1 "$OUTDIR/"
echo ""
echo "Start reflector-map with mTLS:"
echo "  ./reflector-map --tls-ca=$OUTDIR/ca.crt --tls-cert=$OUTDIR/reflector-map.crt --tls-key=$OUTDIR/reflector-map.key"
echo ""
echo "SPIFFE IDs:"
echo "  reflector-map : spiffe://cluster.local/ns/ebpf-reflector/sa/reflector-map"
echo "  reflector     : spiffe://cluster.local/ns/ebpf-reflector/sa/reflector"
