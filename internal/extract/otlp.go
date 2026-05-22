package extract

import (
	"bytes"
	"strconv"

	"google.golang.org/protobuf/encoding/protowire"
)

// OTLPSignal represents a captured OTel export from SSL_write plaintext.
type OTLPSignal struct {
	SignalType  string // "traces", "metrics", "logs"
	ServiceName string // resource.attributes["service.name"] (best-effort, may be empty)
	BatchCount  int    // number of ResourceSpans/ResourceMetrics/ResourceLogs entries
	RawBody     []byte // raw protobuf body, ready for OTLP/HTTP re-forward
	IsTruncated bool   // true if captured bytes < Content-Length (body incomplete)
}

// otlpPaths maps HTTP POST paths to OTLP signal types.
var otlpPaths = map[string]string{
	"/v1/traces":  "traces",
	"/v1/metrics": "metrics",
	"/v1/logs":    "logs",
}

// otlpGRPCPaths maps gRPC method paths to OTLP signal types.
var otlpGRPCPaths = map[string]string{
	"/opentelemetry.proto.collector.trace.v1.TraceService/Export":   "traces",
	"/opentelemetry.proto.collector.metrics.v1.MetricsService/Export": "metrics",
	"/opentelemetry.proto.collector.logs.v1.LogsService/Export":     "logs",
}

// ExtractOTLPFromTLS scans captured HTTP/HTTPS plaintext for an OTLP export request.
//
// Detects:
//   - OTLP/HTTP:  POST /v1/traces|metrics|logs with application/x-protobuf body
//   - OTLP/gRPC:  POST to opentelemetry TraceService/MetricsService/LogsService
//     (detected and classified, but gRPC framing means RawBody is NOT re-forwardable
//     as OTLP/HTTP without stripping the 5-byte length prefix — walk scope)
//
// Returns nil if the plaintext does not look like an OTLP export.
func ExtractOTLPFromTLS(plaintext []byte) (*OTLPSignal, error) {
	// Must start with POST
	if !bytes.HasPrefix(plaintext, []byte("POST ")) {
		return nil, nil
	}

	// Extract the request path (between "POST " and " HTTP")
	pathEnd := bytes.IndexByte(plaintext[5:], ' ')
	if pathEnd < 0 {
		return nil, nil
	}
	path := string(plaintext[5 : 5+pathEnd])

	// Detect signal type from path
	var signalType string
	var isGRPC bool

	if st, ok := otlpPaths[path]; ok {
		signalType = st
	} else {
		for grpcPath, st := range otlpGRPCPaths {
			if path == grpcPath {
				signalType = st
				isGRPC = true
				break
			}
		}
	}
	if signalType == "" {
		return nil, nil
	}

	// Parse headers: find Content-Length and locate body start
	headerEnd := findHeaderEnd(plaintext)
	if headerEnd < 0 {
		// Headers incomplete — we can still classify the signal type
		return &OTLPSignal{
			SignalType:  signalType,
			IsTruncated: true,
		}, nil
	}

	headers := plaintext[:headerEnd]
	body := plaintext[headerEnd:]

	// Extract Content-Length for truncation detection
	contentLength := extractContentLength(headers)
	isTruncated := contentLength > 0 && len(body) < contentLength

	sig := &OTLPSignal{
		SignalType:  signalType,
		IsTruncated: isTruncated,
	}

	if len(body) == 0 {
		sig.IsTruncated = true
		return sig, nil
	}

	// For OTLP/gRPC: strip the 5-byte length prefix to get raw protobuf.
	// gRPC framing: 1 byte compressed flag + 4 bytes big-endian message length.
	protoBody := body
	if isGRPC && len(body) >= 5 {
		msgLen := int(body[1])<<24 | int(body[2])<<16 | int(body[3])<<8 | int(body[4])
		if msgLen > 0 && len(body) >= 5+msgLen {
			protoBody = body[5 : 5+msgLen]
			// Re-forward as OTLP/HTTP is viable once gRPC framing is stripped.
			// For crawl: mark as gRPC so sidecar knows to add Content-Type correctly.
		} else {
			// Partial gRPC frame
			sig.IsTruncated = true
			return sig, nil
		}
	}

	// Set raw body for re-forward (only if not truncated)
	if !isTruncated {
		sig.RawBody = protoBody
	}

	// Best-effort: extract service name and batch count from protobuf
	sig.ServiceName = extractServiceName(protoBody)
	sig.BatchCount = countTopLevelEntries(protoBody)

	return sig, nil
}

// findHeaderEnd returns the offset of the first byte after \r\n\r\n,
// or -1 if the header terminator is not in the data.
func findHeaderEnd(data []byte) int {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx >= 0 {
		return idx + 4
	}
	// Fallback: \n\n (non-standard but seen in some implementations)
	idx = bytes.Index(data, []byte("\n\n"))
	if idx >= 0 {
		return idx + 2
	}
	return -1
}

// extractContentLength parses Content-Length from HTTP headers.
// Returns 0 if not found or unparseable.
func extractContentLength(headers []byte) int {
	lower := bytes.ToLower(headers)
	idx := bytes.Index(lower, []byte("content-length:"))
	if idx < 0 {
		return 0
	}
	rest := headers[idx+15:]
	// Skip whitespace
	start := 0
	for start < len(rest) && (rest[start] == ' ' || rest[start] == '\t') {
		start++
	}
	end := start
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == start {
		return 0
	}
	n, err := strconv.Atoi(string(rest[start:end]))
	if err != nil {
		return 0
	}
	return n
}

// extractServiceName walks the OTLP ExportTraceServiceRequest protobuf to find
// resource.attributes["service.name"].
//
// Wire structure:
//   ExportTraceServiceRequest.resource_spans (field 1) →
//     ResourceSpans.resource (field 1) →
//       Resource.attributes (field 1, repeated KeyValue) →
//         KeyValue.key (field 1) == "service.name" →
//           KeyValue.value (field 2) → AnyValue.string_value (field 1)
//
// Returns empty string if not found or on any parse error.
func extractServiceName(protoBody []byte) string {
	// Field 1 = resource_spans (ResourceSpans message)
	rsBytes := protoFirstMessage(protoBody, 1)
	if rsBytes == nil {
		return ""
	}

	// Field 1 inside ResourceSpans = resource (Resource message)
	resourceBytes := protoFirstMessage(rsBytes, 1)
	if resourceBytes == nil {
		return ""
	}

	// Field 1 inside Resource = attributes (repeated KeyValue)
	b := resourceBytes
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if typ == protowire.BytesType && num == 1 {
			// KeyValue message
			kvBytes, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				break
			}
			b = b[n2:]

			key := protoFirstString(kvBytes, 1)
			if key == "service.name" {
				// Value is field 2: AnyValue
				anyBytes := protoFirstMessage(kvBytes, 2)
				if anyBytes != nil {
					// string_value is field 1 of AnyValue
					return protoFirstString(anyBytes, 1)
				}
			}
		} else {
			if n2 := protowire.ConsumeFieldValue(num, typ, b); n2 > 0 {
				b = b[n2:]
			} else {
				break
			}
		}
	}
	return ""
}

// countTopLevelEntries counts the number of top-level repeated field 1 entries
// in the protobuf body (ResourceSpans / ResourceMetrics / ResourceLogs).
// These are the outermost containers — a rough proxy for data volume.
func countTopLevelEntries(protoBody []byte) int {
	count := 0
	b := protoBody
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if typ == protowire.BytesType && num == 1 {
			count++
		}
		n2 := protowire.ConsumeFieldValue(num, typ, b)
		if n2 < 0 {
			break
		}
		b = b[n2:]
	}
	return count
}

// protoFirstMessage returns the bytes of the first occurrence of the given
// field number (expected to be a length-delimited message) in the protobuf data.
// Returns nil if not found.
func protoFirstMessage(data []byte, fieldNum protowire.Number) []byte {
	b := data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if typ == protowire.BytesType && num == fieldNum {
			msg, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				break
			}
			return msg
		}
		n2 := protowire.ConsumeFieldValue(num, typ, b)
		if n2 < 0 {
			break
		}
		b = b[n2:]
	}
	return nil
}

// protoFirstString returns the string value of the first occurrence of the
// given field number (expected to be a length-delimited string).
func protoFirstString(data []byte, fieldNum protowire.Number) string {
	b := data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if typ == protowire.BytesType && num == fieldNum {
			s, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				break
			}
			return string(s)
		}
		n2 := protowire.ConsumeFieldValue(num, typ, b)
		if n2 < 0 {
			break
		}
		b = b[n2:]
	}
	return ""
}
