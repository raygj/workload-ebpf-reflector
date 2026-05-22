// Package policy evaluates SPIFFE identity events against a Rego policy.
// Used in the walk stage to detect policy violations before TC/XDP enforcement.
package policy

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"

	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed default.rego
var defaultPolicy string

// Result is the output of a policy evaluation.
type Result struct {
	Allow  bool
	Reason string
}

// Input is the data passed to OPA for each SPIFFE event.
type Input struct {
	SPIFFEID string `json:"spiffe_id"`
	SrcAddr  string `json:"src_addr"`
	DstAddr  string `json:"dst_addr"`
	PID      uint32 `json:"pid"`
}

// Evaluator holds a compiled OPA query ready for repeated evaluation.
type Evaluator struct {
	query  rego.PreparedEvalQuery
	logger *slog.Logger
}

// New creates an Evaluator. If policyPath is non-empty and the file exists,
// it loads policy from that path; otherwise falls back to the compiled-in default.
func New(policyPath string, logger *slog.Logger) (*Evaluator, error) {
	src, label := defaultPolicy, "embedded default.rego"

	if policyPath != "" {
		data, err := os.ReadFile(policyPath)
		if err == nil {
			src, label = string(data), policyPath
		} else {
			logger.Warn("policy file not readable, using default", "path", policyPath, "error", err)
		}
	}

	q, err := rego.New(
		rego.Query("data.reflector.policy.result"),
		rego.Module(label, src),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compiling policy %s: %w", label, err)
	}

	logger.Info("policy loaded", "source", label)
	return &Evaluator{query: q, logger: logger}, nil
}

// Eval evaluates the policy against the given input. Returns allow=true on
// any evaluation error so a broken policy never silently blocks traffic.
func (e *Evaluator) Eval(ctx context.Context, in Input) Result {
	rs, err := e.query.Eval(ctx, rego.EvalInput(in))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		e.logger.Warn("policy eval error — defaulting to allow", "error", err)
		return Result{Allow: true, Reason: "eval-error"}
	}

	obj, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return Result{Allow: true, Reason: "eval-error"}
	}
	allow, _ := obj["allow"].(bool)
	reason, _ := obj["reason"].(string)
	if reason == "" {
		reason = "default-allow"
	}
	return Result{Allow: allow, Reason: reason}
}
