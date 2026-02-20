package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

// Intent represents the structured input to OPA
type Intent struct {
	ActionCategory  string   `json:"action_category"`
	NetworkRequired bool     `json:"network_required"`
	RequestedPaths  []string `json:"requested_paths"`
}

// EvaluationInput represents the data OPA receives
type EvaluationInput struct {
	SessionID      string `json:"session_id"`
	UserRole       string `json:"user_role"`
	AgentFramework string `json:"agent_framework"`
	Intent         Intent `json:"intent"`
}

// Verdict is the output from OPA evaluation
type Verdict struct {
	AllowNetwork      bool     `json:"allow_network"`
	AllowedReadPaths  []string `json:"allowed_read_paths"`
	AllowedWritePaths []string `json:"allowed_write_paths"`
}

type Engine struct {
	evaluator rego.PreparedEvalQuery
}

// Constitution is the Rego policy source
const Constitution = `
package tensorpath.agent.policy

import future.keywords.in

default allow_network = false
default allowed_read_paths = []
default allowed_write_paths = ["/tmp/"]

allow_network {
    input.intent.network_required == true
    input.user_role == "researcher"
}

allowed_read_paths = paths {
    input.intent.action_category == "read_only_analysis"
    paths := input.intent.requested_paths
}

verdict = {
    "allow_network": allow_network,
    "allowed_read_paths": allowed_read_paths,
    "allowed_write_paths": allowed_write_paths
}
`

func New(ctx context.Context) (*Engine, error) {
	r := rego.New(
		rego.Query("data.tensorpath.agent.policy.verdict"),
		rego.Module("agent_boundaries.rego", Constitution),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego: %w", err)
	}

	return &Engine{evaluator: query}, nil
}

func (e *Engine) Evaluate(ctx context.Context, input EvaluationInput) (*Verdict, error) {
	results, err := e.evaluator.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("eval error: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no results from policy evaluation")
	}

	if len(results[0].Expressions) == 0 {
		return nil, fmt.Errorf("no expressions in policy evaluation result")
	}

	// OPA returns an interface{} map, we need to map it to our Verdict struct
	val := results[0].Expressions[0].Value
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected verdict format: %T", val)
	}

	allowNetwork, ok := m["allow_network"].(bool)
	if !ok {
		return nil, fmt.Errorf("invalid or missing allow_network field")
	}

	verdict := &Verdict{
		AllowNetwork: allowNetwork,
	}

	if paths, ok := m["allowed_read_paths"].([]interface{}); ok {
		for _, p := range paths {
			pathStr, ok := p.(string)
			if !ok {
				return nil, fmt.Errorf("invalid read path type: %T", p)
			}
			verdict.AllowedReadPaths = append(verdict.AllowedReadPaths, pathStr)
		}
	}

	if paths, ok := m["allowed_write_paths"].([]interface{}); ok {
		for _, p := range paths {
			pathStr, ok := p.(string)
			if !ok {
				return nil, fmt.Errorf("invalid write path type: %T", p)
			}
			verdict.AllowedWritePaths = append(verdict.AllowedWritePaths, pathStr)
		}
	}

	return verdict, nil
}
