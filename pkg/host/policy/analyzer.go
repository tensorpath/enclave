package policy

import (
	"encoding/json"
	"strings"
)

// Analyzer wraps the logic for converting tool requests to OPA inputs
type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze extracts intent from the tool request and its context
func (a *Analyzer) Analyze(sessionID string, toolName string, input string, contextJSON string) EvaluationInput {
	// Default Intent (Strict Sandbox)
	intent := Intent{
		ActionCategory:  "restricted",
		NetworkRequired: false,
		RequestedPaths:  []string{},
	}

	// Default EvaluationInput
	evalInput := EvaluationInput{
		SessionID:      sessionID,
		UserRole:       "standard_agent",
		AgentFramework: "enclave-orchestrator",
		Intent:         intent,
	}

	// 1. Try to parse context_json if provided by the client
	if contextJSON != "" {
		var ctxData map[string]interface{}
		if err := json.Unmarshal([]byte(contextJSON), &ctxData); err == nil {
			if role, ok := ctxData["user_role"].(string); ok {
				evalInput.UserRole = role
			}
			if framework, ok := ctxData["agent_framework"].(string); ok {
				evalInput.AgentFramework = framework
			}
			
			// If context already contains intent, use it (The "Intent Extractor" LLM flow)
			if intentData, ok := ctxData["intent"].(map[string]interface{}); ok {
				if cat, ok := intentData["action_category"].(string); ok {
					evalInput.Intent.ActionCategory = cat
				}
				if net, ok := intentData["network_required"].(bool); ok {
					evalInput.Intent.NetworkRequired = net
				}
				if paths, ok := intentData["requested_paths"].([]interface{}); ok {
					for _, p := range paths {
						if pathStr, ok := p.(string); ok {
							evalInput.Intent.RequestedPaths = append(evalInput.Intent.RequestedPaths, pathStr)
						}
					}
				}
				return evalInput
			}
		}
	}

	// 2. Simple Heuristics (Heuristic Fallback)
	// If no explicit intent, we look at the code/input
	if strings.Contains(input, "http") || strings.Contains(input, "requests.") || strings.Contains(input, "urllib") {
		evalInput.Intent.NetworkRequired = true
	}

	// Look for file paths in common analysis tools
	if strings.Contains(input, "pd.read_csv") || strings.Contains(input, "open(") {
		evalInput.Intent.ActionCategory = "read_only_analysis"
		// Heuristically extract paths if they look like /workspace/ or /data/
		// (In a real implementation, this would be a more robust regex or LLM)
	}

	return evalInput
}
