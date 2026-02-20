package policy

import (
	"context"
	"testing"
)

func TestPolicyEvaluation(t *testing.T) {
	ctx := context.Background()
	engine, err := New(ctx)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name            string
		input           EvaluationInput
		expectNetwork   bool
		expectReadPaths []string
	}{
		{
			name: "Researcher allows network",
			input: EvaluationInput{
				UserRole: "researcher",
				Intent: Intent{
					NetworkRequired: true,
				},
			},
			expectNetwork: true,
		},
		{
			name: "Analyst blocks network",
			input: EvaluationInput{
				UserRole: "analyst",
				Intent: Intent{
					NetworkRequired: true,
				},
			},
			expectNetwork: false,
		},
		{
			name: "Read only analysis grants paths",
			input: EvaluationInput{
				Intent: Intent{
					ActionCategory: "read_only_analysis",
					RequestedPaths: []string{"/data/q3.csv"},
				},
			},
			expectReadPaths: []string{"/data/q3.csv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := engine.Evaluate(ctx, tt.input)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if verdict.AllowNetwork != tt.expectNetwork {
				t.Errorf("Expected network %v, got %v", tt.expectNetwork, verdict.AllowNetwork)
			}

			if len(tt.expectReadPaths) > 0 {
				found := false
				for _, p := range verdict.AllowedReadPaths {
					if p == tt.expectReadPaths[0] {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected read path %v not found in %v", tt.expectReadPaths[0], verdict.AllowedReadPaths)
				}
			}
		})
	}
}

func TestCompiler(t *testing.T) {
	verdict := &Verdict{
		AllowNetwork:     false,
		AllowedReadPaths: []string{"/workspace/data/"},
	}

	yaml, err := Compile(CompilerInput{
		SessionID: "test-sess",
		Verdict:   verdict,
	})

	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	if !contains(yaml, "action: Override") {
		t.Errorf("Expected Override action in YAML, got: %s", yaml)
	}
	if contains(yaml, "Sigkill") {
		t.Errorf("Did not expect Sigkill in network policy, got: %s", yaml)
	}
	if !contains(yaml, "/workspace/data/") {
		t.Errorf("Expected path /workspace/data/ in YAML, got: %s", yaml)
	}
}

func contains(s, substr string) bool {
	return bytesContains([]byte(s), []byte(substr))
}

func bytesContains(s, b []byte) bool {
	for i := 0; i <= len(s)-len(b); i++ {
		if string(s[i:i+len(b)]) == string(b) {
			return true
		}
	}
	return false
}
