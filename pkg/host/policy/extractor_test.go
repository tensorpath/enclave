package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExtractIntentWithOpenAIFallbackToTextOnResponseFormat400(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&calls, 1)
		defer r.Body.Close()

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		responseFormat, _ := req["response_format"].(map[string]interface{})
		if responseFormat == nil {
			t.Fatalf("missing response_format")
		}

		if call == 1 {
			if responseFormat["type"] != "json_schema" {
				t.Fatalf("expected first attempt json_schema, got %v", responseFormat["type"])
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"'response_format.type' must be 'json_schema' or 'text'"}`))
			return
		}

		if responseFormat["type"] != "text" {
			t.Fatalf("expected fallback attempt text, got %v", responseFormat["type"])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"choices\":[{\"message\":{\"content\":\"Here is the result:\\n```json\\n{\\\"action_category\\\":\\\"read_only_analysis\\\",\\\"network_required\\\":false,\\\"requested_paths\\\":[\\\"/workspace/data.csv\\\"],\\\"confidence\\\":0.92}\\n```\"}}]}"))
	}))
	defer server.Close()

	extractor := NewExtractor()
	extractor.httpClient = server.Client()

	intent, confidence, err := extractor.extractIntentWithOpenAI(context.Background(), ExtractorRequest{
		SessionID: "sess-1",
		ToolName:  "python",
		Input:     "pd.read_csv('/workspace/data.csv')",
	}, IntentExtractorConfig{Model: "gpt", Endpoint: server.URL})
	if err != nil {
		t.Fatalf("extractIntentWithOpenAI error: %v", err)
	}
	if got := intent.ActionCategory; got != "read_only_analysis" {
		t.Fatalf("unexpected action category: %s", got)
	}
	if len(intent.RequestedPaths) != 1 || intent.RequestedPaths[0] != "/workspace/data.csv" {
		t.Fatalf("unexpected requested_paths: %#v", intent.RequestedPaths)
	}
	if confidence != 0.92 {
		t.Fatalf("unexpected confidence: %v", confidence)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected two API calls, got %d", atomic.LoadInt32(&calls))
	}
}

func TestParseIntentPayloadFromModelContentRejectsNonJSON(t *testing.T) {
	_, err := parseIntentPayloadFromModelContent("not json output")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid intent JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFormatOpenAIStatusErrorIncludesCompatibilityHint(t *testing.T) {
	err := formatOpenAIStatusError(http.StatusBadRequest, "https://api.example.com/v1/chat/completions", true, []byte(`{"error":"'response_format.type' must be 'json_schema' or 'text'"}`))
	if err == nil {
		t.Fatalf("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "hint:") {
		t.Fatalf("expected compatibility hint in error: %s", msg)
	}
	if strings.Contains(msg, "Bearer") || strings.Contains(msg, "sk-") {
		t.Fatalf("error leaked secrets: %s", msg)
	}
}
