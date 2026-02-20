package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	defaultExtractorProvider = "heuristic"
	defaultOpenAIBaseURL     = "https://api.openai.com/v1"
	defaultOpenAIModel       = "gpt-4o-mini"
)

type IntentExtractorConfig struct {
	Enabled    bool
	StrictMode bool
	Provider   string
	Model      string
	BaseURL    string
	Endpoint   string
	APIKey     string
}

type ExtractorRequest struct {
	SessionID   string
	ToolName    string
	Input       string
	ContextJSON string
}

type ExtractorMetadata struct {
	Provider     string  `json:"provider"`
	Model        string  `json:"model"`
	Confidence   float64 `json:"confidence"`
	LatencyMS    int64   `json:"latency_ms"`
	SourceMethod string  `json:"source_method"`
	Error        string  `json:"error,omitempty"`
}

type ExtractorResult struct {
	EvaluationInput EvaluationInput   `json:"evaluation_input"`
	Metadata        ExtractorMetadata `json:"metadata"`
}

type Extractor struct {
	httpClient *http.Client
}

func NewExtractor() *Extractor {
	return &Extractor{
		httpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

func (e *Extractor) Extract(ctx context.Context, req ExtractorRequest, cfg IntentExtractorConfig) (ExtractorResult, error) {
	start := time.Now()
	norm := normalizeExtractorConfig(cfg)
	base := defaultEvaluationInput(req.SessionID)

	result := ExtractorResult{
		EvaluationInput: base,
		Metadata: ExtractorMetadata{
			Provider:     norm.Provider,
			Model:        norm.Model,
			Confidence:   0.0,
			SourceMethod: "heuristic",
		},
	}

	if norm.Provider == "openai" {
		intent, confidence, err := e.extractIntentWithOpenAI(ctx, req, norm)
		if err == nil {
			result.EvaluationInput.Intent = intent
			result.Metadata.Confidence = confidence
			result.Metadata.SourceMethod = "llm_json"
			result.Metadata.LatencyMS = time.Since(start).Milliseconds()
			return result, nil
		}

		result.EvaluationInput.Intent = heuristicIntent(req.Input)
		result.Metadata.Confidence = 0.4
		result.Metadata.SourceMethod = "heuristic_fallback"
		result.Metadata.Error = err.Error()
		result.Metadata.LatencyMS = time.Since(start).Milliseconds()
		return result, fmt.Errorf("openai intent extraction failed: %w", err)
	}

	result.EvaluationInput.Intent = heuristicIntent(req.Input)
	result.Metadata.Confidence = 0.4
	result.Metadata.LatencyMS = time.Since(start).Milliseconds()
	return result, nil
}

func defaultEvaluationInput(sessionID string) EvaluationInput {
	return EvaluationInput{
		SessionID:      sessionID,
		UserRole:       "standard_agent",
		AgentFramework: "enclave-orchestrator",
		Intent: Intent{
			ActionCategory:  "restricted",
			NetworkRequired: false,
			RequestedPaths:  []string{},
		},
	}
}

func normalizeExtractorConfig(cfg IntentExtractorConfig) IntentExtractorConfig {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider != "openai" {
		provider = defaultExtractorProvider
	}

	model := strings.TrimSpace(os.Getenv("ENCLAVE_POLICY_INTENT_OPENAI_MODEL"))
	if model == "" {
		model = strings.TrimSpace(cfg.Model)
	}
	if provider == "openai" && model == "" {
		model = defaultOpenAIModel
	}

	baseURL := strings.TrimSpace(os.Getenv("ENCLAVE_POLICY_INTENT_OPENAI_BASE_URL"))
	if baseURL == "" {
		if provider == "openai" && allowBaseURLHint() && strings.TrimSpace(cfg.BaseURL) != "" {
			baseURL = strings.TrimSpace(cfg.BaseURL)
		} else {
			baseURL = defaultOpenAIBaseURL
		}
	}

	apiKey := resolveOpenAIAPIKey(cfg)

	return IntentExtractorConfig{
		Enabled:    cfg.Enabled,
		StrictMode: cfg.StrictMode,
		Provider:   provider,
		Model:      model,
		BaseURL:    baseURL,
		Endpoint:   strings.TrimSpace(cfg.Endpoint),
		APIKey:     apiKey,
	}
}

func allowBaseURLHint() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ENCLAVE_POLICY_INTENT_ALLOW_BASEURL_HINT")))
	if v == "" {
		return false
	}
	if v == "0" || v == "false" || v == "no" || v == "off" {
		return false
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func allowAPIKeyHint() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ENCLAVE_POLICY_INTENT_ALLOW_API_KEY_HINT")))
	if v == "" {
		return false
	}
	if v == "0" || v == "false" || v == "no" || v == "off" {
		return false
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

type openAIChatRequest struct {
	Model          string              `json:"model"`
	Messages       []openAIChatMessage `json:"messages"`
	Temperature    float64             `json:"temperature"`
	ResponseFormat interface{}         `json:"response_format,omitempty"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type llmIntentPayload struct {
	ActionCategory  string   `json:"action_category"`
	NetworkRequired bool     `json:"network_required"`
	RequestedPaths  []string `json:"requested_paths"`
	Confidence      float64  `json:"confidence"`
}

type openAIStatusError struct {
	StatusCode int
	Message    string
	Hint       string
}

func (e *openAIStatusError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Message) != "" {
		if strings.TrimSpace(e.Hint) != "" {
			return fmt.Sprintf("non-success status: %d (%s; hint: %s)", e.StatusCode, e.Message, e.Hint)
		}
		return fmt.Sprintf("non-success status: %d (%s)", e.StatusCode, e.Message)
	}
	if strings.TrimSpace(e.Hint) != "" {
		return fmt.Sprintf("non-success status: %d (hint: %s)", e.StatusCode, e.Hint)
	}
	return fmt.Sprintf("non-success status: %d", e.StatusCode)
}

func (e *Extractor) extractIntentWithOpenAI(ctx context.Context, req ExtractorRequest, cfg IntentExtractorConfig) (Intent, float64, error) {
	endpoint := buildOpenAIEndpoint(cfg.BaseURL, cfg.Endpoint)
	if endpoint == "" {
		return Intent{}, 0, fmt.Errorf("missing OpenAI endpoint")
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	contextForPrompt := sanitizeContextJSONForPrompt(req.ContextJSON)

	prompt := fmt.Sprintf(
		"Extract policy intent for secure sandboxing. Return strict JSON only.\nSchema: {\"action_category\":\"restricted|read_only_analysis|code_execution\",\"network_required\":boolean,\"requested_paths\":string[],\"confidence\":number}.\nSession: %s\nTool: %s\nInput:\n%s\nContextJSON:\n%s",
		req.SessionID,
		req.ToolName,
		req.Input,
		contextForPrompt,
	)

	body := openAIChatRequest{
		Model: cfg.Model,
		Messages: []openAIChatMessage{
			{Role: "system", Content: "You are a policy intent extractor. Output only a single JSON object that strictly follows the requested schema."},
			{Role: "user", Content: prompt},
		},
		Temperature:    0,
		ResponseFormat: jsonSchemaResponseFormat(),
	}

	content, err := e.performOpenAIIntentRequest(ctx, endpoint, apiKey, body)
	if err != nil {
		statusErr := (*openAIStatusError)(nil)
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusBadRequest && isResponseFormatCompatibilityMessage(statusErr.Message) {
			fallbackBody := body
			fallbackBody.ResponseFormat = map[string]string{"type": "text"}
			fallbackBody.Messages[0].Content = "You are a policy intent extractor. Output only a single JSON object and no additional prose."
			fallbackBody.Messages[1].Content = prompt + "\nFallback requirement: return plain text that is only one JSON object with exactly these keys: action_category, network_required, requested_paths, confidence."
			fallbackContent, fallbackErr := e.performOpenAIIntentRequest(ctx, endpoint, apiKey, fallbackBody)
			if fallbackErr != nil {
				return Intent{}, 0, fallbackErr
			}
			content = fallbackContent
		}
		if content == "" {
			return Intent{}, 0, err
		}
	}

	llm, err := parseIntentPayloadFromModelContent(content)
	if err != nil {
		return Intent{}, 0, err
	}

	intent := sanitizeIntent(Intent{
		ActionCategory:  llm.ActionCategory,
		NetworkRequired: llm.NetworkRequired,
		RequestedPaths:  llm.RequestedPaths,
	})

	return intent, clampConfidence(llm.Confidence), nil
}

func (e *Extractor) performOpenAIIntentRequest(ctx context.Context, endpoint, apiKey string, body openAIChatRequest) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return "", formatOpenAIStatusError(resp.StatusCode, endpoint, apiKey != "", body)
	}

	var parsed openAIChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("empty choices in response")
	}

	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("empty model content")
	}

	return content, nil
}

func parseIntentPayloadFromModelContent(content string) (llmIntentPayload, error) {
	payload := strings.TrimSpace(content)
	if payload == "" {
		return llmIntentPayload{}, fmt.Errorf("empty model content")
	}

	if parsed, err := decodeIntentPayload(payload); err == nil {
		return parsed, nil
	}

	if fenced := extractFencedJSON(payload); fenced != "" {
		if parsed, err := decodeIntentPayload(fenced); err == nil {
			return parsed, nil
		}
	}

	if extracted := extractFirstJSONObject(payload); extracted != "" {
		if parsed, err := decodeIntentPayload(extracted); err == nil {
			return parsed, nil
		}
	}

	return llmIntentPayload{}, fmt.Errorf("invalid intent JSON: expected a single JSON object with keys action_category, network_required, requested_paths, confidence")
}

func decodeIntentPayload(raw string) (llmIntentPayload, error) {
	var llm llmIntentPayload
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&llm); err != nil {
		return llmIntentPayload{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return llmIntentPayload{}, fmt.Errorf("intent JSON contains trailing data")
	}
	return llm, nil
}

func extractFencedJSON(content string) string {
	start := strings.Index(content, "```")
	for start >= 0 {
		rest := content[start+3:]
		newline := strings.Index(rest, "\n")
		if newline < 0 {
			return ""
		}
		lang := strings.TrimSpace(rest[:newline])
		block := rest[newline+1:]
		end := strings.Index(block, "```")
		if end < 0 {
			return ""
		}
		candidate := strings.TrimSpace(block[:end])
		if lang == "" || strings.EqualFold(lang, "json") {
			return candidate
		}
		nextIdx := strings.Index(block[end+3:], "```")
		if nextIdx < 0 {
			return ""
		}
		start = start + 3 + newline + 1 + end + 3 + nextIdx
	}
	return ""
}

func extractFirstJSONObject(content string) string {
	start := strings.Index(content, "{")
	if start < 0 {
		return ""
	}

	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(content); i++ {
		ch := content[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return strings.TrimSpace(content[start : i+1])
			}
		}
	}

	return ""
}

func jsonSchemaResponseFormat() map[string]interface{} {
	return map[string]interface{}{
		"type": "json_schema",
		"json_schema": map[string]interface{}{
			"name":   "policy_intent",
			"strict": true,
			"schema": map[string]interface{}{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"action_category", "network_required", "requested_paths", "confidence"},
				"properties": map[string]interface{}{
					"action_category": map[string]interface{}{
						"type": "string",
						"enum": []string{"restricted", "read_only_analysis", "code_execution"},
					},
					"network_required": map[string]interface{}{
						"type": "boolean",
					},
					"requested_paths": map[string]interface{}{
						"type":  "array",
						"items": map[string]interface{}{"type": "string"},
					},
					"confidence": map[string]interface{}{
						"type":    "number",
						"minimum": 0,
						"maximum": 1,
					},
				},
			},
		},
	}
}

func buildOpenAIEndpoint(baseURL, endpoint string) string {
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
			return endpoint
		}
		if baseURL == "" {
			return ""
		}
		return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(endpoint, "/")
	}
	if baseURL == "" {
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/chat/completions"
}

func resolveOpenAIAPIKey(cfg IntentExtractorConfig) string {
	if v := strings.TrimSpace(os.Getenv("ENCLAVE_POLICY_INTENT_OPENAI_API_KEY")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")); v != "" {
		return v
	}
	if allowAPIKeyHint() {
		if v := strings.TrimSpace(cfg.APIKey); v != "" {
			return v
		}
	}
	return ""
}

func sanitizeContextJSONForPrompt(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return raw
	}

	policyIntent, ok := payload["policy_intent"].(map[string]interface{})
	if ok {
		delete(policyIntent, "api_key")
		delete(policyIntent, "apiKey")
	}

	redacted, err := json.Marshal(payload)
	if err != nil {
		return raw
	}
	return string(redacted)
}

func formatOpenAIStatusError(statusCode int, endpoint string, hasAPIKey bool, body []byte) error {
	errMsg := strings.TrimSpace(extractOpenAIErrorMessage(body))
	host := "unknown-host"
	if u, err := url.Parse(endpoint); err == nil && strings.TrimSpace(u.Host) != "" {
		host = u.Host
	}

	if statusCode == http.StatusUnauthorized {
		if !hasAPIKey {
			return &openAIStatusError{StatusCode: statusCode, Message: "missing API key for policy intent extractor; configure endpoint API key in the client config or set ENCLAVE_POLICY_INTENT_OPENAI_API_KEY"}
		}
		if errMsg != "" {
			return &openAIStatusError{StatusCode: statusCode, Message: fmt.Sprintf("authentication denied by %s: %s", host, errMsg)}
		}
		return &openAIStatusError{StatusCode: statusCode, Message: fmt.Sprintf("authentication denied by %s; verify API key and endpoint", host)}
	}

	if statusCode == http.StatusBadRequest && isResponseFormatCompatibilityMessage(errMsg) {
		hint := fmt.Sprintf("%s may not support structured response_format json_schema. Verify OpenAI-compatible endpoint behavior or use response_format.type=text", host)
		if errMsg != "" {
			return &openAIStatusError{StatusCode: statusCode, Message: errMsg, Hint: hint}
		}
		return &openAIStatusError{StatusCode: statusCode, Hint: hint}
	}

	if errMsg != "" {
		return &openAIStatusError{StatusCode: statusCode, Message: errMsg}
	}
	return &openAIStatusError{StatusCode: statusCode}
}

func isResponseFormatCompatibilityMessage(message string) bool {
	msg := strings.ToLower(strings.TrimSpace(message))
	if msg == "" {
		return false
	}
	if !strings.Contains(msg, "response_format") {
		return false
	}
	if strings.Contains(msg, "json_schema") || strings.Contains(msg, "json_object") || strings.Contains(msg, "must be") || strings.Contains(msg, "unsupported") || strings.Contains(msg, "not supported") {
		return true
	}
	return false
}

func extractOpenAIErrorMessage(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}

	var parsed struct {
		Error struct {
			Message string `json:"message"`
			Code    string `json:"code"`
			Type    string `json:"type"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return trimmed
	}

	parts := []string{}
	if parsed.Error.Message != "" {
		parts = append(parts, parsed.Error.Message)
	}
	if parsed.Error.Code != "" {
		parts = append(parts, "code="+parsed.Error.Code)
	}
	if parsed.Error.Type != "" {
		parts = append(parts, "type="+parsed.Error.Type)
	}
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	if parsed.Message != "" {
		return parsed.Message
	}
	return trimmed
}

var pathPattern = regexp.MustCompile(`['"](/[^'"\s]+)['"]`)

func heuristicIntent(input string) Intent {
	normalized := strings.ToLower(input)
	intent := Intent{
		ActionCategory:  "restricted",
		NetworkRequired: strings.Contains(normalized, "http") || strings.Contains(normalized, "requests.") || strings.Contains(normalized, "urllib") || strings.Contains(normalized, "fetch("),
		RequestedPaths:  []string{},
	}

	if strings.Contains(normalized, "pd.read_csv") || strings.Contains(normalized, "open(") || strings.Contains(normalized, "read_text(") {
		intent.ActionCategory = "read_only_analysis"
	}

	matches := pathPattern.FindAllStringSubmatch(input, 8)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		candidate := strings.TrimSpace(match[1])
		if strings.HasPrefix(candidate, "/") {
			intent.RequestedPaths = append(intent.RequestedPaths, candidate)
		}
	}

	return sanitizeIntent(intent)
}

func sanitizeIntent(intent Intent) Intent {
	safe := Intent{
		ActionCategory:  "restricted",
		NetworkRequired: intent.NetworkRequired,
		RequestedPaths:  []string{},
	}

	switch strings.TrimSpace(intent.ActionCategory) {
	case "read_only_analysis", "code_execution", "restricted":
		safe.ActionCategory = intent.ActionCategory
	}

	seen := map[string]struct{}{}
	for _, p := range intent.RequestedPaths {
		path := strings.TrimSpace(p)
		if path == "" || !strings.HasPrefix(path, "/") {
			continue
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		safe.RequestedPaths = append(safe.RequestedPaths, path)
		if len(safe.RequestedPaths) >= 16 {
			break
		}
	}

	return safe
}

func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
