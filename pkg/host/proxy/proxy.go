package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	agentv1 "enclave/api/v1"
	"enclave/api/v1/agentv1connect"
	"enclave/pkg/host/audit"
	"enclave/pkg/host/policy"
	"enclave/pkg/host/vmm"
	"enclave/pkg/shared/logger"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Secure by default: Allow same-origin and local development origins.
		// In production, this should be restricted to the specific authorized client origins.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Not a cross-origin request
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		// Allow localhost and 127.0.0.1 for development
		host := strings.Split(u.Host, ":")[0]
		return host == "localhost" || host == "127.0.0.1" || host == "enclave"
	},
}

var log = logger.New(os.Stdout)

type Proxy struct {
	client    agentv1connect.AgentServiceClient
	mgr       *vmm.Manager
	logWriter *audit.AsyncLogWriter
	policy    *policy.Engine
	extractor *policy.Extractor
}

type policyIntentSettings struct {
	Enabled    bool
	StrictMode bool
	Provider   string
	Model      string
	BaseURL    string
	Endpoint   string
	APIKey     string
}

type policyProbeSettings struct {
	Enabled         bool
	Scenario        string
	ExpectedBlocked bool
	EvaluationInput policy.EvaluationInput
}

func parseLineage(meta map[string]interface{}) (executionID, originKind, originConversationID string) {
	if meta == nil {
		return "", "", ""
	}
	originRaw, ok := meta["origin"].(map[string]interface{})
	if !ok {
		return "", "", ""
	}

	if src, ok := originRaw["source"].(map[string]interface{}); ok {
		if v, ok := src["kind"].(string); ok {
			originKind = v
		}
		if v, ok := src["conversationId"].(string); ok {
			originConversationID = v
		}
	}

	if exec, ok := originRaw["execution"].(map[string]interface{}); ok {
		if v, ok := exec["executionId"].(string); ok {
			executionID = v
		}
	}

	return executionID, originKind, originConversationID
}

func parseJSONMetadata(raw string) map[string]interface{} {
	if raw == "" {
		return map[string]interface{}{}
	}
	meta := map[string]interface{}{}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return map[string]interface{}{}
	}
	return meta
}

func parsePolicyIntentSettings(meta map[string]interface{}) policyIntentSettings {
	settings := policyIntentSettings{
		Enabled:    false,
		StrictMode: false,
		Provider:   "heuristic",
	}
	if meta == nil {
		return settings
	}

	raw, ok := meta["policy_intent"].(map[string]interface{})
	if !ok {
		return settings
	}

	if v, ok := raw["enabled"].(bool); ok {
		settings.Enabled = v
	}
	if v, ok := raw["strict_mode"].(bool); ok {
		settings.StrictMode = v
	}
	if v, ok := raw["provider"].(string); ok && strings.TrimSpace(v) != "" {
		settings.Provider = strings.TrimSpace(v)
	}
	if v, ok := raw["model"].(string); ok {
		settings.Model = strings.TrimSpace(v)
	}
	if v, ok := raw["base_url"].(string); ok {
		settings.BaseURL = strings.TrimSpace(v)
	}
	if v, ok := raw["endpoint"].(string); ok {
		settings.Endpoint = strings.TrimSpace(v)
	}
	if v, ok := raw["api_key"].(string); ok {
		settings.APIKey = strings.TrimSpace(v)
	}

	if settings.Provider == "openai" && settings.Endpoint == "" {
		if v, ok := raw["baseUrl"].(string); ok {
			settings.BaseURL = strings.TrimSpace(v)
		}
		if v, ok := raw["apiKey"].(string); ok {
			settings.APIKey = strings.TrimSpace(v)
		}
	}

	return settings
}

func parsePolicyProbeSettings(meta map[string]interface{}) (policyProbeSettings, bool) {
	settings := policyProbeSettings{}
	if meta == nil {
		return settings, false
	}

	raw, ok := meta["policy_probe"].(map[string]interface{})
	if !ok {
		return settings, false
	}

	enabled, ok := raw["enabled"].(bool)
	if !ok || !enabled {
		return settings, false
	}
	settings.Enabled = true

	if v, ok := raw["scenario"].(string); ok {
		settings.Scenario = strings.TrimSpace(v)
	}
	if v, ok := raw["expected_blocked"].(bool); ok {
		settings.ExpectedBlocked = v
	}

	evalRaw, ok := raw["eval_input"].(map[string]interface{})
	if !ok {
		return policyProbeSettings{}, false
	}

	sessionID, ok := evalRaw["session_id"].(string)
	if !ok || strings.TrimSpace(sessionID) == "" {
		return policyProbeSettings{}, false
	}
	userRole, ok := evalRaw["user_role"].(string)
	if !ok || strings.TrimSpace(userRole) == "" {
		return policyProbeSettings{}, false
	}
	agentFramework, ok := evalRaw["agent_framework"].(string)
	if !ok || strings.TrimSpace(agentFramework) == "" {
		return policyProbeSettings{}, false
	}

	intentRaw, ok := evalRaw["intent"].(map[string]interface{})
	if !ok {
		return policyProbeSettings{}, false
	}
	actionCategory, ok := intentRaw["action_category"].(string)
	if !ok || strings.TrimSpace(actionCategory) == "" {
		return policyProbeSettings{}, false
	}
	networkRequired, ok := intentRaw["network_required"].(bool)
	if !ok {
		return policyProbeSettings{}, false
	}

	requestedPathsRaw, ok := intentRaw["requested_paths"].([]interface{})
	if !ok {
		return policyProbeSettings{}, false
	}
	requestedPaths := make([]string, 0, len(requestedPathsRaw))
	for _, item := range requestedPathsRaw {
		path, ok := item.(string)
		if !ok {
			return policyProbeSettings{}, false
		}
		trimmed := strings.TrimSpace(path)
		if trimmed == "" || !strings.HasPrefix(trimmed, "/") {
			return policyProbeSettings{}, false
		}
		requestedPaths = append(requestedPaths, trimmed)
	}

	switch strings.TrimSpace(actionCategory) {
	case "restricted", "read_only_analysis", "code_execution":
	default:
		return policyProbeSettings{}, false
	}

	settings.EvaluationInput = policy.EvaluationInput{
		SessionID:      strings.TrimSpace(sessionID),
		UserRole:       strings.TrimSpace(userRole),
		AgentFramework: strings.TrimSpace(agentFramework),
		Intent: policy.Intent{
			ActionCategory:  strings.TrimSpace(actionCategory),
			NetworkRequired: networkRequired,
			RequestedPaths:  requestedPaths,
		},
	}

	return settings, true
}

func extractOriginMetadata(meta map[string]interface{}) map[string]interface{} {
	if meta == nil {
		return nil
	}
	if origin, ok := meta["origin"].(map[string]interface{}); ok {
		return origin
	}
	source, hasSource := meta["source"].(map[string]interface{})
	exec, hasExec := meta["execution"].(map[string]interface{})
	if !hasSource && !hasExec {
		return nil
	}
	origin := map[string]interface{}{}
	if hasSource {
		origin["source"] = source
	}
	if hasExec {
		origin["execution"] = exec
	}
	return origin
}

func cloneMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return map[string]interface{}{}
	}
	output := make(map[string]interface{}, len(input))
	for k, v := range input {
		output[k] = v
	}
	return output
}

func (p *Proxy) pushPolicyEvent(sessionID, action, status, input string, metadata map[string]interface{}) {
	p.logWriter.Push(&audit.Entry{
		SessionID: sessionID,
		Action:    action,
		Status:    status,
		Input:     input,
		Metadata:  metadata,
	})
}

// New creates a new Proxy that listens for external requests and forwards them to the Guest VM.
func New(mgr *vmm.Manager, port uint32, logWriter *audit.AsyncLogWriter) *Proxy {
	dialer := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		udsPath := mgr.GetSocketPath() + ".vsock"
		conn, err := net.Dial("unix", udsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to dial uds: %w", err)
		}
		msg := fmt.Sprintf("CONNECT %d\n", port)
		if _, err := conn.Write([]byte(msg)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to write handshake: %w", err)
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read handshake response: %w", err)
		}
		resp := string(buf[:n])
		if len(resp) < 2 || resp[:2] != "OK" {
			conn.Close()
			return nil, fmt.Errorf("handshake failed: %s", resp)
		}
		return conn, nil
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}

	client := agentv1connect.NewAgentServiceClient(
		httpClient,
		"http://tensor-agent",
	)

	policyEngine, policyErr := policy.New(context.Background())
	if policyErr != nil {
		log.Error("Failed to initialize policy engine: %v", policyErr)
	}

	return &Proxy{
		client:    client,
		mgr:       mgr,
		logWriter: logWriter,
		policy:    policyEngine,
		extractor: policy.NewExtractor(),
	}
}

// StartSession handles requests to start a session.
func (p *Proxy) StartSession(ctx context.Context, req *connect.Request[agentv1.StartRequest]) (*connect.Response[agentv1.SessionResponse], error) {
	log.Info("StartSession request received for session: %s", req.Msg.SessionId)

	return connect.NewResponse(&agentv1.SessionResponse{
		SessionId:  req.Msg.SessionId,
		Status:     "READY",
		SocketPath: p.mgr.GetSocketPath(),
	}), nil
}

// ExecuteTool forwards the tool execution request to the Guest Agent.
func (p *Proxy) ExecuteTool(ctx context.Context, req *connect.Request[agentv1.ToolRequest]) (*connect.Response[agentv1.ToolResponse], error) {
	log.Info("ExecuteTool request: %s (Policy: %s)", req.Msg.ToolName, req.Msg.PolicyId)

	contextMeta := map[string]interface{}{}
	if raw := req.Msg.ContextJson; raw != "" {
		if err := json.Unmarshal([]byte(raw), &contextMeta); err != nil {
			log.Error("Failed to parse context_json: %v", err)
		}
	}
	originMeta := extractOriginMetadata(contextMeta)
	intentSettings := parsePolicyIntentSettings(contextMeta)
	probeSettings, probeEnabled := parsePolicyProbeSettings(contextMeta)

	extractCfg := policy.IntentExtractorConfig{
		Enabled:    intentSettings.Enabled,
		StrictMode: intentSettings.StrictMode,
		Provider:   intentSettings.Provider,
		Model:      intentSettings.Model,
		BaseURL:    intentSettings.BaseURL,
		Endpoint:   intentSettings.Endpoint,
		APIKey:     intentSettings.APIKey,
	}
	if !extractCfg.Enabled {
		extractCfg.Provider = "heuristic"
	}

	var (
		extractResult policy.ExtractorResult
		extractErr    error
	)
	if probeEnabled {
		extractResult = policy.ExtractorResult{
			EvaluationInput: probeSettings.EvaluationInput,
			Metadata: policy.ExtractorMetadata{
				Provider:     "probe",
				Model:        "context_json",
				Confidence:   1,
				LatencyMS:    0,
				SourceMethod: "probe_override",
			},
		}
	} else {
		extractResult, extractErr = p.extractor.Extract(ctx, policy.ExtractorRequest{
			SessionID:   req.Msg.SessionId,
			ToolName:    req.Msg.ToolName,
			Input:       req.Msg.Input,
			ContextJSON: req.Msg.ContextJson,
		}, extractCfg)
	}

	intentMeta := map[string]interface{}{
		"provider":      extractResult.Metadata.Provider,
		"model":         extractResult.Metadata.Model,
		"latency_ms":    extractResult.Metadata.LatencyMS,
		"confidence":    extractResult.Metadata.Confidence,
		"source_method": extractResult.Metadata.SourceMethod,
		"strict_mode":   intentSettings.StrictMode,
		"intent":        extractResult.EvaluationInput.Intent,
	}
	if extractResult.Metadata.Error != "" {
		intentMeta["error"] = extractResult.Metadata.Error
	}
	if probeEnabled {
		intentMeta["scenario"] = probeSettings.Scenario
		intentMeta["expected_blocked"] = probeSettings.ExpectedBlocked
	}
	if originMeta != nil {
		intentMeta["origin"] = originMeta
	}

	intentStatus := "COMPLETED"
	if extractErr != nil {
		intentStatus = "ERROR"
	}
	p.pushPolicyEvent(req.Msg.SessionId, "POLICY:INTENT_EXTRACTED", intentStatus, req.Msg.ToolName, intentMeta)

	if extractErr != nil && intentSettings.StrictMode {
		intentMeta["strict_blocked"] = true
		p.pushPolicyEvent(req.Msg.SessionId, "POLICY:ENFORCEMENT_FAILED", "BLOCKED", req.Msg.ToolName, intentMeta)
		return nil, fmt.Errorf("strict policy intent extraction failed: %w", extractErr)
	}

	// 1. JIT Policy Evaluation
	evalInput := extractResult.EvaluationInput
	var (
		verdict *policy.Verdict
		err     error
	)
	if p.policy == nil {
		err = fmt.Errorf("policy engine unavailable")
	} else {
		verdict, err = p.policy.Evaluate(ctx, evalInput)
	}
	opaMeta := map[string]interface{}{
		"provider":      extractResult.Metadata.Provider,
		"model":         extractResult.Metadata.Model,
		"source_method": extractResult.Metadata.SourceMethod,
		"strict_mode":   intentSettings.StrictMode,
		"intent":        evalInput.Intent,
	}
	if probeEnabled {
		opaMeta["scenario"] = probeSettings.Scenario
		opaMeta["expected_blocked"] = probeSettings.ExpectedBlocked
	}
	if originMeta != nil {
		opaMeta["origin"] = originMeta
	}
	if err != nil {
		log.Error("Policy evaluation failed: %v", err)
		opaMeta["error"] = err.Error()
		if intentSettings.StrictMode {
			opaMeta["strict_blocked"] = true
		}
		p.pushPolicyEvent(req.Msg.SessionId, "POLICY:OPA_VERDICT", "ERROR", req.Msg.ToolName, opaMeta)
		if intentSettings.StrictMode {
			p.pushPolicyEvent(req.Msg.SessionId, "POLICY:ENFORCEMENT_FAILED", "BLOCKED", req.Msg.ToolName, opaMeta)
			return nil, fmt.Errorf("strict policy evaluation failed: %w", err)
		}
	} else {
		log.Info("Policy Verdict: Network=%v, ReadPaths=%v", verdict.AllowNetwork, verdict.AllowedReadPaths)
		networkBlocked := evalInput.Intent.NetworkRequired && !verdict.AllowNetwork
		opaMeta["verdict"] = verdict
		opaMeta["network_requested"] = evalInput.Intent.NetworkRequired
		opaStatus := "COMPLETED"
		if networkBlocked {
			opaStatus = "BLOCKED"
			opaMeta["blocked_reason"] = "network_required_but_policy_denied"
		}
		p.pushPolicyEvent(req.Msg.SessionId, "POLICY:OPA_VERDICT", opaStatus, req.Msg.ToolName, opaMeta)

		// 2. Compile and Inject Tetragon Policy (via Vsock)
		yaml, compileErr := policy.Compile(policy.CompilerInput{
			SessionID: req.Msg.SessionId,
			Verdict:   verdict,
		})
		if compileErr == nil {
			applyResp, applyErr := p.client.ApplyPolicy(ctx, connect.NewRequest(&agentv1.ApplyPolicyRequest{
				SessionId:  req.Msg.SessionId,
				PolicyYaml: yaml,
			}))
			if applyErr != nil || applyResp == nil || !applyResp.Msg.Success {
				applyErrText := ""
				if applyErr != nil {
					applyErrText = applyErr.Error()
				} else if applyResp == nil {
					applyErrText = "guest returned empty ApplyPolicy response"
				} else {
					applyErrText = strings.TrimSpace(applyResp.Msg.Error)
					if applyErrText == "" {
						applyErrText = "guest reported policy apply failure"
					}
				}
				log.Error("Failed to apply JIT Policy to Guest: %s", applyErrText)
				enforcementMeta := cloneMap(opaMeta)
				enforcementMeta["error"] = applyErrText
				enforcementMeta["stage"] = "apply"
				if intentSettings.StrictMode {
					enforcementMeta["strict_blocked"] = true
				}
				p.pushPolicyEvent(req.Msg.SessionId, "POLICY:ENFORCEMENT_FAILED", "ERROR", req.Msg.ToolName, enforcementMeta)
				if intentSettings.StrictMode {
					return nil, fmt.Errorf("strict policy apply failed: %s", applyErrText)
				}
			} else {
				log.Info("JIT Policy Delivered to Guest via Vsock")
				enforcementMeta := cloneMap(opaMeta)
				enforcementMeta["stage"] = "apply"
				p.pushPolicyEvent(req.Msg.SessionId, "POLICY:ENFORCEMENT_APPLIED", "COMPLETED", req.Msg.ToolName, enforcementMeta)
			}
		} else {
			log.Error("Policy compilation failed: %v", compileErr)
			enforcementMeta := cloneMap(opaMeta)
			enforcementMeta["error"] = compileErr.Error()
			enforcementMeta["stage"] = "compile"
			if intentSettings.StrictMode {
				enforcementMeta["strict_blocked"] = true
			}
			p.pushPolicyEvent(req.Msg.SessionId, "POLICY:ENFORCEMENT_FAILED", "ERROR", req.Msg.ToolName, enforcementMeta)
			if intentSettings.StrictMode {
				return nil, fmt.Errorf("strict policy compile failed: %w", compileErr)
			}
		}

		if networkBlocked {
			blockMeta := cloneMap(opaMeta)
			blockMeta["stage"] = "host_gate"
			blockMeta["reason"] = "network_required_but_policy_denied"
			p.pushPolicyEvent(req.Msg.SessionId, "POLICY:ENFORCEMENT_FAILED", "BLOCKED", req.Msg.ToolName, blockMeta)
			p.logWriter.Push(&audit.Entry{
				SessionID: req.Msg.SessionId,
				Action:    "TOOL:" + req.Msg.ToolName,
				Input:     req.Msg.Input,
				Output:    "",
				Status:    "BLOCKED",
				Metadata: map[string]interface{}{
					"blocked_reason": "network_required_but_policy_denied",
					"origin":         originMeta,
				},
			})
			return nil, fmt.Errorf("policy blocked execution: requested network access is denied")
		}
	}

	// 3. Forward to Guest
	resp, err := p.client.ExecuteTool(ctx, req)
	if err != nil {
		log.Error("Failed to forward ExecuteTool to guest: %v", err)
		return nil, err
	}

	// 4. Log Audit
	toolMeta := map[string]interface{}{"exit_code": resp.Msg.ExitCode}
	if originMeta != nil {
		toolMeta["origin"] = originMeta
	}

	p.logWriter.Push(&audit.Entry{
		SessionID: req.Msg.SessionId,
		Action:    "TOOL:" + req.Msg.ToolName,
		Input:     req.Msg.Input,
		Output:    resp.Msg.Output,
		Status:    "COMPLETED",
		Metadata:  toolMeta,
	})

	// Log Syscalls from eBPF
	baseTime := time.Now()
	for i, syscall := range resp.Msg.SyscallLogs {
		category := "OTHER"
		switch syscall.Name {
		case "openat", "read", "write", "unlink":
			category = "FILE"
		case "execve":
			category = "EXECUTE"
		case "connect", "accept", "bind", "socket":
			category = "NETWORK"
		case "fork", "exec", "process_fork", "process_exec":
			category = "PROCESS"
		}

		sysMeta := parseJSONMetadata(syscall.MetadataJson)
		if _, ok := sysMeta["pid"]; !ok {
			sysMeta["pid"] = syscall.Pid
		}
		if _, ok := sysMeta["event_name"]; !ok && syscall.Name != "" {
			sysMeta["event_name"] = syscall.Name
		}
		if _, ok := sysMeta["event_kind"]; !ok {
			sysMeta["event_kind"] = "syscall"
		}
		if originMeta != nil {
			sysMeta["origin"] = originMeta
		}

		action := syscall.Action
		if action == "" {
			action = fmt.Sprintf("SYSCALL:%s:%s", category, syscall.Name)
		}

		status := syscall.Status
		if status == "" {
			status = "ALLOWED"
		}

		p.logWriter.Push(&audit.Entry{
			SessionID: req.Msg.SessionId,
			Timestamp: baseTime.Add(time.Duration(i+1) * time.Nanosecond),
			Action:    action,
			Input:     syscall.Args,
			Status:    status,
			Metadata:  sysMeta,
		})
	}

	// Optimistically clear logs
	resp.Msg.SyscallLogs = nil
	return resp, nil
}

// StopSession shuts down the VM.
func (p *Proxy) StopSession(ctx context.Context, req *connect.Request[agentv1.StopRequest]) (*connect.Response[agentv1.StopResponse], error) {
	log.Info("StopSession request received")
	if err := p.mgr.Stop(); err != nil {
		log.Error("Failed to stop VMM: %v", err)
		return nil, err
	}
	return connect.NewResponse(&agentv1.StopResponse{Success: true}), nil
}

// GetAuditLogs retrieves the audit logs for a session.
func (p *Proxy) GetAuditLogs(ctx context.Context, req *connect.Request[agentv1.GetAuditLogsRequest]) (*connect.Response[agentv1.GetAuditLogsResponse], error) {
	logs, err := p.logWriter.GetLogs(ctx, req.Msg.SessionId, int(req.Msg.Limit))
	if err != nil {
		return nil, err
	}

	var pbLogs []*agentv1.SyscallLog
	for _, l := range logs {
		metaJSON, _ := json.Marshal(l.Metadata)
		executionID, originKind, originConversationID := parseLineage(l.Metadata)

		pbLogs = append(pbLogs, &agentv1.SyscallLog{
			Timestamp:            l.Timestamp.UnixNano(),
			Name:                 l.Action,
			Action:               l.Action,
			Args:                 l.Input,
			Status:               l.Status,
			SessionId:            l.SessionID,
			MetadataJson:         string(metaJSON),
			ExecutionId:          executionID,
			OriginKind:           originKind,
			OriginConversationId: originConversationID,
		})
	}
	return connect.NewResponse(&agentv1.GetAuditLogsResponse{Logs: pbLogs}), nil
}

func (p *Proxy) ApplyPolicy(ctx context.Context, req *connect.Request[agentv1.ApplyPolicyRequest]) (*connect.Response[agentv1.ApplyPolicyResponse], error) {
	log.Info("Forwarding ApplyPolicy to guest for session: %s", req.Msg.SessionId)
	return p.client.ApplyPolicy(ctx, req)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ws/audit" {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Error("WebSocket upgrade failed: %v", err)
			return
		}
		if p.logWriter != nil && p.logWriter.GetHub() != nil {
			p.logWriter.GetHub().Register(conn)
		}
		return
	}
	http.NotFound(w, r)
}
