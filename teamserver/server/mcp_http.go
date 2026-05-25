package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"c2/auth"
)

const mcpMaxRequestBytes int64 = 384 << 20
const mcpProtocolVersion = "2025-06-18"
const mcpMaxStreams = 64
const mcpStreamMaxLifetime = 15 * time.Minute

var mcpStreamSlots = make(chan struct{}, mcpMaxStreams)

type mcpRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpHTTPServer struct {
	client        *mcpTeamserverClient
	allowMutation bool
	auth          mcpAuthContext
}

func newMCPHTTPServer(client *mcpTeamserverClient, allowMutation bool) *mcpHTTPServer {
	return &mcpHTTPServer{client: client, allowMutation: allowMutation}
}

func (h *Handler) HandleMCPRPC(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, mcpMaxRequestBytes)
	defer r.Body.Close()

	var req mcpRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mcpWriteResponse(w, mcpRPCResponse{
			ID:    json.RawMessage("null"),
			Error: &mcpRPCError{Code: -32700, Message: "parse error"},
		})
		return
	}

	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	rawToken := bearerToken(r)
	internalToken, err := h.mcpInternalBearer(rawToken)
	if err != nil {
		mcpWriteResponse(w, mcpError(req.ID, -32603, "internal auth error"))
		return
	}
	authCtx, _ := r.Context().Value(mcpAuthKey).(mcpAuthContext)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", h.managementPort)
	server := newMCPHTTPServer(newMCPTeamserverClient(baseURL, internalToken), mcpMutationAllowed())
	server.auth = authCtx
	mcpWriteResponse(w, server.handle(req))
}

func (h *Handler) HandleMCPStream(w http.ResponseWriter, r *http.Request) {
	if !mcpAcquireStream() {
		http.Error(w, "too many MCP streams", http.StatusTooManyRequests)
		return
	}
	defer mcpReleaseStream()
	mcpSetProtocolHeaders(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, ": bebop mcp stream\n\n")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	var hubEvents chan Event
	if h.hub != nil {
		hubEvents = h.hub.Subscribe()
		defer h.hub.Unsubscribe(hubEvents)
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	lifetime := time.NewTimer(mcpStreamMaxLifetime)
	defer lifetime.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case evt := <-hubEvents:
			mcpWriteSSE(w, "message", evt)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		case <-ticker.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

func mcpWriteSSE(w io.Writer, event string, data any) {
	encoded, err := json.Marshal(data)
	if err != nil {
		encoded = []byte(`null`)
	}
	_, _ = fmt.Fprintf(w, "event: %s\n", event)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
}

func mcpAcquireStream() bool {
	select {
	case mcpStreamSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func mcpReleaseStream() {
	select {
	case <-mcpStreamSlots:
	default:
	}
}

func (h *Handler) mcpInternalBearer(rawToken string) (string, error) {
	if authCtx, ok := validateMCPToken(rawToken); ok {
		operator := normalizeMCPOperator(authCtx.Operator)
		if !h.operatorExists(operator) {
			return "", fmt.Errorf("operator not found")
		}
		return auth.SignToken(operator, h.jwtKey)
	}
	return rawToken, nil
}

func (s *mcpHTTPServer) handle(req mcpRPCRequest) mcpRPCResponse {
	switch req.Method {
	case "initialize":
		return mcpResult(req.ID, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"serverInfo": map[string]any{
				"name":    "bebop-http-mcp",
				"version": "1.5.0",
			},
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
		})
	case "tools/list":
		return mcpResult(req.ID, map[string]any{"tools": mcpVisibleToolsForAuth(s.allowMutation, s.auth)})
	case "tools/call":
		result, err := s.callTool(req.Params)
		if err != nil {
			return mcpError(req.ID, -32000, err.Error())
		}
		return mcpResult(req.ID, result)
	case "resources/list":
		if !s.auth.HasScope(mcpScopeRead) {
			return mcpError(req.ID, -32000, "missing MCP scope: read")
		}
		return mcpResult(req.ID, map[string]any{"resources": mcpResourceList()})
	case "resources/read":
		if !s.auth.HasScope(mcpScopeRead) {
			return mcpError(req.ID, -32000, "missing MCP scope: read")
		}
		result, err := s.readResource(req.Params)
		if err != nil {
			return mcpError(req.ID, -32000, err.Error())
		}
		return mcpResult(req.ID, result)
	default:
		return mcpError(req.ID, -32601, "method not found")
	}
}

func mcpResult(id json.RawMessage, result any) mcpRPCResponse {
	encoded, err := json.Marshal(result)
	if err != nil {
		return mcpError(id, -32603, "internal error")
	}
	return mcpRPCResponse{ID: id, Result: encoded}
}

func mcpError(id json.RawMessage, code int, message string) mcpRPCResponse {
	return mcpRPCResponse{ID: id, Error: &mcpRPCError{Code: code, Message: message}}
}

func mcpWriteResponse(w http.ResponseWriter, resp mcpRPCResponse) {
	if resp.JSONRPC == "" {
		resp.JSONRPC = "2.0"
	}
	mcpSetProtocolHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func mcpSetProtocolHeaders(w http.ResponseWriter) {
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
}
