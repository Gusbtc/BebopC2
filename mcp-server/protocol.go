package main

import (
	"bufio"
	"encoding/json"
	"io"
)

const maxScannerBuffer = 16 * 1024 * 1024

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Server struct {
	client        *Client
	allowMutation bool
}

func NewServer(client *Client, allowMutation bool) *Server {
	return &Server{
		client:        client,
		allowMutation: allowMutation,
	}
}

func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScannerBuffer)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeResponse(out, rpcResponse{
				ID:    json.RawMessage("null"),
				Error: &rpcError{Code: -32700, Message: "parse error"},
			})
			continue
		}

		if len(req.ID) == 0 {
			s.handleNotification(req)
			continue
		}

		s.handle(out, req)
	}
	return scanner.Err()
}

func (s *Server) handleNotification(req rpcRequest) {
	switch req.Method {
	case "notifications/initialized":
		return
	default:
		return
	}
}

func (s *Server) handle(out io.Writer, req rpcRequest) {
	switch req.Method {
	case "initialize":
		writeResult(out, req.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"serverInfo": map[string]any{
				"name":    "bebop-mcp",
				"version": "1.5.0",
			},
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
		})
	case "tools/list":
		writeResult(out, req.ID, map[string]any{
			"tools": visibleTools(s.allowMutation),
		})
	case "tools/call":
		result, err := s.callTool(req.Params)
		if err != nil {
			writeResponse(out, rpcResponse{
				ID:    req.ID,
				Error: &rpcError{Code: -32000, Message: err.Error()},
			})
			return
		}
		writeResult(out, req.ID, result)
	case "resources/list":
		writeResult(out, req.ID, map[string]any{
			"resources": resourceList(),
		})
	case "resources/read":
		result, err := s.readResource(req.Params)
		if err != nil {
			writeResponse(out, rpcResponse{
				ID:    req.ID,
				Error: &rpcError{Code: -32000, Message: err.Error()},
			})
			return
		}
		writeResult(out, req.ID, result)
	default:
		writeResponse(out, rpcResponse{
			ID:    req.ID,
			Error: &rpcError{Code: -32601, Message: "method not found"},
		})
	}
}

func writeResult(out io.Writer, id json.RawMessage, result any) {
	encoded, err := json.Marshal(result)
	if err != nil {
		writeResponse(out, rpcResponse{
			ID:    id,
			Error: &rpcError{Code: -32603, Message: "internal error"},
		})
		return
	}

	writeResponse(out, rpcResponse{
		ID:     id,
		Result: encoded,
	})
}

func writeResponse(out io.Writer, resp rpcResponse) {
	if resp.JSONRPC == "" {
		resp.JSONRPC = "2.0"
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = out.Write(append(encoded, '\n'))
}
