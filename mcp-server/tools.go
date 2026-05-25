package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Mutating    bool           `json:"-"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type idArgs struct {
	BeaconID uint32 `json:"beacon_id"`
}

type commandArgs struct {
	BeaconID  uint32   `json:"beacon_id"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Transport string   `json:"transport"`
}

type moduleArgs struct {
	BeaconID     uint32   `json:"beacon_id"`
	ObjectName   string   `json:"object_name"`
	AssemblyName string   `json:"assembly_name"`
	Args         []string `json:"args"`
	Mode         string   `json:"mode"`
}

func allTools() []toolDef {
	beaconID := integerProperty(1, 0)
	beaconIDSchema := objectSchema(
		map[string]any{"beacon_id": beaconID},
		[]string{"beacon_id"},
	)

	return []toolDef{
		{
			Name:        "sessions.list",
			Description: "List active beacon sessions.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "session.get",
			Description: "Get one beacon session by ID.",
			InputSchema: objectSchema(
				map[string]any{"beacon_id": beaconID},
				[]string{"beacon_id"},
			),
		},
		{
			Name:        "results.list",
			Description: "List task results for a beacon.",
			InputSchema: objectSchema(
				map[string]any{
					"beacon_id": beaconID,
					"since":     integerProperty(0, 0),
				},
				[]string{"beacon_id"},
			),
		},
		{
			Name:        "events.list",
			Description: "List operator event log entries.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "loot.list",
			Description: "List exfiltrated loot files.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "library.list",
			Description: "List available BOF and inline assembly modules.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "command.run",
			Description: "Run a command on a beacon.",
			InputSchema: objectSchema(
				map[string]any{
					"beacon_id": beaconID,
					"command":   stringProperty(),
					"args":      stringArrayProperty([]string{}),
					"transport": enumStringProperty([]string{"auto", "http", "session"}, "auto"),
				},
				[]string{"beacon_id", "command"},
			),
			Mutating: true,
		},
		{
			Name:        "bof.execute",
			Description: "Execute a BOF module on a beacon.",
			InputSchema: objectSchema(
				map[string]any{
					"beacon_id":   beaconID,
					"object_name": stringProperty(),
					"args":        stringArrayProperty([]string{}),
				},
				[]string{"beacon_id", "object_name"},
			),
			Mutating: true,
		},
		{
			Name:        "inline-assembly.execute",
			Description: "Execute an inline assembly module on a beacon.",
			InputSchema: objectSchema(
				map[string]any{
					"beacon_id":     beaconID,
					"assembly_name": stringProperty(),
					"args":          stringArrayProperty([]string{}),
					"mode":          enumStringProperty([]string{"auto", "bridge"}, "auto"),
				},
				[]string{"beacon_id", "assembly_name"},
			),
			Mutating: true,
		},
		{
			Name:        "beacon.sleep",
			Description: "Change beacon sleep interval and jitter.",
			InputSchema: objectSchema(
				map[string]any{
					"beacon_id": beaconID,
					"seconds":   integerProperty(0, 0),
					"jitter":    integerProperty(0, 100, withDefault(0)),
				},
				[]string{"beacon_id", "seconds"},
			),
			Mutating: true,
		},
		{
			Name:        "beacon.exit",
			Description: "Task a beacon to exit.",
			InputSchema: beaconIDSchema,
			Mutating:    true,
		},
		{
			Name:        "beacon.interactive",
			Description: "Start an interactive session for a beacon.",
			InputSchema: beaconIDSchema,
			Mutating:    true,
		},
		{
			Name:        "socks.start",
			Description: "Start SOCKS proxy through a beacon.",
			InputSchema: objectSchema(
				map[string]any{
					"beacon_id": beaconID,
					"port":      integerProperty(0, 65535, withDefault(0)),
				},
				[]string{"beacon_id"},
			),
			Mutating: true,
		},
		{
			Name:        "socks.stop",
			Description: "Stop SOCKS proxy by ID.",
			InputSchema: beaconIDSchema,
			Mutating:    true,
		},
	}
}

func visibleTools(allowMutation bool) []toolDef {
	tools := allTools()
	if allowMutation {
		return tools
	}

	visible := make([]toolDef, 0, len(tools))
	for _, tool := range tools {
		if !tool.Mutating {
			visible = append(visible, tool)
		}
	}
	return visible
}

func isMutatingTool(name string) bool {
	for _, tool := range allTools() {
		if tool.Name == name {
			return tool.Mutating
		}
	}
	return false
}

func contentResult(v interface{}) map[string]interface{} {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		encoded = []byte(fmt.Sprintf("%v", v))
	}
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": string(encoded),
			},
		},
	}
}

func (s *Server) callTool(raw json.RawMessage) (map[string]interface{}, error) {
	var params toolCallParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	if params.Name == "" {
		return nil, fmt.Errorf("missing tool name")
	}
	if !knownTool(params.Name) {
		return nil, fmt.Errorf("unknown tool: %s", params.Name)
	}
	if isMutatingTool(params.Name) && !s.allowMutation {
		return nil, fmt.Errorf("mutation disabled")
	}
	if s.client == nil {
		return nil, fmt.Errorf("teamserver client unavailable")
	}
	args := params.Arguments
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	var out interface{}
	switch params.Name {
	case "sessions.list":
		if err := s.client.getJSON("/api/sessions", &out); err != nil {
			return nil, err
		}
	case "session.get":
		var req idArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		sessions, err := s.listSessions()
		if err != nil {
			return nil, err
		}
		for _, session := range sessions {
			if numericID(session["id"]) == req.BeaconID {
				return contentResult(session), nil
			}
		}
		return nil, fmt.Errorf("session not found: %d", req.BeaconID)
	case "results.list":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Since    int64  `json:"since"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if err := s.client.getJSON(resultRoute(req.BeaconID, req.Since), &out); err != nil {
			return nil, err
		}
	case "events.list":
		if err := s.client.getJSON("/api/events", &out); err != nil {
			return nil, err
		}
	case "loot.list":
		if err := s.client.getJSON("/api/loot", &out); err != nil {
			return nil, err
		}
	case "library.list":
		if err := s.client.getJSON("/api/library", &out); err != nil {
			return nil, err
		}
	case "command.run":
		var req commandArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 || strings.TrimSpace(req.Command) == "" {
			return nil, fmt.Errorf("beacon_id and command required")
		}
		transport := strings.TrimSpace(req.Transport)
		if transport == "" || transport == "auto" {
			transport = "session"
		} else if transport != "http" && transport != "session" {
			return nil, fmt.Errorf("transport must be auto, http, or session")
		}
		body := map[string]interface{}{
			"beacon_id": req.BeaconID,
			"type":      12,
			"code":      0,
			"args":      joinCommandArgs(req.Command, req.Args),
			"transport": transport,
		}
		if err := s.client.postJSON("/api/task", body, &out); err != nil {
			return nil, err
		}
	case "bof.execute":
		var req moduleArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 || strings.TrimSpace(req.ObjectName) == "" {
			return nil, fmt.Errorf("beacon_id and object_name required")
		}
		fields := map[string]string{
			"beacon_id":   fmt.Sprintf("%d", req.BeaconID),
			"object_name": req.ObjectName,
			"args":        joinArgs(req.Args),
		}
		if err := s.client.postMultipart("/api/bof", fields, &out); err != nil {
			return nil, err
		}
	case "inline-assembly.execute":
		var req moduleArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 || strings.TrimSpace(req.AssemblyName) == "" {
			return nil, fmt.Errorf("beacon_id and assembly_name required")
		}
		mode := strings.TrimSpace(req.Mode)
		if mode == "" {
			mode = "auto"
		}
		if mode == "direct" {
			return nil, fmt.Errorf("direct mode disabled")
		}
		fields := map[string]string{
			"beacon_id":     fmt.Sprintf("%d", req.BeaconID),
			"assembly_name": req.AssemblyName,
			"args":          joinArgs(req.Args),
			"mode":          mode,
		}
		if err := s.client.postMultipart("/api/inline-assembly", fields, &out); err != nil {
			return nil, err
		}
	case "beacon.sleep":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Seconds  *int   `json:"seconds"`
			Jitter   int    `json:"jitter"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if req.Seconds == nil {
			return nil, fmt.Errorf("seconds required")
		}
		if *req.Seconds < 0 {
			return nil, fmt.Errorf("seconds must be >= 0")
		}
		if req.Jitter < 0 || req.Jitter > 100 {
			return nil, fmt.Errorf("jitter must be 0-100")
		}
		body := map[string]interface{}{
			"beacon_id": req.BeaconID,
			"type":      2,
			"code":      0,
			"args":      fmt.Sprintf("%d %d", *req.Seconds, req.Jitter),
		}
		if err := s.client.postJSON("/api/task", body, &out); err != nil {
			return nil, err
		}
	case "beacon.exit":
		var req idArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		body := map[string]interface{}{
			"beacon_id": req.BeaconID,
			"type":      1,
			"code":      0,
			"args":      "",
		}
		if err := s.client.postJSON("/api/task", body, &out); err != nil {
			return nil, err
		}
	case "beacon.interactive":
		var req idArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		body := map[string]interface{}{
			"beacon_id": req.BeaconID,
			"port":      4443,
		}
		if err := s.client.postJSON("/api/interactive", body, &out); err != nil {
			return nil, err
		}
	case "socks.start":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Port     int    `json:"port"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if req.Port < 0 || req.Port > 65535 {
			return nil, fmt.Errorf("port must be 0-65535")
		}
		body := map[string]interface{}{
			"beacon_id": req.BeaconID,
			"port":      req.Port,
		}
		if err := s.client.postJSON("/api/socks", body, &out); err != nil {
			return nil, err
		}
	case "socks.stop":
		var req idArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if err := s.client.deleteJSON(fmt.Sprintf("/api/socks/%d", req.BeaconID), nil); err != nil {
			return nil, err
		}
		out = map[string]interface{}{"stopped": req.BeaconID}
	}

	return contentResult(out), nil
}

func knownTool(name string) bool {
	for _, tool := range allTools() {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) listSessions() ([]map[string]interface{}, error) {
	var sessions []map[string]interface{}
	if err := s.client.getJSON("/api/sessions", &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func numericID(v interface{}) uint32 {
	switch id := v.(type) {
	case float64:
		return uint32(id)
	case int:
		return uint32(id)
	case uint32:
		return id
	case json.Number:
		n, _ := id.Int64()
		return uint32(n)
	}
	return 0
}

func resourceList() []map[string]interface{} {
	return []map[string]interface{}{
		{"uri": "bebop://sessions", "name": "sessions", "mimeType": "application/json"},
		{"uri": "bebop://sessions/{id}", "name": "session", "mimeType": "application/json"},
		{"uri": "bebop://results/{id}", "name": "results", "mimeType": "application/json"},
		{"uri": "bebop://events", "name": "events", "mimeType": "application/json"},
		{"uri": "bebop://loot", "name": "loot", "mimeType": "application/json"},
		{"uri": "bebop://library", "name": "library", "mimeType": "application/json"},
	}
}

func (s *Server) readResource(raw json.RawMessage) (map[string]interface{}, error) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	if params.URI == "" {
		return nil, fmt.Errorf("missing resource uri")
	}
	if s.client == nil {
		return nil, fmt.Errorf("teamserver client unavailable")
	}

	var out interface{}
	switch params.URI {
	case "bebop://sessions":
		if err := s.client.getJSON("/api/sessions", &out); err != nil {
			return nil, err
		}
	case "bebop://events":
		if err := s.client.getJSON("/api/events", &out); err != nil {
			return nil, err
		}
	case "bebop://loot":
		if err := s.client.getJSON("/api/loot", &out); err != nil {
			return nil, err
		}
	case "bebop://library":
		if err := s.client.getJSON("/api/library", &out); err != nil {
			return nil, err
		}
	default:
		if idText, ok := strings.CutPrefix(params.URI, "bebop://sessions/"); ok {
			beaconID, err := parseResourceID(idText, "session")
			if err != nil {
				return nil, err
			}
			session, err := s.readSessionByID(beaconID)
			if err != nil {
				return nil, err
			}
			out = session
		} else if idText, ok := strings.CutPrefix(params.URI, "bebop://results/"); ok {
			beaconID, err := parseResourceID(idText, "results")
			if err != nil {
				return nil, err
			}
			if err := s.client.getJSON(resultRoute(beaconID, 0), &out); err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("unknown resource: %s", params.URI)
		}
	}
	return resourceContents(params.URI, out), nil
}

func parseResourceID(text string, kind string) (uint32, error) {
	id, err := strconv.ParseUint(text, 10, 32)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid %s id: %s", kind, text)
	}
	return uint32(id), nil
}

func (s *Server) readSessionByID(beaconID uint32) (map[string]interface{}, error) {
	sessions, err := s.listSessions()
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if numericID(session["id"]) == beaconID {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session not found: %d", beaconID)
}

func resourceContents(uri string, v interface{}) map[string]interface{} {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		encoded = []byte(fmt.Sprintf("%v", v))
	}
	return map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"uri":      uri,
				"mimeType": "application/json",
				"text":     string(encoded),
			},
		},
	}
}

func emptySchema() map[string]any {
	return objectSchema(map[string]any{}, nil)
}

func objectSchema(properties map[string]any, required []string) map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

type propertyOption func(map[string]any)

func integerProperty(minimum int, maximum int, options ...propertyOption) map[string]any {
	property := map[string]any{
		"type":    "integer",
		"minimum": minimum,
	}
	if maximum > 0 {
		property["maximum"] = maximum
	}
	for _, option := range options {
		option(property)
	}
	return property
}

func stringProperty(options ...propertyOption) map[string]any {
	property := map[string]any{
		"type": "string",
	}
	for _, option := range options {
		option(property)
	}
	return property
}

func stringArrayProperty(defaultValue []string) map[string]any {
	return map[string]any{
		"type":    "array",
		"items":   map[string]any{"type": "string"},
		"default": defaultValue,
	}
}

func enumStringProperty(values []string, defaultValue string) map[string]any {
	return map[string]any{
		"type":    "string",
		"enum":    values,
		"default": defaultValue,
	}
}

func withDefault(value any) propertyOption {
	return func(property map[string]any) {
		property["default"] = value
	}
}
