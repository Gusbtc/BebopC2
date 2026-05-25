package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestToolsListMutationDisabled(t *testing.T) {
	tools := readToolsList(t, NewServer(nil, false))

	for _, name := range []string{
		"command.run",
		"bof.execute",
		"inline-assembly.execute",
		"beacon.sleep",
		"beacon.exit",
		"beacon.interactive",
		"socks.start",
		"socks.stop",
	} {
		if hasTool(tools, name) {
			t.Fatalf("tools/list exposed mutating tool when mutation disabled: %s", name)
		}
	}
	if !hasTool(tools, "sessions.list") {
		t.Fatal("tools/list did not include sessions.list")
	}
}

func TestToolsListMutationEnabledIncludesTypedModuleTools(t *testing.T) {
	tools := readToolsList(t, NewServer(nil, true))

	for _, name := range []string{
		"command.run",
		"bof.execute",
		"inline-assembly.execute",
	} {
		if !hasTool(tools, name) {
			t.Fatalf("tools/list did not include %s", name)
		}
	}

	command := findTool(t, tools, "command.run")
	schema, ok := command["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("command.run inputSchema missing or not an object")
	}
	if schema["type"] != "object" {
		t.Fatalf("command.run schema type = %v, want object", schema["type"])
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("command.run additionalProperties = %v, want false", schema["additionalProperties"])
	}
	assertRequired(t, schema, "beacon_id", "command")
	props := schema["properties"].(map[string]any)
	assertArrayStringDefault(t, props["args"].(map[string]any))
	assertEnumDefault(t, props["transport"].(map[string]any), "auto", "http", "session")

	bof := findTool(t, tools, "bof.execute")
	bofSchema := bof["inputSchema"].(map[string]any)
	assertRequired(t, bofSchema, "beacon_id", "object_name")
	bofProps := bofSchema["properties"].(map[string]any)
	assertArrayStringDefault(t, bofProps["args"].(map[string]any))

	inline := findTool(t, tools, "inline-assembly.execute")
	inlineSchema := inline["inputSchema"].(map[string]any)
	assertRequired(t, inlineSchema, "beacon_id", "assembly_name")
	inlineProps := inlineSchema["properties"].(map[string]any)
	assertArrayStringDefault(t, inlineProps["args"].(map[string]any))
	assertEnumDefault(t, inlineProps["mode"].(map[string]any), "auto", "bridge")
}

func TestBeaconTargetToolsUseBeaconID(t *testing.T) {
	tools := readToolsList(t, NewServer(nil, true))

	for _, name := range []string{
		"beacon.exit",
		"beacon.interactive",
		"socks.stop",
	} {
		schema := findTool(t, tools, name)["inputSchema"].(map[string]any)
		assertRequired(t, schema, "beacon_id")
		props := schema["properties"].(map[string]any)
		if _, ok := props["id"]; ok {
			t.Fatalf("%s exposes id instead of beacon_id", name)
		}
		if _, ok := props["beacon_id"]; !ok {
			t.Fatalf("%s missing beacon_id property", name)
		}
	}

	sleepSchema := findTool(t, tools, "beacon.sleep")["inputSchema"].(map[string]any)
	sleepProps := sleepSchema["properties"].(map[string]any)
	seconds := sleepProps["seconds"].(map[string]any)
	if seconds["minimum"] != float64(0) && seconds["minimum"] != 0 {
		t.Fatalf("sleep seconds minimum = %v, want 0", seconds["minimum"])
	}

	socksSchema := findTool(t, tools, "socks.start")["inputSchema"].(map[string]any)
	socksProps := socksSchema["properties"].(map[string]any)
	port := socksProps["port"].(map[string]any)
	if port["minimum"] != float64(0) && port["minimum"] != 0 {
		t.Fatalf("socks port minimum = %v, want 0", port["minimum"])
	}
	if port["default"] != float64(0) && port["default"] != 0 {
		t.Fatalf("socks port default = %v, want 0", port["default"])
	}
}

func TestMutationBlockedWhenDisabled(t *testing.T) {
	var out bytes.Buffer
	NewServer(NewClient("http://example.test", "tok"), false).handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"command.run","arguments":{"beacon_id":7,"command":"whoami"}}`),
	})

	var response rpcResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected mutation disabled error")
	}
	if response.Error.Code != -32000 {
		t.Fatalf("error code = %d, want -32000", response.Error.Code)
	}
	if response.Error.Message != "mutation disabled" {
		t.Fatalf("error message = %q, want mutation disabled", response.Error.Message)
	}
}

func TestPrefixedToolNamesAreRejected(t *testing.T) {
	var out bytes.Buffer
	NewServer(NewClient("http://example.test", "tok"), true).handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"bebop.command.run","arguments":{"beacon_id":7,"command":"whoami"}}`),
	})

	var response rpcResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected unknown tool error")
	}
	if response.Error.Message != "unknown tool: bebop.command.run" {
		t.Fatalf("error message = %q", response.Error.Message)
	}
}

func TestToolCallValidatesRequiredArguments(t *testing.T) {
	tests := []struct {
		name   string
		params string
		want   string
	}{
		{
			name:   "command missing command",
			params: `{"name":"command.run","arguments":{"beacon_id":7}}`,
			want:   "beacon_id and command required",
		},
		{
			name:   "bof missing object",
			params: `{"name":"bof.execute","arguments":{"beacon_id":7}}`,
			want:   "beacon_id and object_name required",
		},
		{
			name:   "inline missing assembly",
			params: `{"name":"inline-assembly.execute","arguments":{"beacon_id":7}}`,
			want:   "beacon_id and assembly_name required",
		},
		{
			name:   "sleep missing seconds",
			params: `{"name":"beacon.sleep","arguments":{"beacon_id":7}}`,
			want:   "seconds required",
		},
		{
			name:   "sleep negative seconds",
			params: `{"name":"beacon.sleep","arguments":{"beacon_id":7,"seconds":-1}}`,
			want:   "seconds must be >= 0",
		},
		{
			name:   "sleep invalid jitter",
			params: `{"name":"beacon.sleep","arguments":{"beacon_id":7,"seconds":5,"jitter":101}}`,
			want:   "jitter must be 0-100",
		},
		{
			name:   "socks invalid port",
			params: `{"name":"socks.start","arguments":{"beacon_id":7,"port":-1}}`,
			want:   "port must be 0-65535",
		},
		{
			name:   "command invalid transport",
			params: `{"name":"command.run","arguments":{"beacon_id":7,"command":"whoami","transport":"bogus"}}`,
			want:   "transport must be auto, http, or session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			NewServer(NewClient("http://example.test", "tok"), true).handle(&out, rpcRequest{
				JSONRPC: "2.0",
				ID:      json.RawMessage(`1`),
				Method:  "tools/call",
				Params:  json.RawMessage(tt.params),
			})

			var response rpcResponse
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if response.Error == nil {
				t.Fatal("expected validation error")
			}
			if response.Error.Message != tt.want {
				t.Fatalf("error message = %q, want %q", response.Error.Message, tt.want)
			}
		})
	}
}

func TestResourceReadRejectsTrailingIDText(t *testing.T) {
	var out bytes.Buffer
	NewServer(NewClient("http://example.test", "tok"), false).handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "resources/read",
		Params:  json.RawMessage(`{"uri":"bebop://sessions/7/junk"}`),
	})

	var response rpcResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected invalid id error")
	}
	if response.Error.Message != "invalid session id: 7/junk" {
		t.Fatalf("error message = %q", response.Error.Message)
	}
}

func TestCommandRunPostsTaskWithAuthorization(t *testing.T) {
	var gotAuth string
	var gotBody struct {
		BeaconID  uint32 `json:"beacon_id"`
		Type      int    `json:"type"`
		Code      int    `json:"code"`
		Args      string `json:"args"`
		Transport string `json:"transport"`
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/task" {
			t.Fatalf("path = %s, want /api/task", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"queued": true})
	}))
	defer ts.Close()

	var out bytes.Buffer
	NewServer(NewClient(ts.URL, "tok"), true).handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"command.run","arguments":{"beacon_id":7,"command":"shell","args":["whoami /all"],"transport":"http"}}`),
	})
	assertNoRPCError(t, out.Bytes())

	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if gotBody.BeaconID != 7 || gotBody.Type != 12 || gotBody.Code != 0 {
		t.Fatalf("task body = %+v, want beacon_id 7 type 12 code 0", gotBody)
	}
	if gotBody.Args != `shell "whoami /all"` {
		t.Fatalf("args = %q, want quoted command args", gotBody.Args)
	}
	if gotBody.Transport != "http" {
		t.Fatalf("transport = %q, want http", gotBody.Transport)
	}
}

func TestBOFExecutePostsMultipartArgs(t *testing.T) {
	var gotAuth string
	var gotBeaconID string
	var gotObjectName string
	var gotArgs string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/bof" {
			t.Fatalf("path = %s, want /api/bof", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("parse multipart: %v", err)
		}
		gotBeaconID = r.FormValue("beacon_id")
		gotObjectName = r.FormValue("object_name")
		gotArgs = r.FormValue("args")
		_ = json.NewEncoder(w).Encode(map[string]bool{"queued": true})
	}))
	defer ts.Close()

	var out bytes.Buffer
	NewServer(NewClient(ts.URL, "tok"), true).handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"bof.execute","arguments":{"beacon_id":9,"object_name":"whoami.x64.o","args":["arg one","two"]}}`),
	})
	assertNoRPCError(t, out.Bytes())

	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if gotBeaconID != "9" || gotObjectName != "whoami.x64.o" {
		t.Fatalf("multipart fields beacon_id=%q object_name=%q", gotBeaconID, gotObjectName)
	}
	if gotArgs != `"arg one" two` {
		t.Fatalf("args = %q, want packed args", gotArgs)
	}
}

func TestResourcesListIncludesSessionAndResultTemplates(t *testing.T) {
	var out bytes.Buffer
	NewServer(nil, false).handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "resources/list",
	})

	var response struct {
		Result struct {
			Resources []map[string]any `json:"resources"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("unexpected error: %+v", response.Error)
	}
	if !hasResource(response.Result.Resources, "bebop://sessions/{id}") {
		t.Fatal("resources/list missing bebop://sessions/{id}")
	}
	if !hasResource(response.Result.Resources, "bebop://results/{id}") {
		t.Fatal("resources/list missing bebop://results/{id}")
	}
}

func readToolsList(t *testing.T, server *Server) []map[string]any {
	t.Helper()

	var out bytes.Buffer
	server.handle(&out, rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	})

	var response struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("unexpected error: %+v", response.Error)
	}
	return response.Result.Tools
}

func assertNoRPCError(t *testing.T, data []byte) {
	t.Helper()
	var response rpcResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("unexpected error: %+v", response.Error)
	}
}

func hasTool(tools []map[string]any, name string) bool {
	return findToolOrNil(tools, name) != nil
}

func hasResource(resources []map[string]any, uri string) bool {
	for _, resource := range resources {
		if resource["uri"] == uri {
			return true
		}
	}
	return false
}

func findTool(t *testing.T, tools []map[string]any, name string) map[string]any {
	t.Helper()
	tool := findToolOrNil(tools, name)
	if tool == nil {
		t.Fatalf("tool not found: %s", name)
	}
	return tool
}

func findToolOrNil(tools []map[string]any, name string) map[string]any {
	for _, tool := range tools {
		if tool["name"] == name {
			return tool
		}
	}
	return nil
}

func assertRequired(t *testing.T, schema map[string]any, want ...string) {
	t.Helper()
	raw, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("required missing or invalid: %#v", schema["required"])
	}
	got := make(map[string]bool, len(raw))
	for _, item := range raw {
		got[item.(string)] = true
	}
	for _, item := range want {
		if !got[item] {
			t.Fatalf("required missing %s in %#v", item, raw)
		}
	}
}

func assertArrayStringDefault(t *testing.T, schema map[string]any) {
	t.Helper()
	if schema["type"] != "array" {
		t.Fatalf("array schema type = %v, want array", schema["type"])
	}
	items := schema["items"].(map[string]any)
	if items["type"] != "string" {
		t.Fatalf("array items type = %v, want string", items["type"])
	}
	defaultValue, ok := schema["default"].([]any)
	if !ok || len(defaultValue) != 0 {
		t.Fatalf("array default = %#v, want empty array", schema["default"])
	}
}

func assertEnumDefault(t *testing.T, schema map[string]any, values ...string) {
	t.Helper()
	if schema["type"] != "string" {
		t.Fatalf("enum schema type = %v, want string", schema["type"])
	}
	if schema["default"] != values[0] {
		t.Fatalf("enum default = %v, want %s", schema["default"], values[0])
	}
	raw, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("enum missing or invalid: %#v", schema["enum"])
	}
	if len(raw) != len(values) {
		t.Fatalf("enum length = %d, want %d", len(raw), len(values))
	}
	for i, value := range values {
		if raw[i] != value {
			t.Fatalf("enum[%d] = %v, want %s", i, raw[i], value)
		}
	}
}
