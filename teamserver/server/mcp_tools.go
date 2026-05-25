package server

import "strings"

const mcpInternalToolPrefix = "bebop."

func mcpPublicToolName(name string) string {
	return strings.TrimPrefix(name, mcpInternalToolPrefix)
}

func mcpInternalToolName(name string) string {
	if strings.HasPrefix(name, mcpInternalToolPrefix) {
		return name
	}
	if internal, ok := mcpPublicToInternalToolName(name); ok {
		return internal
	}
	return name
}

func mcpPublicToInternalToolName(name string) (string, bool) {
	if strings.HasPrefix(name, mcpInternalToolPrefix) {
		return "", false
	}
	candidate := mcpInternalToolPrefix + name
	for _, tool := range mcpAllTools() {
		if tool.Name == candidate {
			return candidate, true
		}
	}
	return "", false
}

func mcpPublicTools(tools []mcpToolDef) []mcpToolDef {
	public := make([]mcpToolDef, 0, len(tools))
	for _, tool := range tools {
		tool.Name = mcpPublicToolName(tool.Name)
		public = append(public, tool)
	}
	return public
}

func mcpAllTools() []mcpToolDef {
	beaconID := mcpIntegerProperty(1, 0)
	beaconIDSchema := mcpObjectSchema(map[string]any{"beacon_id": beaconID}, []string{"beacon_id"})
	return []mcpToolDef{
		{Name: "bebop.sessions.list", Description: "List active beacon sessions.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.session.get", Description: "Get one beacon session by ID.", InputSchema: beaconIDSchema},
		{Name: "bebop.results.list", Description: "List task results for a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"since":     mcpIntegerProperty(0, 0),
		}, []string{"beacon_id"})},
		{Name: "bebop.task.get", Description: "Get task result by beacon ID and label.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"label":     mcpIntegerProperty(1, 0),
		}, []string{"beacon_id", "label"})},
		{Name: "bebop.task.wait", Description: "Wait for task result by beacon ID and label.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"label":      mcpIntegerProperty(1, 0),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "label"})},
		{Name: "bebop.events.list", Description: "List operator event log entries.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.events.add", Description: "Add operator event log entry.", InputSchema: mcpObjectSchema(map[string]any{
			"type":    mcpStringProperty(mcpWithDefault("mcp")),
			"message": mcpStringProperty(),
		}, []string{"message"}), Mutating: true},
		{Name: "bebop.events.post", Description: "Add operator event log entry.", InputSchema: mcpObjectSchema(map[string]any{
			"type":    mcpStringProperty(mcpWithDefault("mcp")),
			"message": mcpStringProperty(),
		}, []string{"message"}), Mutating: true},
		{Name: "bebop.loot.list", Description: "List exfiltrated loot files.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.loot.get", Description: "Read exfiltrated loot file content.", InputSchema: mcpObjectSchema(map[string]any{
			"label":    mcpIntegerProperty(1, 0),
			"encoding": mcpEnumStringProperty([]string{"text", "base64"}, "base64"),
		}, []string{"label"})},
		{Name: "bebop.loot.delete", Description: "Delete loot metadata and disk file.", InputSchema: mcpObjectSchema(map[string]any{
			"label":   mcpIntegerProperty(1, 0),
			"confirm": mcpBooleanProperty(false),
		}, []string{"label", "confirm"}), Mutating: true},
		{Name: "bebop.library.list", Description: "List available BOF and inline assembly modules.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.library.upload", Description: "Upload .o, .obj, or .exe to operator library.", InputSchema: mcpObjectSchema(map[string]any{
			"name":           mcpStringProperty(),
			"content_base64": mcpStringProperty(),
		}, []string{"name", "content_base64"}), Mutating: true},
		{Name: "bebop.library.delete", Description: "Delete an operator library file.", InputSchema: mcpObjectSchema(map[string]any{
			"name":    mcpStringProperty(),
			"confirm": mcpBooleanProperty(false),
		}, []string{"name", "confirm"}), Mutating: true},
		{Name: "bebop.assembly.list", Description: "List uploaded assemblies.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.assembly.upload", Description: "Upload .NET assembly to assembly library.", InputSchema: mcpObjectSchema(map[string]any{
			"name":           mcpStringProperty(),
			"content_base64": mcpStringProperty(),
		}, []string{"name", "content_base64"}), Mutating: true},
		{Name: "bebop.assembly.delete", Description: "Delete uploaded assembly.", InputSchema: mcpObjectSchema(map[string]any{
			"name":    mcpStringProperty(),
			"confirm": mcpBooleanProperty(false),
		}, []string{"name", "confirm"}), Mutating: true},
		{Name: "bebop.file.download", Description: "Queue remote file download and optionally wait for its result.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":   beaconID,
			"remote_path": mcpStringProperty(),
			"wait":        mcpBooleanProperty(true),
			"timeout_ms":  mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "remote_path"}), Mutating: true},
		{Name: "bebop.file.upload", Description: "Upload local bytes to a remote path through beacon staging.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":      beaconID,
			"dest_path":      mcpStringProperty(),
			"filename":       mcpStringProperty(mcpWithDefault("upload.bin")),
			"content_base64": mcpStringProperty(),
		}, []string{"beacon_id", "dest_path", "content_base64"}), Mutating: true},
		{Name: "bebop.listeners.list", Description: "List configured listeners.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.listeners.create", Description: "Create and start an HTTP or HTTPS listener.", InputSchema: mcpObjectSchema(map[string]any{
			"name":           mcpStringProperty(),
			"scheme":         mcpEnumStringProperty([]string{"http", "https"}, "http"),
			"host":           mcpStringProperty(),
			"bind_addr":      mcpStringProperty(mcpWithDefault("0.0.0.0")),
			"port":           mcpIntegerProperty(1, 65535),
			"custom_headers": mcpStringMapProperty(),
			"cert_pem":       mcpStringProperty(),
			"key_pem":        mcpStringProperty(),
		}, []string{"name", "scheme", "host", "port"}), Mutating: true},
		{Name: "bebop.listeners.delete", Description: "Stop and delete a listener.", InputSchema: mcpObjectSchema(map[string]any{
			"id":      mcpIntegerProperty(1, 0),
			"confirm": mcpBooleanProperty(false),
		}, []string{"id", "confirm"}), Mutating: true},
		{Name: "bebop.beacon.build", Description: "Build a beacon artifact for a listener.", InputSchema: mcpObjectSchema(map[string]any{
			"listener_id":  beaconID,
			"sleep_ms":     mcpIntegerProperty(0, 0, mcpWithDefault(5000)),
			"jitter_pct":   mcpIntegerProperty(0, 100, mcpWithDefault(20)),
			"format":       mcpEnumStringProperty([]string{"exe", "bin"}, "exe"),
			"platform":     mcpEnumStringProperty([]string{"windows", "linux"}, "windows"),
			"session_port": mcpIntegerProperty(0, 65535, mcpWithDefault(0)),
		}, []string{"listener_id"}), Mutating: true},
		{Name: "bebop.terminal.get", Description: "Read saved terminal and file-browser cache for a beacon.", InputSchema: beaconIDSchema},
		{Name: "bebop.terminal.put", Description: "Save terminal and file-browser cache for a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"state":     map[string]any{"type": "object"},
		}, []string{"beacon_id", "state"}), Mutating: true},
		{Name: "bebop.filebrowser.list", Description: "List a remote directory via beacon filebrowser command and cache the result.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"path":       mcpStringProperty(),
			"transport":  mcpEnumStringProperty([]string{"auto", "http", "session"}, "auto"),
			"session":    mcpBooleanProperty(false),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "path"}), Mutating: true},
		{Name: "bebop.filebrowser.cache.get", Description: "Read saved file-browser cache for a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"session":   mcpBooleanProperty(false),
		}, []string{"beacon_id"})},
		{Name: "bebop.filebrowser.cache.set", Description: "Save file-browser cache for a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"session":   mcpBooleanProperty(false),
			"cache":     map[string]any{"type": "object"},
		}, []string{"beacon_id", "cache"}), Mutating: true},
		{Name: "bebop.chat.list", Description: "List operator chat messages.", InputSchema: mcpObjectSchema(map[string]any{
			"limit": mcpIntegerProperty(0, 1000, mcpWithDefault(200)),
		}, nil)},
		{Name: "bebop.chat.send", Description: "Send operator chat message as the MCP client.", InputSchema: mcpObjectSchema(map[string]any{
			"message": mcpStringProperty(),
		}, []string{"message"}), Mutating: true},
		{Name: "bebop.commands.list", Description: "List known beacon command catalog.", InputSchema: mcpObjectSchema(map[string]any{
			"platform": mcpEnumStringProperty([]string{"all", "windows", "linux"}, "all"),
		}, nil)},
		{Name: "bebop.command.describe", Description: "Describe one command syntax.", InputSchema: mcpObjectSchema(map[string]any{
			"name": mcpStringProperty(),
		}, []string{"name"})},
		{Name: "bebop.identity.whoami", Description: "Run whoami and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.fs.pwd", Description: "Print current working directory and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.fs.ls", Description: "List directory and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"path":       mcpStringProperty(),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.fs.cat", Description: "Read file and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"path":       mcpStringProperty(),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "path"}), Mutating: true},
		{Name: "bebop.fs.cd", Description: "Change working directory and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"path":       mcpStringProperty(),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "path"}), Mutating: true},
		{Name: "bebop.process.list", Description: "List processes and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.net.netstat", Description: "List network connections and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"args":       mcpStringArrayProperty([]string{}),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.domain.ldapsearch", Description: "Run built-in LDAP search BOF and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"filter":     mcpStringProperty(),
			"attrs":      mcpStringProperty(),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "filter"}), Mutating: true},
		{Name: "bebop.domain.adcs_enum", Description: "Run built-in ADCS enumeration BOF and wait for output.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"args":       mcpStringArrayProperty([]string{}),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.command.run", Description: "Run a command on a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"command":   mcpStringProperty(),
			"args":      mcpStringArrayProperty([]string{}),
			"transport": mcpEnumStringProperty([]string{"auto", "http", "session"}, "auto"),
		}, []string{"beacon_id", "command"}), Mutating: true},
		{Name: "bebop.command.execute", Description: "Queue a command and wait for its result.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":  beaconID,
			"command":    mcpStringProperty(),
			"args":       mcpStringArrayProperty([]string{}),
			"transport":  mcpEnumStringProperty([]string{"auto", "http", "session"}, "auto"),
			"timeout_ms": mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "command"}), Mutating: true},
		{Name: "bebop.bof.execute", Description: "Execute a BOF module on a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":   beaconID,
			"object_name": mcpStringProperty(),
			"args":        mcpStringArrayProperty([]string{}),
		}, []string{"beacon_id", "object_name"}), Mutating: true},
		{Name: "bebop.bof.execute.wait", Description: "Execute a BOF and wait for its result.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":   beaconID,
			"object_name": mcpStringProperty(),
			"args":        mcpStringArrayProperty([]string{}),
			"timeout_ms":  mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "object_name"}), Mutating: true},
		{Name: "bebop.inline-assembly.execute", Description: "Execute an inline assembly module on a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":     beaconID,
			"assembly_name": mcpStringProperty(),
			"args":          mcpStringArrayProperty([]string{}),
			"mode":          mcpEnumStringProperty([]string{"auto", "bridge"}, "auto"),
		}, []string{"beacon_id", "assembly_name"}), Mutating: true},
		{Name: "bebop.inline-assembly.execute.wait", Description: "Execute an inline assembly module and wait for its result.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id":     beaconID,
			"assembly_name": mcpStringProperty(),
			"args":          mcpStringArrayProperty([]string{}),
			"mode":          mcpEnumStringProperty([]string{"auto", "bridge"}, "auto"),
			"timeout_ms":    mcpIntegerProperty(1, 300000, mcpWithDefault(60000)),
		}, []string{"beacon_id", "assembly_name"}), Mutating: true},
		{Name: "bebop.beacon.sleep", Description: "Change beacon sleep interval and jitter.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"seconds":   mcpIntegerProperty(0, 0),
			"jitter":    mcpIntegerProperty(0, 100, mcpWithDefault(0)),
		}, []string{"beacon_id", "seconds"}), Mutating: true},
		{Name: "bebop.session.close", Description: "Close an active interactive/session channel without killing the beacon.", InputSchema: beaconIDSchema, Mutating: true},
		{Name: "bebop.beacon.exit", Description: "Task a beacon to exit.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"confirm":   mcpBooleanProperty(false),
		}, []string{"beacon_id", "confirm"}), Mutating: true},
		{Name: "bebop.beacon.interactive", Description: "Start an interactive session for a beacon.", InputSchema: beaconIDSchema, Mutating: true},
		{Name: "bebop.socks.list", Description: "List active SOCKS proxies.", InputSchema: mcpEmptySchema()},
		{Name: "bebop.socks.start", Description: "Start SOCKS proxy through a beacon.", InputSchema: mcpObjectSchema(map[string]any{
			"beacon_id": beaconID,
			"port":      mcpIntegerProperty(0, 65535, mcpWithDefault(0)),
		}, []string{"beacon_id"}), Mutating: true},
		{Name: "bebop.socks.stop", Description: "Stop SOCKS proxy by ID.", InputSchema: beaconIDSchema, Mutating: true},
	}
}

func mcpVisibleTools(allowMutation bool) []mcpToolDef {
	tools := mcpAllTools()
	if allowMutation {
		return tools
	}
	visible := make([]mcpToolDef, 0, len(tools))
	for _, tool := range tools {
		if !tool.Mutating {
			visible = append(visible, tool)
		}
	}
	return visible
}

func mcpVisibleToolsForAuth(allowMutation bool, auth mcpAuthContext) []mcpToolDef {
	tools := mcpVisibleTools(allowMutation)
	if auth.Scopes == nil {
		return mcpPublicTools(tools)
	}
	visible := make([]mcpToolDef, 0, len(tools))
	for _, tool := range tools {
		if auth.HasScope(mcpToolScope(tool.Name)) {
			visible = append(visible, tool)
		}
	}
	return mcpPublicTools(visible)
}

func mcpKnownTool(name string) bool {
	_, ok := mcpPublicToInternalToolName(name)
	return ok
}

func mcpIsMutatingTool(name string) bool {
	if !strings.HasPrefix(name, mcpInternalToolPrefix) {
		internal, ok := mcpPublicToInternalToolName(name)
		if !ok {
			return false
		}
		name = internal
	}
	for _, tool := range mcpAllTools() {
		if tool.Name == name {
			return tool.Mutating
		}
	}
	return false
}

func mcpReadOnlyToolNames() []string {
	return mcpToolNames(mcpPublicTools(mcpVisibleTools(false)))
}

func mcpMutatingToolNames() []string {
	names := make([]string, 0)
	for _, tool := range mcpAllTools() {
		if tool.Mutating {
			names = append(names, mcpPublicToolName(tool.Name))
		}
	}
	return names
}

func mcpToolNames(tools []mcpToolDef) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}
