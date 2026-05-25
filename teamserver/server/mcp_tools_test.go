package server

import (
	"strings"
	"testing"
)

func TestMCPToolNamesArePublicWithoutServerPrefix(t *testing.T) {
	tools := mcpVisibleToolsForAuth(true, mcpAuthContext{})
	if len(tools) == 0 {
		t.Fatal("expected visible MCP tools")
	}

	seenCommandExecute := false
	for _, tool := range tools {
		if strings.HasPrefix(tool.Name, mcpInternalToolPrefix) {
			t.Fatalf("tool name still has internal prefix: %s", tool.Name)
		}
		if tool.Name == "command.execute" {
			seenCommandExecute = true
		}
	}
	if !seenCommandExecute {
		t.Fatal("command.execute not found in visible MCP tools")
	}
}

func TestMCPToolNamesUsePublicContractOnly(t *testing.T) {
	if !mcpKnownTool("command.execute") {
		t.Fatal("public tool name not recognized")
	}
	if mcpKnownTool("bebop.command.execute") {
		t.Fatal("prefixed tool name should not be accepted by MCP API")
	}
	if !mcpIsMutatingTool("command.execute") {
		t.Fatal("public mutating tool not recognized")
	}
	if !mcpToolRequiresConfirm("beacon.exit") {
		t.Fatal("public destructive tool did not require confirmation")
	}
}
