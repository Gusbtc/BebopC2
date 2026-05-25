package main

import "testing"

func TestLoadConfigRequiresURLAndToken(t *testing.T) {
	t.Setenv("BEBOP_TEAMSERVER_URL", "")
	t.Setenv("BEBOP_MCP_TOKEN", "")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "")

	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error for missing URL and token")
	}
}

func TestLoadConfigReadsMutationFlag(t *testing.T) {
	t.Setenv("BEBOP_TEAMSERVER_URL", " http://127.0.0.1:8080 ")
	t.Setenv("BEBOP_MCP_TOKEN", " test-token ")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", " 1 ")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.TeamserverURL != "http://127.0.0.1:8080" {
		t.Fatalf("TeamserverURL = %q, want trimmed URL", cfg.TeamserverURL)
	}
	if cfg.Token != "test-token" {
		t.Fatalf("Token = %q, want trimmed token", cfg.Token)
	}
	if !cfg.AllowMutation {
		t.Fatal("AllowMutation = false, want true")
	}
}

func TestLoadConfigRejectsMissingToken(t *testing.T) {
	t.Setenv("BEBOP_TEAMSERVER_URL", "http://127.0.0.1:8080")
	t.Setenv("BEBOP_MCP_TOKEN", " ")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "1")

	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error for missing token")
	}
}
