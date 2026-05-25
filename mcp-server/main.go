package main

import (
	"fmt"
	"os"
	"strings"
)

type config struct {
	TeamserverURL string
	Token         string
	AllowMutation bool
}

func loadConfig() (config, error) {
	cfg := config{
		TeamserverURL: strings.TrimSpace(os.Getenv("BEBOP_TEAMSERVER_URL")),
		Token:         strings.TrimSpace(os.Getenv("BEBOP_MCP_TOKEN")),
		AllowMutation: strings.TrimSpace(os.Getenv("BEBOP_MCP_ALLOW_MUTATION")) == "1",
	}

	if cfg.TeamserverURL == "" {
		return config{}, fmt.Errorf("BEBOP_TEAMSERVER_URL is required")
	}
	if cfg.Token == "" {
		return config{}, fmt.Errorf("BEBOP_MCP_TOKEN is required")
	}

	return cfg, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	client := NewClient(cfg.TeamserverURL, cfg.Token)
	server := NewServer(client, cfg.AllowMutation)
	if err := server.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
