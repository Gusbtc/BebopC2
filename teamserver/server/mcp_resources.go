package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func mcpResourceList() []map[string]any {
	return []map[string]any{
		{"uri": "bebop://sessions", "name": "sessions", "mimeType": "application/json"},
		{"uri": "bebop://sessions/{id}", "name": "session", "mimeType": "application/json"},
		{"uri": "bebop://results/{id}", "name": "results", "mimeType": "application/json"},
		{"uri": "bebop://events", "name": "events", "mimeType": "application/json"},
		{"uri": "bebop://loot", "name": "loot", "mimeType": "application/json"},
		{"uri": "bebop://library", "name": "library", "mimeType": "application/json"},
		{"uri": "bebop://assemblies", "name": "assemblies", "mimeType": "application/json"},
		{"uri": "bebop://listeners", "name": "listeners", "mimeType": "application/json"},
		{"uri": "bebop://socks", "name": "socks", "mimeType": "application/json"},
		{"uri": "bebop://terminal/{id}", "name": "terminal", "mimeType": "application/json"},
		{"uri": "bebop://filebrowser/{id}", "name": "filebrowser", "mimeType": "application/json"},
		{"uri": "bebop://filebrowser-session/{id}", "name": "session filebrowser", "mimeType": "application/json"},
		{"uri": "bebop://chat", "name": "chat", "mimeType": "application/json"},
	}
}

func mcpResourceURIs() []string {
	resources := mcpResourceList()
	uris := make([]string, 0, len(resources))
	for _, resource := range resources {
		if uri, ok := resource["uri"].(string); ok {
			uris = append(uris, uri)
		}
	}
	return uris
}

func (s *mcpHTTPServer) readResource(raw json.RawMessage) (map[string]any, error) {
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

	var out any
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
	case "bebop://assemblies":
		if err := s.client.getJSON("/api/assemblies", &out); err != nil {
			return nil, err
		}
	case "bebop://listeners":
		if err := s.client.getJSON("/api/listeners", &out); err != nil {
			return nil, err
		}
	case "bebop://socks":
		if err := s.client.getJSON("/api/socks", &out); err != nil {
			return nil, err
		}
	case "bebop://chat":
		if err := s.client.getJSON("/api/chat", &out); err != nil {
			return nil, err
		}
	default:
		if idText, ok := strings.CutPrefix(params.URI, "bebop://sessions/"); ok {
			beaconID, err := mcpParseResourceID(idText, "session")
			if err != nil {
				return nil, err
			}
			out, err = s.readSessionByID(beaconID)
			if err != nil {
				return nil, err
			}
		} else if idText, ok := strings.CutPrefix(params.URI, "bebop://results/"); ok {
			beaconID, err := mcpParseResourceID(idText, "results")
			if err != nil {
				return nil, err
			}
			if err := s.client.getJSON(mcpResultRoute(beaconID, 0), &out); err != nil {
				return nil, err
			}
		} else if idText, ok := strings.CutPrefix(params.URI, "bebop://terminal/"); ok {
			beaconID, err := mcpParseResourceID(idText, "terminal")
			if err != nil {
				return nil, err
			}
			if err := s.client.getJSON(fmt.Sprintf("/api/terminal/%d", beaconID), &out); err != nil {
				return nil, err
			}
		} else if idText, ok := strings.CutPrefix(params.URI, "bebop://filebrowser/"); ok {
			beaconID, err := mcpParseResourceID(idText, "filebrowser")
			if err != nil {
				return nil, err
			}
			var state map[string]any
			if err := s.client.getJSON(fmt.Sprintf("/api/terminal/%d", beaconID), &state); err != nil {
				return nil, err
			}
			out = state["file_browser"]
		} else if idText, ok := strings.CutPrefix(params.URI, "bebop://filebrowser-session/"); ok {
			beaconID, err := mcpParseResourceID(idText, "session filebrowser")
			if err != nil {
				return nil, err
			}
			var state map[string]any
			if err := s.client.getJSON(fmt.Sprintf("/api/terminal/%d", beaconID), &state); err != nil {
				return nil, err
			}
			out = state["session_file_browser"]
		} else {
			return nil, fmt.Errorf("unknown resource: %s", params.URI)
		}
	}
	return mcpResourceContents(params.URI, out), nil
}

func mcpResourceContents(uri string, v any) map[string]any {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		encoded = []byte(fmt.Sprintf("%v", v))
	}
	return map[string]any{
		"contents": []map[string]any{
			{"uri": uri, "mimeType": "application/json", "text": string(encoded)},
		},
	}
}

func mcpParseResourceID(text string, kind string) (uint32, error) {
	id, err := strconv.ParseUint(text, 10, 32)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid %s id: %s", kind, text)
	}
	return uint32(id), nil
}
