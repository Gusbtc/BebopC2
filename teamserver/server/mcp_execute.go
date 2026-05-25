package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type mcpTeamserverClient struct {
	baseURL string
	token   string
	http    *http.Client
}

type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mcpIDArgs struct {
	BeaconID uint32 `json:"beacon_id"`
}

type mcpCommandArgs struct {
	BeaconID  uint32   `json:"beacon_id"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Transport string   `json:"transport"`
}

type mcpModuleArgs struct {
	BeaconID     uint32   `json:"beacon_id"`
	ObjectName   string   `json:"object_name"`
	AssemblyName string   `json:"assembly_name"`
	Args         []string `json:"args"`
	Mode         string   `json:"mode"`
}

type mcpFileUploadArgs struct {
	Name          string `json:"name"`
	ContentBase64 string `json:"content_base64"`
}

func newMCPTeamserverClient(baseURL string, token string) *mcpTeamserverClient {
	return &mcpTeamserverClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *mcpTeamserverClient) getJSON(route string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.url(route), nil)
	if err != nil {
		return err
	}
	return c.decodeJSON(req, out)
}

func (c *mcpTeamserverClient) postJSON(route string, in any, out any) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.url(route), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.decodeJSON(req, out)
}

func (c *mcpTeamserverClient) putJSON(route string, in any, out any) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, c.url(route), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.decodeJSON(req, out)
}

func (c *mcpTeamserverClient) postMultipart(route string, fields map[string]string, out any) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.url(route), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return c.decodeJSON(req, out)
}

func (c *mcpTeamserverClient) postNamedFile(route string, fields map[string]string, fieldName string, filename string, data []byte, out any) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return err
		}
	}
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.url(route), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return c.decodeJSON(req, out)
}

func (c *mcpTeamserverClient) deleteJSON(route string, out any) error {
	req, err := http.NewRequest(http.MethodDelete, c.url(route), nil)
	if err != nil {
		return err
	}
	return c.decodeJSON(req, out)
}

func (c *mcpTeamserverClient) decodeJSON(req *http.Request, out any) error {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return readErr
		}
		return fmt.Errorf("teamserver %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *mcpTeamserverClient) getBytes(route string) ([]byte, string, string, error) {
	req, err := http.NewRequest(http.MethodGet, c.url(route), nil)
	if err != nil {
		return nil, "", "", err
	}
	return c.doBytes(req)
}

func (c *mcpTeamserverClient) postJSONBytes(route string, in any) ([]byte, string, string, error) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return nil, "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, c.url(route), &body)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doBytes(req)
}

func (c *mcpTeamserverClient) doBytes(req *http.Request) ([]byte, string, string, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", "", fmt.Errorf("teamserver %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUploadFileBytes+1))
	if err != nil {
		return nil, "", "", err
	}
	if int64(len(data)) > maxUploadFileBytes {
		return nil, "", "", fmt.Errorf("response too large")
	}
	return data, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"), nil
}

func (c *mcpTeamserverClient) url(route string) string {
	if c.baseURL == "" {
		return route
	}
	if strings.HasPrefix(route, "?") {
		return c.baseURL + route
	}
	return c.baseURL + "/" + strings.TrimLeft(route, "/")
}

func (s *mcpHTTPServer) callTool(raw json.RawMessage) (map[string]any, error) {
	var params mcpToolCallParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	if params.Name == "" {
		return nil, fmt.Errorf("missing tool name")
	}
	internalName, ok := mcpPublicToInternalToolName(params.Name)
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", params.Name)
	}
	params.Name = internalName
	if mcpIsMutatingTool(params.Name) && !s.allowMutation {
		return nil, fmt.Errorf("mutation disabled")
	}
	scope := mcpToolScope(params.Name)
	if !s.auth.HasScope(scope) {
		return nil, fmt.Errorf("missing MCP scope: %s", scope)
	}
	args := params.Arguments
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	if mcpToolRequiresConfirm(params.Name) {
		if err := mcpRequireConfirm(args); err != nil {
			return nil, err
		}
	}

	switch params.Name {
	case "bebop.commands.list":
		var req struct {
			Platform string `json:"platform"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		return mcpContentResult(mcpCommandCatalogFiltered(req.Platform)), nil
	case "bebop.command.describe":
		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		spec, ok := mcpFindCommandSpec(req.Name)
		if !ok {
			return nil, fmt.Errorf("command not found: %s", req.Name)
		}
		return mcpContentResult(spec), nil
	}

	if s.client == nil {
		return nil, fmt.Errorf("teamserver client unavailable")
	}

	var out any
	switch params.Name {
	case "bebop.sessions.list":
		if err := s.client.getJSON("/api/sessions", &out); err != nil {
			return nil, err
		}
	case "bebop.session.get":
		var req mcpIDArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		session, err := s.readSessionByID(req.BeaconID)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(session), nil
	case "bebop.results.list":
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
		if err := s.client.getJSON(mcpResultRoute(req.BeaconID, req.Since), &out); err != nil {
			return nil, err
		}
	case "bebop.task.get":
		req, err := decodeMCPTaskWaitArgs(args)
		if err != nil {
			return nil, err
		}
		result, found, err := s.findResult(req.BeaconID, req.Label)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("task result not found")
		}
		return mcpContentResult(result), nil
	case "bebop.task.wait":
		req, err := decodeMCPTaskWaitArgs(args)
		if err != nil {
			return nil, err
		}
		result, err := s.waitForResult(req.BeaconID, req.Label, time.Duration(req.TimeoutMS)*time.Millisecond)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(result), nil
	case "bebop.events.list":
		if err := s.client.getJSON("/api/events", &out); err != nil {
			return nil, err
		}
	case "bebop.events.add", "bebop.events.post":
		var req struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		req.Type = strings.TrimSpace(req.Type)
		if req.Type == "" {
			req.Type = "mcp"
		}
		if strings.TrimSpace(req.Message) == "" {
			return nil, fmt.Errorf("message required")
		}
		if err := s.client.postJSON("/api/events", req, &out); err != nil {
			return nil, err
		}
	case "bebop.loot.list":
		if err := s.client.getJSON("/api/loot", &out); err != nil {
			return nil, err
		}
	case "bebop.loot.get":
		var req struct {
			Label    uint32 `json:"label"`
			Encoding string `json:"encoding"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.Label == 0 {
			return nil, fmt.Errorf("label required")
		}
		data, contentType, disposition, err := s.client.getBytes(fmt.Sprintf("/api/files/%d", req.Label))
		if err != nil {
			return nil, err
		}
		if req.Encoding == "text" {
			return mcpTextResult(string(data)), nil
		}
		filename := mcpFilenameFromDisposition(disposition, fmt.Sprintf("%d", req.Label))
		return mcpContentResult(mcpBinaryPayload(filename, contentType, data, map[string]any{"label": req.Label})), nil
	case "bebop.loot.delete":
		var req struct {
			Label uint32 `json:"label"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.Label == 0 {
			return nil, fmt.Errorf("label required")
		}
		if err := s.client.deleteJSON(fmt.Sprintf("/api/files/%d", req.Label), nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"deleted": req.Label}), nil
	case "bebop.library.list":
		if err := s.client.getJSON("/api/library", &out); err != nil {
			return nil, err
		}
	case "bebop.library.upload":
		var req mcpFileUploadArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		data, err := mcpDecodeBase64(req.ContentBase64, "content_base64", maxAssemblyFileBytes)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Name) == "" {
			return nil, fmt.Errorf("name required")
		}
		if err := s.client.postNamedFile("/api/library", map[string]string{"name": req.Name}, "file", req.Name, data, &out); err != nil {
			return nil, err
		}
	case "bebop.library.delete":
		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Name) == "" {
			return nil, fmt.Errorf("name required")
		}
		if err := s.client.deleteJSON("/api/library/"+url.PathEscape(req.Name), nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"deleted": req.Name}), nil
	case "bebop.assembly.list":
		if err := s.client.getJSON("/api/assemblies", &out); err != nil {
			return nil, err
		}
	case "bebop.assembly.upload":
		var req mcpFileUploadArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		data, err := mcpDecodeBase64(req.ContentBase64, "content_base64", maxAssemblyFileBytes)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Name) == "" {
			return nil, fmt.Errorf("name required")
		}
		if err := s.client.postNamedFile("/api/assemblies", map[string]string{"name": req.Name}, "assembly", req.Name, data, &out); err != nil {
			return nil, err
		}
	case "bebop.assembly.delete":
		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Name) == "" {
			return nil, fmt.Errorf("name required")
		}
		if err := s.client.deleteJSON("/api/assemblies/"+url.PathEscape(req.Name), nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"deleted": req.Name}), nil
	case "bebop.file.download":
		var req struct {
			BeaconID   uint32 `json:"beacon_id"`
			RemotePath string `json:"remote_path"`
			Remote     string `json:"remote"`
			Wait       *bool  `json:"wait"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		remote := strings.TrimSpace(req.RemotePath)
		if remote == "" {
			remote = strings.TrimSpace(req.Remote)
		}
		if req.BeaconID == 0 || remote == "" {
			return nil, fmt.Errorf("beacon_id and remote_path required")
		}
		body := map[string]any{"beacon_id": req.BeaconID, "type": 4, "code": 0, "args": remote}
		if err := s.client.postJSON("/api/task", body, &out); err != nil {
			return nil, err
		}
		if req.Wait != nil && !*req.Wait {
			return mcpContentResult(out), nil
		}
		label, err := mcpLabelFromQueued(out)
		if err != nil {
			return nil, err
		}
		result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(args, 60000))
		if err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"queued": out, "result": result}), nil
	case "bebop.file.upload":
		var req struct {
			BeaconID      uint32 `json:"beacon_id"`
			DestPath      string `json:"dest_path"`
			Remote        string `json:"remote"`
			Filename      string `json:"filename"`
			ContentBase64 string `json:"content_base64"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		dest := strings.TrimSpace(req.DestPath)
		if dest == "" {
			dest = strings.TrimSpace(req.Remote)
		}
		if req.BeaconID == 0 || dest == "" {
			return nil, fmt.Errorf("beacon_id and dest_path required")
		}
		filename := strings.TrimSpace(req.Filename)
		if filename == "" {
			filename = "upload.bin"
		}
		data, err := mcpDecodeBase64(req.ContentBase64, "content_base64", maxUploadFileBytes)
		if err != nil {
			return nil, err
		}
		fields := map[string]string{"beacon_id": fmt.Sprintf("%d", req.BeaconID), "dest_path": dest}
		if err := s.client.postNamedFile("/api/upload", fields, "file", filename, data, &out); err != nil {
			return nil, err
		}
	case "bebop.listeners.list":
		if err := s.client.getJSON("/api/listeners", &out); err != nil {
			return nil, err
		}
	case "bebop.listeners.create":
		var req struct {
			Name          string            `json:"name"`
			Scheme        string            `json:"scheme"`
			Host          string            `json:"host"`
			BindAddr      string            `json:"bind_addr"`
			Port          int               `json:"port"`
			CertPEM       string            `json:"cert_pem"`
			KeyPEM        string            `json:"key_pem"`
			CustomHeaders map[string]string `json:"custom_headers"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Host) == "" {
			return nil, fmt.Errorf("name and host required")
		}
		if req.Scheme == "" {
			req.Scheme = "http"
		}
		if req.Port < 1 || req.Port > 65535 {
			return nil, fmt.Errorf("port must be 1-65535")
		}
		if err := s.client.postJSON("/api/listeners", req, &out); err != nil {
			return nil, err
		}
	case "bebop.listeners.delete":
		var req struct {
			ID uint32 `json:"id"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.ID == 0 {
			return nil, fmt.Errorf("id required")
		}
		if err := s.client.deleteJSON(fmt.Sprintf("/api/listeners/%d", req.ID), nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"deleted": req.ID}), nil
	case "bebop.beacon.build":
		var req struct {
			ListenerID  uint32 `json:"listener_id"`
			SleepMS     int    `json:"sleep_ms"`
			JitterPct   int    `json:"jitter_pct"`
			Format      string `json:"format"`
			SessionPort int    `json:"session_port"`
			Platform    string `json:"platform"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.ListenerID == 0 {
			return nil, fmt.Errorf("listener_id required")
		}
		data, contentType, disposition, err := s.client.postJSONBytes("/api/build", req)
		if err != nil {
			return nil, err
		}
		filename := mcpFilenameFromDisposition(disposition, "beacon.bin")
		return mcpContentResult(mcpBinaryPayload(filename, contentType, data, nil)), nil
	case "bebop.terminal.get":
		var req mcpIDArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if err := s.client.getJSON(fmt.Sprintf("/api/terminal/%d", req.BeaconID), &out); err != nil {
			return nil, err
		}
	case "bebop.terminal.put":
		var req struct {
			BeaconID uint32         `json:"beacon_id"`
			State    map[string]any `json:"state"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 || req.State == nil {
			return nil, fmt.Errorf("beacon_id and state required")
		}
		if err := s.client.putJSON(fmt.Sprintf("/api/terminal/%d", req.BeaconID), req.State, nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"saved": req.BeaconID}), nil
	case "bebop.filebrowser.list":
		var req struct {
			BeaconID  uint32 `json:"beacon_id"`
			Path      string `json:"path"`
			Transport string `json:"transport"`
			Session   bool   `json:"session"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 || strings.TrimSpace(req.Path) == "" {
			return nil, fmt.Errorf("beacon_id and path required")
		}
		transport := strings.TrimSpace(req.Transport)
		if transport == "" || transport == "auto" {
			if req.Session {
				transport = "session"
			} else {
				transport = "http"
			}
		}
		queued, err := s.queueCommand(mcpCommandArgs{
			BeaconID:  req.BeaconID,
			Command:   "filebrowser",
			Args:      []string{req.Path},
			Transport: transport,
		})
		if err != nil {
			return nil, err
		}
		label, err := mcpLabelFromQueued(queued)
		if err != nil {
			return nil, err
		}
		result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(args, 60000))
		if err != nil {
			return nil, err
		}
		entries, err := mcpParseFileBrowserEntries(result)
		if err != nil {
			return nil, err
		}
		cache, err := s.saveFileBrowserCache(req.BeaconID, req.Path, req.Session, entries)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"queued": queued, "result": result, "entries": entries, "cache": cache}), nil
	case "bebop.filebrowser.cache.get":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Session  bool   `json:"session"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		state, err := s.getTerminalState(req.BeaconID)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(state[mcpFileBrowserKey(req.Session)]), nil
	case "bebop.filebrowser.cache.set":
		var req struct {
			BeaconID uint32         `json:"beacon_id"`
			Session  bool           `json:"session"`
			Cache    map[string]any `json:"cache"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 || req.Cache == nil {
			return nil, fmt.Errorf("beacon_id and cache required")
		}
		state, err := s.getTerminalState(req.BeaconID)
		if err != nil {
			return nil, err
		}
		state[mcpFileBrowserKey(req.Session)] = req.Cache
		if err := s.client.putJSON(fmt.Sprintf("/api/terminal/%d", req.BeaconID), state, nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"saved": req.BeaconID, "session": req.Session}), nil
	case "bebop.chat.list":
		var req struct {
			Limit int `json:"limit"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		route := "/api/chat"
		if req.Limit > 0 {
			values := url.Values{}
			values.Set("limit", strconv.Itoa(req.Limit))
			route += "?" + values.Encode()
		}
		if err := s.client.getJSON(route, &out); err != nil {
			return nil, err
		}
	case "bebop.chat.send":
		var req struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Message) == "" {
			return nil, fmt.Errorf("message required")
		}
		if err := s.client.postJSON("/api/chat", req, &out); err != nil {
			return nil, err
		}
	case "bebop.identity.whoami":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "whoami"}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.fs.pwd":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "pwd"}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.fs.ls":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		cmdArgs := mcpOptionalArgs(req.Path)
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "ls", Args: cmdArgs}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.fs.cat":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Path) == "" {
			return nil, fmt.Errorf("path required")
		}
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "cat", Args: []string{req.Path}}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.fs.cd":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Path) == "" {
			return nil, fmt.Errorf("path required")
		}
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "cd", Args: []string{req.Path}}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.process.list":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "ps"}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.net.netstat":
		var req struct {
			BeaconID uint32   `json:"beacon_id"`
			Args     []string `json:"args"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		payload, err := s.queueCommandAndWait(mcpCommandArgs{BeaconID: req.BeaconID, Command: "netstat", Args: req.Args}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.domain.ldapsearch":
		var req struct {
			BeaconID uint32 `json:"beacon_id"`
			Filter   string `json:"filter"`
			Attrs    string `json:"attrs"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Filter) == "" {
			return nil, fmt.Errorf("filter required")
		}
		bofArgs := []string{req.Filter}
		if strings.TrimSpace(req.Attrs) != "" {
			bofArgs = append(bofArgs, req.Attrs)
		}
		payload, err := s.queueBOFAndWait(mcpModuleArgs{BeaconID: req.BeaconID, ObjectName: "ldapsearch", Args: bofArgs}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.domain.adcs_enum":
		var req struct {
			BeaconID uint32   `json:"beacon_id"`
			Args     []string `json:"args"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		payload, err := s.queueBOFAndWait(mcpModuleArgs{BeaconID: req.BeaconID, ObjectName: "adcs_enum", Args: req.Args}, args)
		if err != nil {
			return nil, err
		}
		return mcpContentResult(payload), nil
	case "bebop.command.run":
		var req mcpCommandArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		queued, err := s.queueCommand(req)
		if err != nil {
			return nil, err
		}
		out = queued
	case "bebop.command.execute":
		var req mcpCommandArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		out, err := s.queueCommand(req)
		if err != nil {
			return nil, err
		}
		label, err := mcpLabelFromQueued(out)
		if err != nil {
			return nil, err
		}
		result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(args, 60000))
		if err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"queued": out, "result": result}), nil
	case "bebop.bof.execute":
		var req mcpModuleArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		queued, err := s.queueBOF(req)
		if err != nil {
			return nil, err
		}
		out = queued
	case "bebop.bof.execute.wait":
		var req mcpModuleArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		out, err := s.queueBOF(req)
		if err != nil {
			return nil, err
		}
		label, err := mcpLabelFromQueued(out)
		if err != nil {
			return nil, err
		}
		result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(args, 60000))
		if err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"queued": out, "result": result}), nil
	case "bebop.inline-assembly.execute":
		var req mcpModuleArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		queued, err := s.queueInlineAssembly(req)
		if err != nil {
			return nil, err
		}
		out = queued
	case "bebop.inline-assembly.execute.wait":
		var req mcpModuleArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		out, err := s.queueInlineAssembly(req)
		if err != nil {
			return nil, err
		}
		label, err := mcpLabelFromQueued(out)
		if err != nil {
			return nil, err
		}
		result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(args, 60000))
		if err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"queued": out, "result": result}), nil
	case "bebop.beacon.sleep":
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
		body := map[string]any{
			"beacon_id": req.BeaconID,
			"type":      2,
			"code":      0,
			"args":      fmt.Sprintf("%d %d", *req.Seconds, req.Jitter),
		}
		if err := s.client.postJSON("/api/task", body, &out); err != nil {
			return nil, err
		}
	case "bebop.session.close":
		var req mcpIDArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if err := s.client.deleteJSON(fmt.Sprintf("/api/session/%d", req.BeaconID), nil); err != nil {
			return nil, err
		}
		return mcpContentResult(map[string]any{"closed": req.BeaconID}), nil
	case "bebop.beacon.exit":
		var req mcpIDArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		body := map[string]any{"beacon_id": req.BeaconID, "type": 1, "code": 0, "args": ""}
		if err := s.client.postJSON("/api/task", body, &out); err != nil {
			return nil, err
		}
	case "bebop.beacon.interactive":
		var req mcpIDArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if err := s.client.postJSON("/api/interactive", map[string]any{"beacon_id": req.BeaconID, "port": 4443}, &out); err != nil {
			return nil, err
		}
	case "bebop.socks.list":
		if err := s.client.getJSON("/api/socks", &out); err != nil {
			return nil, err
		}
	case "bebop.socks.start":
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
		if err := s.client.postJSON("/api/socks", map[string]any{"beacon_id": req.BeaconID, "port": req.Port}, &out); err != nil {
			return nil, err
		}
	case "bebop.socks.stop":
		var req mcpIDArgs
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, err
		}
		if req.BeaconID == 0 {
			return nil, fmt.Errorf("beacon_id required")
		}
		if err := s.client.deleteJSON(fmt.Sprintf("/api/socks/%d", req.BeaconID), nil); err != nil {
			return nil, err
		}
		out = map[string]any{"stopped": req.BeaconID}
	default:
		return nil, fmt.Errorf("tool not implemented: %s", params.Name)
	}

	return mcpContentResult(out), nil
}

func (s *mcpHTTPServer) queueCommand(req mcpCommandArgs) (any, error) {
	if req.BeaconID == 0 || strings.TrimSpace(req.Command) == "" {
		return nil, fmt.Errorf("beacon_id and command required")
	}
	transport := strings.TrimSpace(req.Transport)
	if transport == "" || transport == "auto" {
		transport = "session"
	} else if transport != "http" && transport != "session" {
		return nil, fmt.Errorf("transport must be auto, http, or session")
	}
	body := map[string]any{
		"beacon_id": req.BeaconID,
		"type":      12,
		"code":      0,
		"args":      mcpJoinCommandArgs(req.Command, req.Args),
		"transport": transport,
	}
	var out any
	if err := s.client.postJSON("/api/task", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *mcpHTTPServer) queueBOF(req mcpModuleArgs) (any, error) {
	if req.BeaconID == 0 || strings.TrimSpace(req.ObjectName) == "" {
		return nil, fmt.Errorf("beacon_id and object_name required")
	}
	fields := map[string]string{
		"beacon_id":   fmt.Sprintf("%d", req.BeaconID),
		"object_name": req.ObjectName,
		"args":        mcpJoinArgs(req.Args),
	}
	var out any
	if err := s.client.postMultipart("/api/bof", fields, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *mcpHTTPServer) queueInlineAssembly(req mcpModuleArgs) (any, error) {
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
		"args":          mcpJoinArgs(req.Args),
		"mode":          mode,
	}
	var out any
	if err := s.client.postMultipart("/api/inline-assembly", fields, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *mcpHTTPServer) queueCommandAndWait(req mcpCommandArgs, raw json.RawMessage) (map[string]any, error) {
	out, err := s.queueCommand(req)
	if err != nil {
		return nil, err
	}
	label, err := mcpLabelFromQueued(out)
	if err != nil {
		return nil, err
	}
	result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(raw, 60000))
	if err != nil {
		return nil, err
	}
	return map[string]any{"queued": out, "result": result}, nil
}

func (s *mcpHTTPServer) queueBOFAndWait(req mcpModuleArgs, raw json.RawMessage) (map[string]any, error) {
	out, err := s.queueBOF(req)
	if err != nil {
		return nil, err
	}
	label, err := mcpLabelFromQueued(out)
	if err != nil {
		return nil, err
	}
	result, err := s.waitForResult(req.BeaconID, label, mcpTimeoutFromArgs(raw, 60000))
	if err != nil {
		return nil, err
	}
	return map[string]any{"queued": out, "result": result}, nil
}

func mcpLabelFromQueued(out any) (uint32, error) {
	if v, ok := out.(map[string]any); ok {
		label := mcpNumericID(v["label"])
		if label != 0 {
			return label, nil
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return 0, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return 0, err
	}
	label := mcpNumericID(decoded["label"])
	if label == 0 {
		return 0, fmt.Errorf("queued response missing label")
	}
	return label, nil
}

func mcpOptionalArgs(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func mcpContentResult(v any) map[string]any {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		encoded = []byte(fmt.Sprintf("%v", v))
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(encoded)},
		},
	}
}

func mcpTextResult(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
	}
}

func mcpBinaryPayload(filename string, contentType string, data []byte, extra map[string]any) map[string]any {
	sum := sha256.Sum256(data)
	payload := map[string]any{
		"filename":       filename,
		"content_type":   contentType,
		"size":           len(data),
		"sha256":         fmt.Sprintf("%x", sum[:]),
		"content_base64": base64.StdEncoding.EncodeToString(data),
	}
	for key, value := range extra {
		payload[key] = value
	}
	return payload
}

func mcpFilenameFromDisposition(disposition string, fallback string) string {
	_, params, err := mime.ParseMediaType(disposition)
	if err == nil {
		if filename := strings.TrimSpace(params["filename"]); filename != "" {
			return filename
		}
	}
	return fallback
}

func mcpDecodeBase64(value string, field string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%s required", field)
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s invalid", field)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s too large", field)
	}
	return data, nil
}

func (s *mcpHTTPServer) getTerminalState(beaconID uint32) (map[string]any, error) {
	var state map[string]any
	if err := s.client.getJSON(fmt.Sprintf("/api/terminal/%d", beaconID), &state); err != nil {
		return nil, err
	}
	if state == nil {
		state = make(map[string]any)
	}
	if _, ok := state["output_log"]; !ok {
		state["output_log"] = []any{}
	}
	if _, ok := state["cmd_history"]; !ok {
		state["cmd_history"] = []any{}
	}
	if _, ok := state["poll_since"]; !ok {
		state["poll_since"] = 0
	}
	return state, nil
}

func (s *mcpHTTPServer) saveFileBrowserCache(beaconID uint32, remotePath string, session bool, entries []map[string]any) (map[string]any, error) {
	state, err := s.getTerminalState(beaconID)
	if err != nil {
		return nil, err
	}
	key := mcpFileBrowserKey(session)
	cache, _ := state[key].(map[string]any)
	if cache == nil {
		cache = map[string]any{}
	}
	tree, _ := cache["tree"].(map[string]any)
	if tree == nil {
		tree = map[string]any{}
	}
	now := time.Now().Unix()
	tree[remotePath] = map[string]any{"entries": entries, "touched": now}
	cache["tree"] = tree
	cache["selected"] = remotePath
	if strings.TrimSpace(mcpStringFromAny(cache["root"])) == "" {
		cache["root"] = remotePath
	}
	if strings.TrimSpace(mcpStringFromAny(cache["sep"])) == "" {
		cache["sep"] = mcpPathSeparator(remotePath)
	}
	cache["saved_at"] = now
	cache["expanded"] = mcpAppendUniqueString(cache["expanded"], remotePath)
	state[key] = cache
	if err := s.client.putJSON(fmt.Sprintf("/api/terminal/%d", beaconID), state, nil); err != nil {
		return nil, err
	}
	return cache, nil
}

func mcpFileBrowserKey(session bool) string {
	if session {
		return "session_file_browser"
	}
	return "file_browser"
}

func mcpParseFileBrowserEntries(result any) ([]map[string]any, error) {
	item, ok := result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("filebrowser result has unexpected shape")
	}
	output := mcpStringFromAny(item["output"])
	start := strings.Index(output, "[")
	if start < 0 {
		return nil, fmt.Errorf("filebrowser output did not contain JSON array")
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(output[start:]), &entries); err != nil {
		return nil, fmt.Errorf("parse filebrowser output: %w", err)
	}
	return entries, nil
}

func mcpStringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func mcpPathSeparator(remotePath string) string {
	if strings.Contains(remotePath, `\`) {
		return `\`
	}
	return "/"
}

func mcpAppendUniqueString(raw any, value string) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	switch values := raw.(type) {
	case []any:
		for _, item := range values {
			if text := mcpStringFromAny(item); text != "" && !seen[text] {
				seen[text] = true
				out = append(out, text)
			}
		}
	case []string:
		for _, text := range values {
			if text != "" && !seen[text] {
				seen[text] = true
				out = append(out, text)
			}
		}
	}
	if value != "" && !seen[value] {
		out = append(out, value)
	}
	return out
}

func (s *mcpHTTPServer) listSessions() ([]map[string]any, error) {
	var sessions []map[string]any
	if err := s.client.getJSON("/api/sessions", &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *mcpHTTPServer) readSessionByID(beaconID uint32) (map[string]any, error) {
	if beaconID == 0 {
		return nil, fmt.Errorf("beacon_id required")
	}
	sessions, err := s.listSessions()
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if mcpNumericID(session["id"]) == beaconID {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session not found: %d", beaconID)
}

func mcpNumericID(v any) uint32 {
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

func mcpResultRoute(beaconID uint32, since int64) string {
	route := path.Join("/api/results", strconv.FormatUint(uint64(beaconID), 10))
	if since > 0 {
		values := url.Values{}
		values.Set("since", strconv.FormatInt(since, 10))
		route += "?" + values.Encode()
	}
	return route
}

func mcpJoinCommandArgs(command string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	if command != "" {
		parts = append(parts, command)
	}
	parts = append(parts, args...)
	return mcpJoinArgs(parts)
}

func mcpJoinArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, mcpQuoteArg(arg))
	}
	return strings.Join(quoted, " ")
}

func mcpQuoteArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\r\n\"") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, r := range arg {
		if r == '\\' {
			backslashes++
			continue
		}
		if r == '"' {
			b.WriteString(strings.Repeat(`\`, backslashes*2+1))
			b.WriteRune(r)
			backslashes = 0
			continue
		}
		if backslashes > 0 {
			b.WriteString(strings.Repeat(`\`, backslashes))
			backslashes = 0
		}
		b.WriteRune(r)
	}
	if backslashes > 0 {
		b.WriteString(strings.Repeat(`\`, backslashes*2))
	}
	b.WriteByte('"')
	return b.String()
}
