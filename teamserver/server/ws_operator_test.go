package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"c2/auth"
	"c2/protocol"
)

// wsTestEnv is a minimal harness: HTTP test server + Hub + Store + Handler
// with a valid JWT key. Returns a WS-ready URL that uses a short-lived ticket.
type wsTestEnv struct {
	server   *httptest.Server
	hub      *Hub
	handler  *Handler
	jwtKey   []byte
	username string
}

func newWSTestEnv(t *testing.T, username string) *wsTestEnv {
	t.Helper()

	s := newTestStore(t)

	jwtKey := make([]byte, 32)
	if _, err := rand.Read(jwtKey); err != nil {
		t.Fatalf("jwt key: %v", err)
	}

	privKey, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}

	hub := NewHub()
	h := NewHandler(s, privKey, "", &noopLM{}, &nopPersister{}, 0, nil, hub, nil, nil, jwtKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/ws-ticket", h.authMiddleware(h.HandleWSTicket))
	mux.HandleFunc("/ws/operator", handleOperatorWebSocket(hub, s, h))

	srv := httptest.NewServer(mux)
	t.Cleanup(func() { srv.Close() })

	return &wsTestEnv{
		server:   srv,
		hub:      hub,
		handler:  h,
		jwtKey:   jwtKey,
		username: username,
	}
}

func (e *wsTestEnv) token() string {
	tok, err := auth.SignToken(e.username, e.jwtKey)
	if err != nil {
		panic(err)
	}
	return tok
}

func (e *wsTestEnv) wsURL(t *testing.T) string {
	t.Helper()
	ticket := e.wsTicket(t)
	return "ws" + strings.TrimPrefix(e.server.URL, "http") + "/ws/operator?ticket=" + ticket
}

func (e *wsTestEnv) legacyTokenURL() string {
	return "ws" + strings.TrimPrefix(e.server.URL, "http") + "/ws/operator?token=" + e.token()
}

func (e *wsTestEnv) wsTicket(t *testing.T) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/api/ws-ticket", nil)
	if err != nil {
		t.Fatalf("ticket req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token())
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("ticket post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ticket status = %d", resp.StatusCode)
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("ticket decode: %v", err)
	}
	if body.Ticket == "" {
		t.Fatal("empty ticket")
	}
	return body.Ticket
}

func dialWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	return c
}

func dialWSWithOrigin(t *testing.T, url string, origin string) (*websocket.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{origin}},
	})
	return c, err
}

func readEvent(t *testing.T, c *websocket.Conn) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var e Event
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return e
}

// --- Tests ---

func TestInitialChatSync(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	if _, err := env.handler.store.AddChatMessage("alice", "hello"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	conn := dialWS(t, env.wsURL(t))

	// Drain initial sync events until we see a chat sync.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		readCtx, readCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, data, err := conn.Read(readCtx)
		readCancel()
		if err != nil {
			continue
		}
		var evt Event
		if err := json.Unmarshal(data, &evt); err != nil {
			continue
		}
		if evt.Topic == "chat" && evt.Action == "sync" {
			return // PASS
		}
	}
	t.Fatal("did not receive chat sync within timeout")
}

func TestWebSocketRejectsBearerQueryTokenByDefault(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, env.legacyTokenURL(), nil)
	if err == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		t.Fatal("legacy bearer query token connected")
	}
}

func TestWebSocketTicketIsSingleUse(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	url := env.wsURL(t)
	conn := dialWS(t, url)
	_ = conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reused, _, err := websocket.Dial(ctx, url, nil)
	if err == nil {
		_ = reused.Close(websocket.StatusNormalClosure, "")
		t.Fatal("reused websocket ticket connected")
	}
}

func TestWebSocketAllowsLocalhostOperatorOrigin(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	conn, err := dialWSWithOrigin(t, env.wsURL(t), "http://localhost:9090")
	if err != nil {
		t.Fatalf("dial with localhost origin: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
}

func TestWebSocketAllowsExternalOriginByDefault(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	conn, err := dialWSWithOrigin(t, env.wsURL(t), "https://evil.example")
	if err != nil {
		t.Fatalf("dial with external origin: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
}

func TestWebSocketRejectsExternalOriginWhenAllowlistConfigured(t *testing.T) {
	t.Setenv("BEBOP_ALLOWED_ORIGINS", "https://ops.example")
	env := newWSTestEnv(t, "alice")
	conn, err := dialWSWithOrigin(t, env.wsURL(t), "https://evil.example")
	if err == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		t.Fatal("external origin connected despite allowlist")
	}
}

func TestWebSocketAllowsConfiguredURLOrigin(t *testing.T) {
	t.Setenv("BEBOP_ALLOWED_ORIGINS", "https://ops.example")
	env := newWSTestEnv(t, "alice")
	conn, err := dialWSWithOrigin(t, env.wsURL(t), "https://ops.example")
	if err != nil {
		t.Fatalf("dial with configured origin: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
}

func TestInboundChatBroadcastsToAllSubscribers(t *testing.T) {
	env := newWSTestEnv(t, "alice")

	c1 := dialWS(t, env.wsURL(t))
	c2 := dialWS(t, env.wsURL(t))
	drainInitialSync(t, c1)
	drainInitialSync(t, c2)

	send := map[string]any{
		"topic":  "chat",
		"action": "send",
		"data":   map[string]string{"message": "hello world"},
	}
	b, _ := json.Marshal(send)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c1.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, conn := range []*websocket.Conn{c1, c2} {
		evt := waitForChatAdd(t, conn)
		raw, _ := json.Marshal(evt.Data)
		var got struct {
			Operator string `json:"operator"`
			Message  string `json:"message"`
		}
		_ = json.Unmarshal(raw, &got)
		if got.Operator != "alice" {
			t.Fatalf("operator = %q, want alice", got.Operator)
		}
		if got.Message != "hello world" {
			t.Fatalf("message = %q, want 'hello world'", got.Message)
		}
	}
}

func TestInboundChatUsesJWTUsername(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	c := dialWS(t, env.wsURL(t))
	drainInitialSync(t, c)

	// Attempt to spoof operator via payload.
	send := map[string]any{
		"topic":  "chat",
		"action": "send",
		"data":   map[string]string{"message": "pwned", "operator": "eve"},
	}
	b, _ := json.Marshal(send)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}

	evt := waitForChatAdd(t, c)
	raw, _ := json.Marshal(evt.Data)
	var got struct {
		Operator string `json:"operator"`
	}
	_ = json.Unmarshal(raw, &got)
	if got.Operator != "alice" {
		t.Fatalf("operator = %q, want alice (must come from JWT, not payload)", got.Operator)
	}
}

func TestInboundChatRejectsEmpty(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	c := dialWS(t, env.wsURL(t))
	drainInitialSync(t, c)

	for _, payload := range []string{"", "   ", "\t\n"} {
		send := map[string]any{
			"topic":  "chat",
			"action": "send",
			"data":   map[string]string{"message": payload},
		}
		b, _ := json.Marshal(send)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		if err := c.Write(ctx, websocket.MessageText, b); err != nil {
			cancel()
			t.Fatalf("write: %v", err)
		}
		cancel()
	}

	// No chat add event should be produced. After 500ms of silence the
	// test passes. Use a short read timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, _, err := c.Read(ctx)
	if err == nil {
		t.Fatal("expected timeout — no event should have been sent")
	}

	if n := len(env.handler.store.ListChatMessages(0)); n != 0 {
		t.Fatalf("expected 0 stored messages, got %d", n)
	}
}

func TestInboundChatRejectsOversize(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	c := dialWS(t, env.wsURL(t))
	drainInitialSync(t, c)

	big := strings.Repeat("x", 2001)
	send := map[string]any{
		"topic":  "chat",
		"action": "send",
		"data":   map[string]string{"message": big},
	}
	b, _ := json.Marshal(send)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer readCancel()
	_, _, err := c.Read(readCtx)
	if err == nil {
		t.Fatal("expected timeout — oversize message must be dropped")
	}

	if n := len(env.handler.store.ListChatMessages(0)); n != 0 {
		t.Fatalf("expected 0 stored messages, got %d", n)
	}
}

func TestInboundChatRateLimit(t *testing.T) {
	env := newWSTestEnv(t, "alice")
	c := dialWS(t, env.wsURL(t))
	drainInitialSync(t, c)

	// Send 15 rapid messages. Only 10 should get through (burst size).
	for i := 0; i < 15; i++ {
		send := map[string]any{
			"topic":  "chat",
			"action": "send",
			"data":   map[string]string{"message": "m"},
		}
		b, _ := json.Marshal(send)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		if err := c.Write(ctx, websocket.MessageText, b); err != nil {
			cancel()
			t.Fatalf("write %d: %v", i, err)
		}
		cancel()
	}

	// Drain up to 10 chat/add events; the 11th–15th must be rate-limited.
	received := 0
	deadline := time.Now().Add(2 * time.Second)
	for received < 10 && time.Now().Before(deadline) {
		readCtx, readCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, data, err := c.Read(readCtx)
		readCancel()
		if err != nil {
			break
		}
		var evt Event
		if err := json.Unmarshal(data, &evt); err != nil {
			continue
		}
		if evt.Topic == "chat" && evt.Action == "add" {
			received++
		}
	}
	if received != 10 {
		t.Fatalf("received %d chat/add events, want 10", received)
	}
	stored := env.handler.store.ListChatMessages(0)
	if len(stored) != 10 {
		t.Fatalf("stored = %d, want 10", len(stored))
	}
}

// --- helpers ---

func drainInitialSync(t *testing.T, c *websocket.Conn) {
	t.Helper()
	// The server sends 6 sync events up-front (sessions, listeners,
	// events, loot, library, chat). Read them all.
	for i := 0; i < 6; i++ {
		_ = readEvent(t, c)
	}
}

func waitForChatAdd(t *testing.T, c *websocket.Conn) Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evt := readEvent(t, c)
		if evt.Topic == "chat" && evt.Action == "add" {
			return evt
		}
	}
	t.Fatal("timed out waiting for chat add event")
	return Event{}
}
