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
// with a valid JWT key. Returns a WS-ready URL (ws://... with ?token=).
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

func (e *wsTestEnv) wsURL() string {
	tok, err := auth.SignToken(e.username, e.jwtKey)
	if err != nil {
		panic(err)
	}
	return "ws" + strings.TrimPrefix(e.server.URL, "http") + "/ws/operator?token=" + tok
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

	conn := dialWS(t, env.wsURL())

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

func TestInboundChatBroadcastsToAllSubscribers(t *testing.T) {
	env := newWSTestEnv(t, "alice")

	c1 := dialWS(t, env.wsURL())
	c2 := dialWS(t, env.wsURL())
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
	c := dialWS(t, env.wsURL())
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
	c := dialWS(t, env.wsURL())
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
	c := dialWS(t, env.wsURL())
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
	c := dialWS(t, env.wsURL())
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
	// The server sends 5 sync events up-front (sessions, listeners,
	// events, loot, chat). Read them all.
	for i := 0; i < 5; i++ {
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
