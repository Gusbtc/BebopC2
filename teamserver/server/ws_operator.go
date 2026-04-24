package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"nhooyr.io/websocket"

	"c2/store"
)

// InboundMsg is the envelope for every client->server WebSocket message
// on the operator channel. Mirrors Event (server->client) but keeps Data
// as RawMessage so each topic handler can decode its own payload shape.
type InboundMsg struct {
	Topic  string          `json:"topic"`
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data"`
}

func handleOperatorWebSocket(hub *Hub, s *store.Store, h *Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := h.validateWSToken(w, r)
		if !ok {
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		defer conn.CloseNow()

		ch := hub.Subscribe()
		defer hub.Unsubscribe(ch)

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// Send initial sync snapshots.
		syncs := []Event{
			{Topic: "sessions", Action: "sync", Data: buildSessionList(s, h)},
			{Topic: "listeners", Action: "sync", Data: s.ListListeners()},
			{Topic: "events", Action: "sync", Data: s.ListEvents()},
			{Topic: "loot", Action: "sync", Data: s.ListExfilFiles()},
			{Topic: "chat", Action: "sync", Data: s.ListChatMessages(200)},
		}
		for _, evt := range syncs {
			b, _ := json.Marshal(evt)
			if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
				return
			}
		}

		// Read loop: client -> server messages (chat send, future types).
		go func() {
			defer cancel()
			for {
				_, data, err := conn.Read(ctx)
				if err != nil {
					return
				}
				var in InboundMsg
				if err := json.Unmarshal(data, &in); err != nil {
					continue
				}
				handleInbound(in, username, s, hub, h)
			}
		}()

		// Write loop: fan-out hub events.
		for {
			select {
			case <-ctx.Done():
				conn.Close(websocket.StatusNormalClosure, "")
				return
			case evt := <-ch:
				if err := conn.Write(ctx, websocket.MessageText, evt.JSON()); err != nil {
					cancel()
					return
				}
			}
		}
	}
}

// handleInbound routes a validated inbound message by topic. Username is
// sourced from the JWT — never from the client payload.
func handleInbound(in InboundMsg, username string, s *store.Store, hub *Hub, h *Handler) {
	switch in.Topic {
	case "chat":
		handleChatInbound(in, username, s, hub, h)
	}
}

func handleChatInbound(in InboundMsg, username string, s *store.Store, hub *Hub, h *Handler) {
	if in.Action != "send" {
		return
	}
	var p struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(in.Data, &p); err != nil {
		return
	}
	msg := strings.TrimSpace(p.Message)
	if msg == "" || len(msg) > 2000 {
		return
	}
	if !h.chatRateLimit(username) {
		return
	}
	saved, err := s.AddChatMessage(username, msg)
	if err != nil {
		return
	}
	hub.Publish("chat", "add", saved)
}

// buildSessionList is kept verbatim from the previous implementation.
func buildSessionList(s *store.Store, h *Handler) interface{} {
	beacons := s.ListBeacons()
	type item struct {
		ID           uint32 `json:"id"`
		Hostname     string `json:"hostname"`
		Username     string `json:"username"`
		ProcessName  string `json:"process_name"`
		ProcessID    uint32 `json:"process_id"`
		Arch         uint8  `json:"arch"`
		Platform     uint8  `json:"platform"`
		Integrity    uint8  `json:"integrity"`
		Sleep        uint32 `json:"sleep"`
		Jitter       uint32 `json:"jitter"`
		FirstSeen    int64  `json:"first_seen"`
		LastSeen     int64  `json:"last_seen"`
		Alive        bool   `json:"alive"`
		ListenerID   uint32 `json:"listener_id"`
		ListenerName string `json:"listener_name"`
		Mode         string `json:"mode"`
		ShellActive  bool   `json:"shell_active"`
	}
	resp := make([]item, len(beacons))
	for i, b := range beacons {
		lName := "Unknown"
		if l := s.GetListener(b.ListenerID); l != nil {
			lName = l.Name
		}
		resp[i] = item{
			ID:           b.ID,
			Hostname:     b.Hostname,
			Username:     b.Username,
			ProcessName:  b.ProcessName,
			ProcessID:    b.ProcessID,
			Arch:         b.Arch,
			Platform:     b.Platform,
			Integrity:    b.Integrity,
			Sleep:        b.Sleep,
			Jitter:       b.Jitter,
			FirstSeen:    b.FirstSeen.Unix(),
			LastSeen:     b.LastSeen.Unix(),
			Alive:        b.IsAlive() || s.IsSession(b.ID),
			ListenerID:   b.ListenerID,
			ListenerName: lName,
			Mode: func() string {
				if s.IsSession(b.ID) {
					return "session"
				}
				return "beacon"
			}(),
			ShellActive: s.IsShell(b.ID),
		}
	}
	return resp
}
