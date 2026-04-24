package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"c2/models"
	"c2/protocol"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newMeta(id uint32) *models.ImplantMetadata {
	return &models.ImplantMetadata{ID: id, SessionKey: make([]byte, 32), Sleep: 60}
}

func TestRegisterAndGetBeacon(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(1))

	b := s.GetBeacon(1)
	if b == nil {
		t.Fatal("expected beacon, got nil")
	}
	if b.ID != 1 {
		t.Fatalf("expected ID 1, got %d", b.ID)
	}
	if b.FirstSeen.IsZero() {
		t.Fatal("FirstSeen not set")
	}
}

func TestGetBeacon_UnknownID(t *testing.T) {
	s := newStore(t)
	if s.GetBeacon(999) != nil {
		t.Fatal("expected nil for unknown beacon")
	}
}

func TestUpdateLastSeen(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(2))
	before := s.GetBeacon(2).LastSeen

	time.Sleep(2 * time.Millisecond)
	s.UpdateLastSeen(2)

	after := s.GetBeacon(2).LastSeen
	if !after.After(before) {
		t.Fatal("LastSeen was not updated")
	}
}

func TestGetNextTask_EmptyQueue(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(3))

	if s.GetNextTask(3) != nil {
		t.Fatal("expected nil task for empty queue")
	}
}

func TestGetNextTask_ReturnsPendingAndMarksSent(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(4))
	s.QueueTask(&models.Task{Label: 10, BeaconID: 4, Type: 12, Status: models.TaskStatusPending})

	task := s.GetNextTask(4)
	if task == nil {
		t.Fatal("expected task, got nil")
	}
	if task.Label != 10 {
		t.Fatalf("expected label 10, got %d", task.Label)
	}
	if task.Status != models.TaskStatusSent {
		t.Fatalf("expected SENT, got %s", task.Status)
	}

	// second call must return nil (no more PENDING)
	if s.GetNextTask(4) != nil {
		t.Fatal("expected nil on second call")
	}
}

func TestUpdateLastSeen_UnknownID(t *testing.T) {
	s := newStore(t)
	// must not panic on unknown ID
	s.UpdateLastSeen(9999)
}

func TestListBeacons_Empty(t *testing.T) {
	s := newStore(t)
	if len(s.ListBeacons()) != 0 {
		t.Fatal("expected empty slice")
	}
}

func TestListBeacons_ReturnsCopies(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(10))
	s.RegisterBeacon(newMeta(11))
	beacons := s.ListBeacons()
	if len(beacons) != 2 {
		t.Fatalf("expected 2 beacons, got %d", len(beacons))
	}
	// Mutate returned beacon — internal state must not change
	beacons[0].Sleep = 9999
	internal := s.GetBeacon(beacons[0].ID)
	if internal.Sleep == 9999 {
		t.Fatal("ListBeacons returned a live pointer, not a copy")
	}
}

func TestStoreAndGetResults(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(20))
	s.StoreResult(&models.Result{Label: 10, BeaconID: 20, Output: "root"})

	results := s.GetResults(20)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Output != "root" {
		t.Fatalf("output mismatch: %q", results[0].Output)
	}
}

func TestGetResultsSince(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(21))

	before := time.Now()
	time.Sleep(2 * time.Millisecond)
	s.StoreResult(&models.Result{Label: 10, BeaconID: 21, Output: "root", ReceivedAt: time.Now()})

	if len(s.GetResultsSince(21, 0)) != 1 {
		t.Fatal("expected 1 result with since=0")
	}
	if len(s.GetResultsSince(21, time.Now().Add(time.Hour).Unix())) != 0 {
		t.Fatal("expected 0 results with future since")
	}
	if len(s.GetResultsSince(21, before.Unix()-1)) != 1 {
		t.Fatal("expected 1 result with before since")
	}
}

func TestMarkTaskDone(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(22))
	s.QueueTask(&models.Task{Label: 99, BeaconID: 22, Type: 12, Status: models.TaskStatusPending})
	s.GetNextTask(22) // marks SENT

	s.MarkTaskDone(99)

	if s.GetNextTask(22) != nil {
		t.Fatal("expected nil after task completed")
	}
}

func TestMarkTaskDone_UnknownLabel(t *testing.T) {
	s := newStore(t)
	s.MarkTaskDone(0xDEAD) // must not panic
}

func TestDeleteBeacon(t *testing.T) {
	s := newStore(t)
	meta := &models.ImplantMetadata{ID: 7, SessionKey: make([]byte, 32), Sleep: 5}
	s.RegisterBeacon(meta)

	if s.GetBeacon(7) == nil {
		t.Fatal("beacon must exist before delete")
	}

	s.DeleteBeacon(7)

	if s.GetBeacon(7) != nil {
		t.Fatal("GetBeacon should return nil after DeleteBeacon")
	}
	// Verify tasks and results are cleaned up via public API
	if s.GetNextTask(7) != nil {
		t.Error("tasks entry should be removed after DeleteBeacon")
	}
	if len(s.GetResults(7)) != 0 {
		t.Error("results entry should be removed after DeleteBeacon")
	}
}

func TestAddAndListListeners(t *testing.T) {
	s := newStore(t)
	l := &models.Listener{Name: "test", Scheme: "http", Host: "127.0.0.1", Port: 9000}
	s.AddListener(l)

	if l.ID == 0 {
		t.Fatal("expected non-zero ID after AddListener")
	}

	list := s.ListListeners()
	if len(list) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(list))
	}
	if list[0].ID != l.ID {
		t.Fatalf("wrong ID: got %d", list[0].ID)
	}
}

func TestGetListener(t *testing.T) {
	s := newStore(t)
	l := &models.Listener{Name: "x", Scheme: "https", Host: "10.0.0.1", Port: 443}
	s.AddListener(l)

	got := s.GetListener(l.ID)
	if got == nil {
		t.Fatal("expected listener, got nil")
	}
	if got.Scheme != "https" {
		t.Fatalf("expected https, got %s", got.Scheme)
	}
	if s.GetListener(9999) != nil {
		t.Fatal("expected nil for unknown id")
	}
}

func TestRemoveListener(t *testing.T) {
	s := newStore(t)
	l := &models.Listener{Name: "rm", Scheme: "http", Host: "127.0.0.1", Port: 9001}
	s.AddListener(l)
	id := l.ID

	s.RemoveListener(id)

	if s.GetListener(id) != nil {
		t.Fatal("listener still present after removal")
	}
	if len(s.ListListeners()) != 0 {
		t.Fatal("expected empty list after removal")
	}
}

func TestListenerIDsAreUnique(t *testing.T) {
	s := newStore(t)
	a := &models.Listener{Name: "a", Scheme: "http", Host: "127.0.0.1", Port: 9010}
	b := &models.Listener{Name: "b", Scheme: "http", Host: "127.0.0.1", Port: 9011}
	s.AddListener(a)
	s.AddListener(b)
	if a.ID == b.ID {
		t.Fatalf("duplicate IDs: both got %d", a.ID)
	}
}

func TestAllResults(t *testing.T) {
	s := newStore(t)
	s.StoreResult(&models.Result{Label: 1, BeaconID: 10, Output: "a", ReceivedAt: time.Now()})
	s.StoreResult(&models.Result{Label: 2, BeaconID: 10, Output: "b", ReceivedAt: time.Now()})
	s.StoreResult(&models.Result{Label: 3, BeaconID: 20, Output: "c", ReceivedAt: time.Now()})

	all := s.AllResults()
	if len(all) != 2 {
		t.Fatalf("expected 2 beacon entries, got %d", len(all))
	}
	if len(all[10]) != 2 {
		t.Fatalf("expected 2 results for beacon 10, got %d", len(all[10]))
	}
	if len(all[20]) != 1 {
		t.Fatalf("expected 1 result for beacon 20, got %d", len(all[20]))
	}
	// Verify snapshot isolation
	all[10][0].Output = "MUTATED"
	fresh := s.AllResults()
	if fresh[10][0].Output == "MUTATED" {
		t.Fatal("AllResults returned a non-snapshot (mutation visible in store)")
	}
}

func TestLoadBeacons(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	bs := []*models.Beacon{
		{ImplantMetadata: models.ImplantMetadata{ID: 7, Hostname: "HOST"}, FirstSeen: now, LastSeen: now},
	}
	s.LoadBeacons(bs)

	got := s.GetBeacon(7)
	if got == nil {
		t.Fatal("beacon not found after LoadBeacons")
	}
	if got.Hostname != "HOST" {
		t.Errorf("expected HOST, got %s", got.Hostname)
	}
}

func TestLoadListeners(t *testing.T) {
	s := newStore(t)
	ls := []*models.Listener{
		{ID: 3, Name: "a", Scheme: "http", Host: "h", Port: 80},
		{ID: 7, Name: "b", Scheme: "https", Host: "h", Port: 443},
	}
	s.LoadListeners(ls)

	// listenerSeq must be max(ID) so the next AddListener gets ID 8
	next := &models.Listener{Name: "c", Scheme: "http", Host: "h", Port: 9000}
	s.AddListener(next)
	if next.ID != 8 {
		t.Fatalf("expected next listener ID=8, got %d", next.ID)
	}
	if s.GetListener(3) == nil || s.GetListener(7) == nil {
		t.Fatal("loaded listeners not found")
	}
}

func TestLoadResults(t *testing.T) {
	// LoadResults was removed; results are now persisted directly via StoreResult into SQLite.
	s := newStore(t)
	s.StoreResult(&models.Result{Label: 1, BeaconID: 42, Output: "out", ReceivedAt: time.Now()})

	got := s.GetResults(42)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].Output != "out" {
		t.Errorf("output mismatch: %q", got[0].Output)
	}
}

func TestExfilFragmentAssembly(t *testing.T) {
	s := newStore(t)

	// Fragment 0: [uint16 name_len=4]["file"]["AAAA"]
	frag0 := []byte{4, 0, 'f', 'i', 'l', 'e', 'A', 'A', 'A', 'A'}
	done0, name0, data0 := s.AddExfilFragment(42, 0, protocol.FlagFragmented, frag0)
	if done0 {
		t.Fatal("should not be done after fragment 0")
	}
	_ = name0
	_ = data0

	// Fragment 1: last frag, data="BBBB"
	frag1 := []byte{'B', 'B', 'B', 'B'}
	done1, name1, assembled := s.AddExfilFragment(42, 1, protocol.FlagLastFragment, frag1)
	if !done1 {
		t.Fatal("should be done after last fragment")
	}
	if name1 != "file" {
		t.Fatalf("expected filename 'file', got %q", name1)
	}
	if string(assembled) != "AAAABBBB" {
		t.Fatalf("expected 'AAAABBBB', got %q", string(assembled))
	}

	s.MarkExfilDone(42, "file", 1, 8)
	entry := s.GetExfilFile(42)
	if entry == nil {
		t.Fatal("expected exfil entry after MarkExfilDone")
	}
	if entry.Filename != "file" {
		t.Fatalf("expected filename 'file', got %q", entry.Filename)
	}

	s.DeleteExfilFile(42)
	if s.GetExfilFile(42) != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestExfilSingleFragment(t *testing.T) {
	s := newStore(t)
	// Single last-frag chunk: [uint16 name_len=3]["foo"]["XYZ"]
	frag := []byte{3, 0, 'f', 'o', 'o', 'X', 'Y', 'Z'}
	done, name, data := s.AddExfilFragment(99, 0, protocol.FlagLastFragment, frag)
	if !done {
		t.Fatal("single fragment must be done immediately")
	}
	if name != "foo" {
		t.Fatalf("expected 'foo', got %q", name)
	}
	if string(data) != "XYZ" {
		t.Fatalf("expected 'XYZ', got %q", string(data))
	}
}

func TestExfilDuplicateFragment(t *testing.T) {
	s := newStore(t)
	frag0 := []byte{3, 0, 'f', 'o', 'o', 'A', 'A'}
	s.AddExfilFragment(50, 0, protocol.FlagFragmented, frag0)

	// Send duplicate fragment 0 — must be ignored
	dup := []byte{3, 0, 'f', 'o', 'o', 'X', 'X'}
	s.AddExfilFragment(50, 0, protocol.FlagFragmented, dup)

	frag1 := []byte{'B', 'B'}
	done, _, assembled := s.AddExfilFragment(50, 1, protocol.FlagLastFragment, frag1)
	if !done {
		t.Fatal("should be done")
	}
	if string(assembled) != "AABB" {
		t.Fatalf("expected 'AABB', got %q (duplicate fragment was not rejected)", string(assembled))
	}
}

func TestConcurrentRegisterAndCheckin(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup

	for i := uint32(1); i <= 50; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			s.RegisterBeacon(&models.ImplantMetadata{ID: id, SessionKey: make([]byte, 32), Sleep: 60})
		}(i)
	}
	wg.Wait()

	// Concurrent reads + UpdateLastSeen
	for i := uint32(1); i <= 50; i++ {
		wg.Add(2)
		go func(id uint32) {
			defer wg.Done()
			s.GetBeacon(id)
		}(i)
		go func(id uint32) {
			defer wg.Done()
			s.UpdateLastSeen(id)
		}(i)
	}
	wg.Wait()

	if len(s.ListBeacons()) != 50 {
		t.Fatalf("expected 50 beacons, got %d", len(s.ListBeacons()))
	}
}

func TestConcurrentTaskQueue(t *testing.T) {
	s := newStore(t)
	s.RegisterBeacon(newMeta(100))

	var wg sync.WaitGroup
	for i := uint32(0); i < 100; i++ {
		wg.Add(1)
		go func(label uint32) {
			defer wg.Done()
			s.QueueTask(&models.Task{Label: label, BeaconID: 100, Type: 12, Status: models.TaskStatusPending})
		}(i)
	}
	wg.Wait()

	// Drain all tasks concurrently
	var consumed uint32
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if t := s.GetNextTask(100); t != nil {
				mu.Lock()
				consumed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if consumed != 100 {
		t.Fatalf("expected 100 consumed tasks, got %d", consumed)
	}
}

func TestConcurrentStoreResults(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	for i := uint32(0); i < 50; i++ {
		wg.Add(2)
		go func(label uint32) {
			defer wg.Done()
			s.StoreResult(&models.Result{Label: label, BeaconID: 1, Output: "x", ReceivedAt: time.Now()})
		}(i)
		go func() {
			defer wg.Done()
			s.AllResults()
		}()
	}
	wg.Wait()

	all := s.AllResults()
	if len(all[1]) != 50 {
		t.Fatalf("expected 50 results, got %d", len(all[1]))
	}
}

func TestAddChatMessage(t *testing.T) {
	s := newStore(t)

	before := time.Now().Add(-time.Second)
	msg, err := s.AddChatMessage("alice", "hello")
	if err != nil {
		t.Fatalf("AddChatMessage: %v", err)
	}
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	if msg.ID == 0 {
		t.Fatalf("expected ID > 0, got %d", msg.ID)
	}
	if msg.Operator != "alice" {
		t.Fatalf("operator = %q, want alice", msg.Operator)
	}
	if msg.Message != "hello" {
		t.Fatalf("message = %q, want hello", msg.Message)
	}
	if msg.Timestamp.Before(before) {
		t.Fatalf("timestamp %v older than %v", msg.Timestamp, before)
	}
}

func TestListChatMessagesOrder(t *testing.T) {
	s := newStore(t)

	for i := 0; i < 3; i++ {
		if _, err := s.AddChatMessage("op", fmt.Sprintf("m%d", i)); err != nil {
			t.Fatalf("AddChatMessage: %v", err)
		}
	}

	got := s.ListChatMessages(0)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, m := range got {
		want := fmt.Sprintf("m%d", i)
		if m.Message != want {
			t.Fatalf("msg[%d] = %q, want %q", i, m.Message, want)
		}
	}
}

func TestListChatMessagesLimit(t *testing.T) {
	s := newStore(t)

	for i := 0; i < 5; i++ {
		if _, err := s.AddChatMessage("op", fmt.Sprintf("m%d", i)); err != nil {
			t.Fatalf("AddChatMessage: %v", err)
		}
	}

	got := s.ListChatMessages(2)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Last 2 messages in chronological order: m3, m4.
	if got[0].Message != "m3" || got[1].Message != "m4" {
		t.Fatalf("got %q,%q want m3,m4", got[0].Message, got[1].Message)
	}
}

func TestResetChatMessages(t *testing.T) {
	s := newStore(t)
	if _, err := s.AddChatMessage("op", "hi"); err != nil {
		t.Fatalf("AddChatMessage: %v", err)
	}
	if err := s.ResetChatMessages(); err != nil {
		t.Fatalf("ResetChatMessages: %v", err)
	}
	got := s.ListChatMessages(0)
	if len(got) != 0 {
		t.Fatalf("len after reset = %d, want 0", len(got))
	}
}
