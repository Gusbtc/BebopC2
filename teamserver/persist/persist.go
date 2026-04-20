package persist

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"c2/models"
	"c2/ui"
)

// Persister saves and loads operator session state to a local directory.
// Save operations are enqueued and processed by a background goroutine
// to avoid fire-and-forget goroutines. Call Start() before use and
// Shutdown() on exit to flush pending writes.
type Persister struct {
	dir  string
	mu   sync.Mutex
	ops  chan func()
	done chan struct{}
}

// Meta holds summary counts for the startup prompt.
type Meta struct {
	SavedAt   time.Time `json:"saved_at"`
	Listeners int       `json:"listeners"`
	Beacons   int       `json:"beacons"`
	Results   int       `json:"results"`
	Loot      int       `json:"loot"`
	Terminals int       `json:"terminals"`
}

// Session holds all persisted state loaded at startup.
type Session struct {
	Listeners []*models.Listener
	Beacons   []*models.Beacon
	Results   map[uint32][]*models.Result
	Events    []*models.Event
	Terminals  map[uint32]*models.TerminalState
	ExfilFiles []*models.ExfilEntry
	PrivKey    *rsa.PrivateKey
}

// New creates a Persister rooted at dir (supports ~/ prefix).
// The directory is created with perm 0700 if it does not exist.
func New(dir string) (*Persister, error) {
	if len(dir) >= 2 && dir[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir: %w", err)
		}
		dir = filepath.Join(home, dir[2:])
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create persist dir %s: %w", dir, err)
	}
	return &Persister{dir: dir}, nil
}

// Start launches the background save worker. Must be called before any Save* method.
func (p *Persister) Start() {
	p.ops = make(chan func(), 64)
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		for op := range p.ops {
			op()
		}
	}()
}

// Shutdown drains pending saves and stops the background worker.
func (p *Persister) Shutdown() {
	if p.ops != nil {
		close(p.ops)
		<-p.done
	}
}

func (p *Persister) enqueue(fn func()) {
	if p.ops == nil {
		fn()
		return
	}
	select {
	case p.ops <- fn:
	default:
		fn()
	}
}

// HasSession returns true if a non-empty meta.json exists in the directory.
func (p *Persister) HasSession() bool {
	info, err := os.Stat(filepath.Join(p.dir, "meta.json"))
	return err == nil && info.Size() > 0
}

// ReadMeta reads the meta.json summary for the startup prompt.
func (p *Persister) ReadMeta() (Meta, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.readMetaLocked()
}

// readMetaLocked reads meta.json; caller must hold p.mu.
func (p *Persister) readMetaLocked() (Meta, error) {
	var m Meta
	data, err := os.ReadFile(filepath.Join(p.dir, "meta.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

// Load reads all four state files and returns a Session.
// rsa.pem is required; missing JSON files are treated as empty.
func (p *Persister) Load() (*Session, error) {
	sess := &Session{Results: make(map[uint32][]*models.Result)}

	if data, err := os.ReadFile(filepath.Join(p.dir, "listeners.json")); err == nil {
		if err := json.Unmarshal(data, &sess.Listeners); err != nil {
			return nil, fmt.Errorf("parse listeners.json: %w", err)
		}
	}

	if data, err := os.ReadFile(filepath.Join(p.dir, "beacons.json")); err == nil {
		if err := json.Unmarshal(data, &sess.Beacons); err != nil {
			return nil, fmt.Errorf("parse beacons.json: %w", err)
		}
	}

	if data, err := os.ReadFile(filepath.Join(p.dir, "results.json")); err == nil {
		// JSON only allows string keys; beacon IDs are stored as decimal strings.
		var raw map[string][]*models.Result
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse results.json: %w", err)
		}
		for k, v := range raw {
			var id uint32
			if n, _ := fmt.Sscanf(k, "%d", &id); n != 1 {
				return nil, fmt.Errorf("results.json: invalid beacon ID key %q", k)
			}
			sess.Results[id] = v
		}
	}

	if data, err := os.ReadFile(filepath.Join(p.dir, "terminals.json")); err == nil {
		var raw map[string]*models.TerminalState
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse terminals.json: %w", err)
		}
		sess.Terminals = make(map[uint32]*models.TerminalState, len(raw))
		for k, v := range raw {
			var id uint32
			if n, _ := fmt.Sscanf(k, "%d", &id); n == 1 {
				sess.Terminals[id] = v
			}
		}
	}

	if data, err := os.ReadFile(filepath.Join(p.dir, "loot.json")); err == nil {
		if err := json.Unmarshal(data, &sess.ExfilFiles); err != nil {
			return nil, fmt.Errorf("parse loot.json: %w", err)
		}
	}

	if data, err := os.ReadFile(filepath.Join(p.dir, "events.json")); err == nil {
		if err := json.Unmarshal(data, &sess.Events); err != nil {
			return nil, fmt.Errorf("parse events.json: %w", err)
		}
	}

	data, err := os.ReadFile(filepath.Join(p.dir, "rsa.pem"))
	if err != nil {
		return nil, fmt.Errorf("read rsa.pem: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("rsa.pem: missing or invalid PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rsa key: %w", err)
	}
	sess.PrivKey = key

	return sess, nil
}

// Reset deletes all files in the persist directory.
func (p *Persister) Reset() error {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(p.dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// SaveListeners writes listeners.json then updates meta.json.
func (p *Persister) SaveListeners(ls []*models.Listener) {
	p.enqueue(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := p.writeJSON("listeners.json", ls, 0600); err != nil {
			ui.Errorf("persist", "listeners: %v", err)
			return
		}
		p.saveMetaLocked(len(ls), -1, -1, -1, -1)
	})
}

// SaveBeacons writes beacons.json then updates meta.json.
func (p *Persister) SaveBeacons(bs []*models.Beacon) {
	p.enqueue(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := p.writeJSON("beacons.json", bs, 0600); err != nil {
			ui.Errorf("persist", "beacons: %v", err)
			return
		}
		p.saveMetaLocked(-1, len(bs), -1, -1, -1)
	})
}

// SaveResults writes results.json then updates meta.json.
func (p *Persister) SaveResults(rs map[uint32][]*models.Result) {
	p.enqueue(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		str := make(map[string][]*models.Result, len(rs))
		total := 0
		for k, v := range rs {
			str[fmt.Sprintf("%d", k)] = v
			total += len(v)
		}
		if err := p.writeJSON("results.json", str, 0600); err != nil {
			ui.Errorf("persist", "results: %v", err)
			return
		}
		p.saveMetaLocked(-1, -1, total, -1, -1)
	})
}

// SaveTerminals writes terminals.json.
func (p *Persister) SaveTerminals(ts map[uint32]*models.TerminalState) {
	p.enqueue(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		str := make(map[string]*models.TerminalState, len(ts))
		for k, v := range ts {
			str[fmt.Sprintf("%d", k)] = v
		}
		if err := p.writeJSON("terminals.json", str, 0600); err != nil {
			ui.Errorf("persist", "terminals: %v", err)
			return
		}
		p.saveMetaLocked(-1, -1, -1, -1, len(ts))
	})
}

// SaveLoot writes loot.json.
func (p *Persister) SaveLoot(files []*models.ExfilEntry) {
	p.enqueue(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := p.writeJSON("loot.json", files, 0600); err != nil {
			ui.Errorf("persist", "loot: %v", err)
			return
		}
		p.saveMetaLocked(-1, -1, -1, len(files), -1)
	})
}

// SaveEvents writes events.json.
func (p *Persister) SaveEvents(evts []*models.Event) {
	p.enqueue(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := p.writeJSON("events.json", evts, 0600); err != nil {
			ui.Errorf("persist", "events: %v", err)
		}
	})
}

// SaveRSAKey writes the private key to rsa.pem with perm 0600.
func (p *Persister) SaveRSAKey(key *rsa.PrivateKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := p.writeFile("rsa.pem", data, 0600); err != nil {
		ui.Errorf("persist", "rsa key: %v", err)
	}
}

// saveMetaLocked updates meta.json. Caller must hold p.mu.
func (p *Persister) saveMetaLocked(listeners, beacons, results, loot, terminals int) {
	cur, _ := p.readMetaLocked()
	if listeners >= 0 {
		cur.Listeners = listeners
	}
	if beacons >= 0 {
		cur.Beacons = beacons
	}
	if results >= 0 {
		cur.Results = results
	}
	if loot >= 0 {
		cur.Loot = loot
	}
	if terminals >= 0 {
		cur.Terminals = terminals
	}
	cur.SavedAt = time.Now()
	_ = p.writeJSON("meta.json", cur, 0600)
}

func (p *Persister) writeJSON(name string, v any, perm os.FileMode) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.writeFile(name, data, perm)
}

// writeFile writes to <name>.tmp then renames to <name> for atomicity.
func (p *Persister) writeFile(name string, data []byte, perm os.FileMode) error {
	path := filepath.Join(p.dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
