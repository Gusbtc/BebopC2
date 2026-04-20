package persist_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"c2/models"
	"c2/persist"
)

func newP(t *testing.T) *persist.Persister {
	t.Helper()
	p, err := persist.New(t.TempDir())
	if err != nil {
		t.Fatalf("persist.New: %v", err)
	}
	return p
}

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func TestHasSession_FalseWhenEmpty(t *testing.T) {
	p := newP(t)
	if p.HasSession() {
		t.Fatal("expected HasSession=false on fresh dir")
	}
}

func TestHasSession_TrueAfterSave(t *testing.T) {
	p := newP(t)
	p.SaveRSAKey(genKey(t))
	p.SaveListeners([]*models.Listener{})
	if !p.HasSession() {
		t.Fatal("expected HasSession=true after SaveListeners")
	}
}

func TestSaveAndLoadListeners(t *testing.T) {
	p := newP(t)
	p.SaveRSAKey(genKey(t))

	ls := []*models.Listener{
		{ID: 1, Name: "default", Scheme: "http", Host: "127.0.0.1", Port: 8080, IsDefault: true},
		{ID: 2, Name: "tls", Scheme: "https", Host: "10.0.0.1", Port: 4433,
			CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"), AutoCert: true,
			CustomHeaders: map[string]string{"X-Hdr": "val"}},
	}
	p.SaveListeners(ls)

	sess, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(sess.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(sess.Listeners))
	}
	got := sess.Listeners[1]
	if got.Name != "tls" || got.Port != 4433 {
		t.Errorf("listener mismatch: %+v", got)
	}
	if string(got.CertPEM) != "CERT" {
		t.Errorf("CertPEM not preserved: %q", got.CertPEM)
	}
	if got.CustomHeaders["X-Hdr"] != "val" {
		t.Errorf("CustomHeaders not preserved: %v", got.CustomHeaders)
	}
}

func TestSaveAndLoadBeacons(t *testing.T) {
	p := newP(t)
	p.SaveRSAKey(genKey(t))

	now := time.Now().Truncate(time.Second)
	bs := []*models.Beacon{
		{
			ImplantMetadata: models.ImplantMetadata{
				ID: 42, SessionKey: []byte("01234567890123456789012345678901"),
				Sleep: 5000, Jitter: 20, Hostname: "WIN-TARGET",
			},
			FirstSeen: now, LastSeen: now,
		},
	}
	p.SaveBeacons(bs)

	sess, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(sess.Beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(sess.Beacons))
	}
	b := sess.Beacons[0]
	if b.ID != 42 || b.Hostname != "WIN-TARGET" {
		t.Errorf("beacon mismatch: %+v", b)
	}
	if string(b.SessionKey) != "01234567890123456789012345678901" {
		t.Errorf("SessionKey not preserved")
	}
}

func TestSaveAndLoadResults(t *testing.T) {
	p := newP(t)
	p.SaveRSAKey(genKey(t))

	now := time.Now().Truncate(time.Second)
	rs := map[uint32][]*models.Result{
		99: {{Label: 1, BeaconID: 99, Output: "hello", ReceivedAt: now}},
	}
	p.SaveResults(rs)

	sess, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(sess.Results[99]) != 1 {
		t.Fatalf("expected 1 result for beacon 99")
	}
	if sess.Results[99][0].Output != "hello" {
		t.Errorf("output not preserved: %q", sess.Results[99][0].Output)
	}
}

func TestSaveAndLoadRSAKey(t *testing.T) {
	p := newP(t)
	key := genKey(t)
	p.SaveRSAKey(key)

	sess, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if sess.PrivKey == nil {
		t.Fatal("PrivKey is nil after Load")
	}
	if sess.PrivKey.PublicKey.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("loaded RSA key does not match saved key")
	}
}

func TestReset(t *testing.T) {
	p := newP(t)
	p.SaveRSAKey(genKey(t))
	p.SaveListeners([]*models.Listener{})

	if err := p.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if p.HasSession() {
		t.Fatal("expected HasSession=false after Reset")
	}
}

func TestReadMeta(t *testing.T) {
	p := newP(t)
	p.SaveRSAKey(genKey(t))
	p.SaveListeners([]*models.Listener{
		{ID: 1, Name: "x", Scheme: "http", Host: "h", Port: 80},
	})

	m, err := p.ReadMeta()
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if m.Listeners != 1 {
		t.Errorf("expected 1 in meta.Listeners, got %d", m.Listeners)
	}
	if m.SavedAt.IsZero() {
		t.Error("SavedAt is zero")
	}
}
