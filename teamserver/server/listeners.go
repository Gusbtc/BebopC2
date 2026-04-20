package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"c2/models"
)

// listenerStarter is the interface the Handler uses to start/stop listeners.
// The real implementation is ListenerManager; tests use noopLM.
type listenerStarter interface {
	Start(l *models.Listener, handler http.Handler) error
	Stop(id uint32) error
}

// ListenerManager owns the running *http.Server instances keyed by listener ID.
type ListenerManager struct {
	mu      sync.Mutex
	servers map[uint32]*http.Server
}

func NewListenerManager() *ListenerManager {
	return &ListenerManager{servers: make(map[uint32]*http.Server)}
}

type ctxKey string

const listenerIDKey ctxKey = "listener_id"

// listenerContextMiddleware injects the listener ID into the request context.
func listenerContextMiddleware(id uint32, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), listenerIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Start launches an http.Server for l.
func (lm *ListenerManager) Start(l *models.Listener, handler http.Handler) error {
	if l.Scheme == "https" && len(l.CertPEM) == 0 {
		cert, key, err := generateSelfSignedCert(l.Host)
		if err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
		l.CertPEM = cert
		l.KeyPEM = key
		l.AutoCert = true
	}

	// Wrap with both custom headers and listener ID context
	wrapped := customHeadersMiddleware(l.CustomHeaders, handler)
	wrapped = listenerContextMiddleware(l.ID, wrapped)

	bindAddr := l.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", bindAddr, l.Port)

	// Probe the port synchronously so errors surface in the HTTP response.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind %s: %w", addr, err)
	}

	srv := &http.Server{Addr: addr, Handler: wrapped}

	if l.Scheme == "https" {
		tlsCert, err := tls.X509KeyPair(l.CertPEM, l.KeyPEM)
		if err != nil {
			ln.Close()
			return fmt.Errorf("parse TLS keypair: %w", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
		lm.mu.Lock()
		lm.servers[l.ID] = srv
		lm.mu.Unlock()
		go srv.ServeTLS(ln, "", "")
	} else {
		lm.mu.Lock()
		lm.servers[l.ID] = srv
		lm.mu.Unlock()
		go srv.Serve(ln)
	}
	return nil
}

// Stop gracefully shuts down the listener within 5 seconds.
func (lm *ListenerManager) Stop(id uint32) error {
	lm.mu.Lock()
	srv, ok := lm.servers[id]
	if ok {
		delete(lm.servers, id)
	}
	lm.mu.Unlock()

	if !ok {
		return fmt.Errorf("listener %d not running", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// ShutdownAll gracefully shuts down every running listener.
func (lm *ListenerManager) ShutdownAll() {
	lm.mu.Lock()
	ids := make([]uint32, 0, len(lm.servers))
	for id := range lm.servers {
		ids = append(ids, id)
	}
	lm.mu.Unlock()
	for _, id := range ids {
		lm.Stop(id)
	}
}

// generateSelfSignedCert creates an ECDSA P-256 self-signed cert valid for 10 years.
// host is used as the cert's CN and SAN (IP or DNS).
func generateSelfSignedCert(host string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	return certPEM, keyPEM, nil
}

// customHeadersMiddleware injects the given headers into every HTTP response.
func customHeadersMiddleware(headers map[string]string, next http.Handler) http.Handler {
	if len(headers) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}
