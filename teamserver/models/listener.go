package models

// Listener represents a running (or stopped) HTTP/HTTPS endpoint
// that beacons connect to.
type Listener struct {
	ID            uint32
	Name          string            // operator-defined label
	Scheme        string            // "http" | "https"
	Host          string            // public hostname/IP embedded in beacons + cert SAN
	BindAddr      string            // local bind address, e.g. "0.0.0.0"
	Port          int
	CertPEM       []byte            // nil until Start; populated by auto-gen or operator
	KeyPEM        []byte
	CustomHeaders map[string]string // injected into every response (malleable C2)
	IsDefault     bool              // default listener cannot be deleted
	AutoCert      bool              // true if cert was auto-generated (drives IGNORE_CERT_ERRORS)
}
