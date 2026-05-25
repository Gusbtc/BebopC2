package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	amber   = "\033[38;5;214m"
	gray    = "\033[3;38;5;245m"
	green   = "\033[38;5;77m"
	bold    = "\033[1m"
	reset   = "\033[0m"
	version = "1.5.0"
	repoAPI = "https://api.github.com/repos/Gusbtc/BebopC2/releases/latest"

	proxyMaxBodyBytes int64 = 256 << 20
)

var proxyTargetOrigin *url.URL

func checkForUpdates() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(repoAPI)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if json.NewDecoder(resp.Body).Decode(&rel) != nil {
		return
	}
	remote := strings.TrimPrefix(rel.TagName, "v")
	if remote != "" && remote != version {
		fmt.Fprintf(os.Stdout, "   %s>>%s %supdate%s   %s available (current: %s)\n", amber, reset, amber, reset, remote, version)
		fmt.Fprintf(os.Stdout, "   %s>>%s           %s\n\n", amber, reset, rel.HTMLURL)
	}
}

//go:embed static
var assets embed.FS

func main() {
	port := flag.Int("port", 9090, "Operator client listen port")
	host := flag.String("host", "127.0.0.1", "Operator client bind host")
	proxyTarget := flag.String("teamserver", "http://127.0.0.1:8080", "Allowed teamserver URL for proxy fallback")
	flag.Parse()

	var err error
	proxyTargetOrigin, err = parseProxyOrigin(*proxyTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   \033[38;5;203m!! proxy     %v%s\n", err, reset)
		os.Exit(1)
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Fprintf(os.Stdout, "\n   %s\"See you, space cowboy...\"%s\n\n", amber, reset)
		os.Exit(0)
	}()

	fmt.Fprintf(os.Stdout, "\n   %s%sBEBOP // OPERATOR CLIENT%s\n", amber, bold, reset)
	fmt.Fprintf(os.Stdout, "   %s\"You're gonna carry that weight.\"%s\n\n", gray, reset)
	go checkForUpdates()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/sessions", http.StatusFound)
	})
	mux.HandleFunc("GET /sessions", servePage("static/pages/index.html"))
	mux.HandleFunc("GET /listeners", servePage("static/pages/listeners.html"))
	mux.HandleFunc("GET /build", servePage("static/pages/build.html"))
	mux.HandleFunc("GET /mcp", servePage("static/pages/mcp.html"))
	mux.HandleFunc("GET /login", servePage("static/pages/login.html"))
	mux.HandleFunc("/api/proxy", proxyTeamserver)

	mime.AddExtensionType(".woff2", "font/woff2")
	mime.AddExtensionType(".woff", "font/woff")

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		fmt.Fprintf(os.Stderr, "   \033[38;5;203m!! static     %v%s\n", err, reset)
		os.Exit(1)
	}
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))
	mux.Handle("GET /static/", noStore(staticHandler))

	addr := fmt.Sprintf("%s:%d", *host, *port)
	displayHost := *host
	if displayHost == "127.0.0.1" || displayHost == "" {
		displayHost = "localhost"
	}
	fmt.Fprintf(os.Stdout, "   %s>>%s %s   connected%s   http://%s:%d                %s[ok]%s\n",
		amber, reset, amber, reset, displayHost, *port, green, reset)
	fmt.Fprintf(os.Stdout, "   %s>>%s %s       ready%s   waiting for tasks\n\n",
		amber, reset, amber, reset)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "   \033[38;5;203m!!      error   %v%s\n", err, reset)
		os.Exit(1)
	}
}

func servePage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := assets.ReadFile(path)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		w.Write(data)
	}
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		next.ServeHTTP(w, r)
	})
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func parseProxyOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("bad teamserver proxy target")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func proxyTeamserver(w http.ResponseWriter, r *http.Request) {
	if authz := r.Header.Get("Authorization"); !strings.HasPrefix(authz, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !proxyMethodAllowed(r.Method) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	targetRaw := r.URL.Query().Get("url")
	targetURL, err := url.Parse(targetRaw)
	if err != nil || targetURL == nil || targetURL.Host == "" ||
		(targetURL.Scheme != "http" && targetURL.Scheme != "https") ||
		!proxyTargetAllowed(targetURL) ||
		!strings.HasPrefix(targetURL.EscapedPath(), "/api/") {
		http.Error(w, "bad proxy target", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, proxyMaxBodyBytes+1))
	if err != nil {
		http.Error(w, "proxy read failed", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > proxyMaxBodyBytes {
		http.Error(w, "proxy body too large", http.StatusRequestEntityTooLarge)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "proxy request failed", http.StatusBadRequest)
		return
	}
	copyProxyHeader(req.Header, r.Header, "Authorization")
	copyProxyHeader(req.Header, r.Header, "Content-Type")
	copyProxyHeader(req.Header, r.Header, "Accept")

	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "teamserver unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func proxyTargetAllowed(target *url.URL) bool {
	if proxyTargetOrigin == nil || target == nil {
		return false
	}
	return strings.EqualFold(target.Scheme, proxyTargetOrigin.Scheme) &&
		strings.EqualFold(target.Host, proxyTargetOrigin.Host)
}

func proxyMethodAllowed(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func copyProxyHeader(dst, src http.Header, name string) {
	if v := src.Get(name); v != "" {
		dst.Set(name, v)
	}
}
