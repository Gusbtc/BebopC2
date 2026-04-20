package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
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
	version = "1.1.0"
	repoAPI = "https://api.github.com/repos/Gusbtc/Bepop-Framework/releases/latest"
)

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
	flag.Parse()

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
	mux.HandleFunc("GET /interact/{id}", servePage("static/pages/interact.html"))
	mux.HandleFunc("GET /build", servePage("static/pages/build.html"))
	mux.HandleFunc("GET /loot", servePage("static/pages/loot.html"))

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		fmt.Fprintf(os.Stderr, "   \033[38;5;203m!! static     %v%s\n", err, reset)
		os.Exit(1)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	addr := fmt.Sprintf(":%d", *port)
	fmt.Fprintf(os.Stdout, "   %s>>%s %s   connected%s   http://localhost%s                %s[ok]%s\n",
		amber, reset, amber, reset, addr, green, reset)
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
		w.Write(data)
	}
}
