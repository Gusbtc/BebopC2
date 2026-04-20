package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"c2/models"
	"c2/persist"
	"c2/protocol"
	"c2/server"
	"c2/store"
	"c2/ui"
	"c2/version"
)

func main() {
	port := flag.Int("port", 8080, "HTTP listen port")
	host := flag.String("host", "127.0.0.1", "Public hostname/IP of this server (embedded in beacons)")
	beaconSrc := flag.String("beacon-src", "./beacon", "Path to beacon/ source dir; enables POST /api/build")
	flag.Parse()

	// Resolve beacon-src to absolute path, trying multiple locations
	if abs, err := filepath.Abs(*beaconSrc); err == nil {
		if _, serr := os.Stat(abs); serr == nil {
			*beaconSrc = abs
		} else {
			// Try ../beacon relative to cwd (running from teamserver/)
			if alt, err2 := filepath.Abs("../beacon"); err2 == nil {
				if _, serr2 := os.Stat(alt); serr2 == nil {
					*beaconSrc = alt
				}
			}
		}
	}

	ui.Banner()
	go version.CheckForUpdates()

	p, err := persist.New("~/.bebop")
	if err != nil {
		ui.Errorf("persist", "%v", err)
		os.Exit(1)
	}

	p.Start()

	s := store.New()
	var toRestart []*models.Listener

	if p.HasSession() {
		meta, err := p.ReadMeta()
		if err != nil {
			ui.Errorf("session", "read meta: %v", err)
			os.Exit(1)
		}

		ui.MenuHeader(fmt.Sprintf("session found (%s)", meta.SavedAt.Format("2006/01/02 15:04")))
		ui.Detail(fmt.Sprintf("%d listeners, %d beacons, %d results, %d loot, %d terminals",
			meta.Listeners, meta.Beacons, meta.Results, meta.Loot, meta.Terminals))
		ui.Blank()
		ui.MenuItem("L", "load last session")
		ui.MenuItem("R", "reset (fresh start, exfil files deleted)")
		ui.MenuItem("Q", "quit")
		ui.Prompt("choice")

		reader := bufio.NewReader(os.Stdin)
	choiceLoop:
		for {
			line, _ := reader.ReadString('\n')
			choice := strings.ToUpper(strings.TrimSpace(line))
			if choice == "" {
				choice = "L"
			}
			switch choice {
			case "L":
				fmt.Println()
				session, err := p.Load()
				if err != nil {
					ui.Errorf("session", "load failed: %v", err)
					os.Exit(1)
				}
				s.LoadListeners(session.Listeners)
				s.LoadBeacons(session.Beacons)
				s.LoadResults(session.Results)
				if session.Events != nil {
					s.LoadEvents(session.Events)
				}
				if session.Terminals != nil {
					s.LoadTerminals(session.Terminals)
				}
				if session.ExfilFiles != nil {
					s.LoadLoot(session.ExfilFiles)
				}
				toRestart = append(toRestart, session.Listeners...)

				privKey := session.PrivKey
				pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
				pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

				ui.Action("restored", fmt.Sprintf("%d listeners, %d beacons, %d results",
					meta.Listeners, meta.Beacons, meta.Results))
				fp := strings.ReplaceAll(strings.TrimSpace(string(pubPEM)), "\n", "")
				ui.Action("restoring", "RSA key loaded  "+fp[:60]+"...")
				ui.Action("build", fmt.Sprintf("beacon source: %s", *beaconSrc))
				ui.Blank()

				s.AddEvent(&models.Event{Type: "sys", Message: "teamserver started (session restored)", Timestamp: time.Now()})
				p.SaveEvents(s.ListEvents())

				srv, lm, err := server.Run(*port, *host, s, privKey, *beaconSrc, p, toRestart)
				if err != nil {
					ui.Errorf("server", "%v", err)
					os.Exit(1)
				}
				pruneCtx, pruneCancel := context.WithCancel(context.Background())
				s.StartPruner(pruneCtx)
				waitForShutdown(srv, lm, p, pruneCancel)
				return
			case "R":
				fmt.Printf("      type 'reset' to confirm: ")
				confirm, _ := reader.ReadString('\n')
				if strings.TrimSpace(confirm) != "reset" {
					ui.Error("reset", "aborted")
					ui.Prompt("choice")
					continue choiceLoop
				}
				if err := p.Reset(); err != nil {
					ui.Errorf("reset", "%v", err)
					os.Exit(1)
				}
				os.RemoveAll("exfil")
				ui.Action("reset", "session cleared, exfil files deleted")
				ui.Blank()
				break choiceLoop
			case "Q":
				ui.Goodbye()
				os.Exit(0)
			default:
				ui.Error("input", fmt.Sprintf("unknown choice %q — enter L, R, or Q", choice))
				ui.Prompt("choice")
			}
		}
	}

	privKey, err := protocol.GenerateRSAKey()
	if err != nil {
		ui.Errorf("crypto", "RSA keygen failed: %v", err)
		os.Exit(1)
	}
	p.SaveRSAKey(privKey)

	pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	fp := strings.ReplaceAll(strings.TrimSpace(string(pubPEM)), "\n", "")
	ui.Action("crypto", "RSA-2048 key generated  "+fp[:60]+"...")
	ui.Action("build", fmt.Sprintf("beacon source: %s", *beaconSrc))
	ui.Blank()

	s.AddEvent(&models.Event{Type: "sys", Message: "teamserver started (fresh)", Timestamp: time.Now()})
	p.SaveEvents(s.ListEvents())

	srv, lm, err := server.Run(*port, *host, s, privKey, *beaconSrc, p, nil)
	if err != nil {
		ui.Errorf("server", "%v", err)
		os.Exit(1)
	}
	pruneCtx, pruneCancel := context.WithCancel(context.Background())
	s.StartPruner(pruneCtx)
	waitForShutdown(srv, lm, p, pruneCancel)
}

func waitForShutdown(srv *http.Server, lm *server.ListenerManager, p *persist.Persister, pruneCancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	pruneCancel()
	ui.Action("shutdown", "draining connections...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	lm.ShutdownAll()
	p.Shutdown()
	ui.Goodbye()
}
