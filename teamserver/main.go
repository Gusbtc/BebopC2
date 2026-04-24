package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"c2/auth"
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
	sessionPort := flag.Int("session-port", 4443, "TCP port for session mode listener (0 to disable)")
	addOperator := flag.String("add-operator", "", "Add operator user:pass and exit")
	flag.Parse()

	if *addOperator != "" {
		parts := strings.SplitN(*addOperator, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			ui.Error("input", "format: -add-operator user:pass")
			os.Exit(1)
		}
		a, err := auth.New("~/.bebop/operators.db")
		if err != nil {
			ui.Errorf("auth", "%v", err)
			os.Exit(1)
		}
		if err := a.CreateOperator(parts[0], parts[1]); err != nil {
			ui.Errorf("auth", "create operator: %v", err)
			os.Exit(1)
		}
		a.Close()
		ui.Success("operator", fmt.Sprintf("%q created/updated", parts[0]))
		os.Exit(0)
	}

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

	s, err := store.New("~/.bebop/byps.db")
	if err != nil {
		ui.Errorf("store", "open db: %v", err)
		os.Exit(1)
	}
	defer s.Close()
	hub := server.NewHub()
	var toRestart []*models.Listener

	if p.HasSession() {
		meta, err := p.ReadMeta()
		if err != nil {
			ui.Errorf("session", "read meta: %v", err)
			os.Exit(1)
		}

		opCount := 0
		if tmpAuth, err := auth.New("~/.bebop/operators.db"); err == nil {
			opCount, _ = tmpAuth.OperatorCount()
			tmpAuth.Close()
		}
		chatCount := s.ChatMessageCount()

		ui.MenuHeader(fmt.Sprintf("session found (%s)", meta.SavedAt.Format("2006/01/02 15:04")))
		ui.Detail(fmt.Sprintf("%d listeners, %d beacons, %d results, %d loot, %d terminals, %d operators, %d messages",
			meta.Listeners, meta.Beacons, meta.Results, meta.Loot, meta.Terminals, opCount, chatCount))
		ui.Blank()
		ui.MenuItem("L", "load last session")
		ui.MenuItem("R", "reset (fresh start, exfil files deleted)")
		ui.MenuItem("O", "manage operators")
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

				ui.Action("restored", fmt.Sprintf("%d listeners, %d beacons, %d results, %d operators, %d messages",
					meta.Listeners, meta.Beacons, meta.Results, opCount, chatCount))
				ui.Blank()

				s.AddEvent(&models.Event{Type: "sys", Message: "teamserver started (session restored)", Timestamp: time.Now()})
				p.SaveEvents(s.ListEvents())

				authSvc, jwtKey := initAuth(reader)
				sl := startSessionListener(*sessionPort, s, p, hub)
				srv, lm, err := server.Run(*port, *host, s, privKey, *beaconSrc, p, toRestart, sl, hub, authSvc, jwtKey)
				if err != nil {
					ui.Errorf("server", "%v", err)
					os.Exit(1)
				}
				pruneCtx, pruneCancel := context.WithCancel(context.Background())
				s.StartPruner(pruneCtx)
				waitForShutdown(srv, lm, sl, p, pruneCancel, s, authSvc)
				return
			case "R":
				ui.InputPrompt("type 'reset' to confirm")
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
				// clear chat history from SQLite.
				if err := s.ResetChatMessages(); err != nil {
					ui.Errorf("reset", "chat: %v", err)
					os.Exit(1)
				}
				os.RemoveAll("exfil")
				ui.Action("reset", "session cleared, exfil files deleted, chat cleared")
				ui.Blank()
				break choiceLoop
			case "O":
				fmt.Println()
				if a, err := auth.New("~/.bebop/operators.db"); err != nil {
					ui.Errorf("auth", "%v", err)
				} else {
					manageOperators(reader, a)
					a.Close()
				}
				if tmpAuth, err := auth.New("~/.bebop/operators.db"); err == nil {
					opCount, _ = tmpAuth.OperatorCount()
					tmpAuth.Close()
				}
				chatCount = s.ChatMessageCount()
				ui.MenuHeader(fmt.Sprintf("session found (%s)", meta.SavedAt.Format("2006/01/02 15:04")))
				ui.Detail(fmt.Sprintf("%d listeners, %d beacons, %d results, %d loot, %d terminals, %d operators, %d messages",
					meta.Listeners, meta.Beacons, meta.Results, meta.Loot, meta.Terminals, opCount, chatCount))
				ui.Blank()
				ui.MenuItem("L", "load last session")
				ui.MenuItem("R", "reset (fresh start, exfil files deleted)")
				ui.MenuItem("O", "manage operators")
				ui.MenuItem("Q", "quit")
				ui.Prompt("choice")
			case "Q":
				ui.Goodbye()
				os.Exit(0)
			default:
				ui.Error("input", fmt.Sprintf("unknown choice %q — enter L, R, O, or Q", choice))
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
	ui.Blank()

	s.AddEvent(&models.Event{Type: "sys", Message: "teamserver started (fresh)", Timestamp: time.Now()})
	p.SaveEvents(s.ListEvents())

	reader := bufio.NewReader(os.Stdin)
	authSvc, jwtKey := initAuth(reader)
	sl := startSessionListener(*sessionPort, s, p, hub)
	srv, lm, err := server.Run(*port, *host, s, privKey, *beaconSrc, p, nil, sl, hub, authSvc, jwtKey)
	if err != nil {
		ui.Errorf("server", "%v", err)
		os.Exit(1)
	}
	pruneCtx, pruneCancel := context.WithCancel(context.Background())
	s.StartPruner(pruneCtx)
	waitForShutdown(srv, lm, sl, p, pruneCancel, s, authSvc)
}

func initAuth(reader *bufio.Reader) (*auth.Auth, []byte) {
	a, err := auth.New("~/.bebop/operators.db")
	if err != nil {
		ui.Errorf("auth", "%v", err)
		os.Exit(1)
	}
	jwtKey, err := auth.LoadOrCreateJWTKey("~/.bebop/jwt.key")
	if err != nil {
		ui.Errorf("auth", "jwt key: %v", err)
		os.Exit(1)
	}

	count, err := a.OperatorCount()
	if err != nil {
		ui.Errorf("auth", "operator count: %v", err)
		os.Exit(1)
	}

	if count == 0 {
		ui.MenuHeader("first operator setup")
		ui.Divider()
		fmt.Println()

		ui.InputPrompt("username")
		uname, _ := reader.ReadString('\n')
		uname = strings.TrimSpace(uname)
		if uname == "" {
			ui.Error("input", "username cannot be empty")
			os.Exit(1)
		}

		ui.InputPrompt("password")
		passBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			ui.Errorf("input", "read password: %v", err)
			os.Exit(1)
		}
		pass := strings.TrimSpace(string(passBytes))
		if pass == "" {
			ui.Error("input", "password cannot be empty")
			os.Exit(1)
		}

		if err := a.CreateOperator(uname, pass); err != nil {
			ui.Errorf("auth", "create: %v", err)
			os.Exit(1)
		}
		ui.Blank()
		ui.Success("operator", fmt.Sprintf("%q created", uname))
		ui.Blank()
	}
	return a, jwtKey
}

func startSessionListener(port int, s *store.Store, p *persist.Persister, hub *server.Hub) *server.SessionListener {
	if port <= 0 {
		return nil
	}
	sl := server.NewSessionListener(port, s, p, hub, nil)
	if err := sl.Start(); err != nil {
		ui.Errorf("session", "%v", err)
		return nil
	}
	ui.Success("session", fmt.Sprintf("listening on 0.0.0.0:%d", port))
	return sl
}

func waitForShutdown(srv *http.Server, lm *server.ListenerManager, sl *server.SessionListener, p *persist.Persister, pruneCancel context.CancelFunc, s *store.Store, authSvc *auth.Auth) {
	shutdown := func() {
		pruneCancel()
		ui.Action("shutdown", "draining connections...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		if sl != nil {
			sl.Shutdown()
		}
		lm.ShutdownAll()
		if authSvc != nil {
			authSvc.Close()
		}
		p.Shutdown()
		ui.Goodbye()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Signal handler goroutine — triggers shutdown on Ctrl+C, with
	// confirmation if there are active sessions/shells.
	go func() {
		for {
			<-sig
			sessions, shells := s.ActiveSessionCount()
			if sessions > 0 || shells > 0 {
				ui.Blank()
				ui.Error("warning", fmt.Sprintf("%d active session(s), %d active shell(s) will be terminated", sessions, shells))
				ui.Prompt("press Ctrl+C again to confirm shutdown, or wait 10s to cancel")

				select {
				case <-sig:
				case <-time.After(10 * time.Second):
					ui.Success("shutdown", "cancelled — resuming operation")
					continue
				}
			}
			shutdown()
			os.Exit(0)
		}
	}()

	// Main thread: runtime command loop. Reads lines from stdin and
	// dispatches to subcommands (ops, help, quit).
	ui.Info("cmd", "type 'help' for commands, ctrl+c to shutdown")
	ui.CommandPrompt()

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// stdin closed — block forever waiting for signal
			select {}
		}
		cmd := strings.ToLower(strings.TrimSpace(line))
		switch cmd {
		case "":
			// ignore
		case "ops", "operators":
			manageOperators(reader, authSvc)
		case "help", "?":
			printHelp()
		case "quit", "exit":
			shutdown()
			os.Exit(0)
		default:
			ui.Error("cmd", fmt.Sprintf("unknown %q — try 'help'", cmd))
		}
		if cmd != "quit" && cmd != "exit" {
			ui.CommandPrompt()
		}
	}
}

func printHelp() {
	ui.MenuHeader("commands")
	ui.MenuItem("ops", "manage operators (list, add, delete)")
	ui.MenuItem("help", "show this help")
	ui.MenuItem("quit", "shutdown teamserver")
	ui.Blank()
}

func manageOperators(reader *bufio.Reader, a *auth.Auth) {
	for {
		ops, err := a.ListOperators()
		if err != nil {
			ui.Errorf("auth", "list: %v", err)
			return
		}

		ui.MenuHeader(fmt.Sprintf("operators (%d)", len(ops)))
		if len(ops) == 0 {
			ui.Detail("(none)")
		} else {
			for _, u := range ops {
				ui.Detail("• " + u)
			}
		}
		ui.Blank()
		ui.MenuItem("A", "add operator")
		ui.MenuItem("D", "delete operator")
		ui.MenuItem("B", "back")
		ui.Prompt("choice")

		line, _ := reader.ReadString('\n')
		choice := strings.ToUpper(strings.TrimSpace(line))

		switch choice {
		case "A":
			fmt.Println()
			ui.InputPrompt("username")
			uname, _ := reader.ReadString('\n')
			uname = strings.TrimSpace(uname)
			if uname == "" {
				ui.Error("input", "username cannot be empty")
				ui.Blank()
				continue
			}
			ui.InputPrompt("password")
			passBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				ui.Errorf("input", "read password: %v", err)
				continue
			}
			pass := strings.TrimSpace(string(passBytes))
			if pass == "" {
				ui.Error("input", "password cannot be empty")
				ui.Blank()
				continue
			}
			if err := a.CreateOperator(uname, pass); err != nil {
				ui.Errorf("auth", "create: %v", err)
				ui.Blank()
				continue
			}
			ui.Blank()
			ui.Success("operator", fmt.Sprintf("%q created", uname))
			ui.Blank()

		case "D":
			if len(ops) <= 1 {
				ui.Error("auth", "cannot delete last operator")
				ui.Blank()
				continue
			}
			fmt.Println()
			ui.InputPrompt("username to delete")
			uname, _ := reader.ReadString('\n')
			uname = strings.TrimSpace(uname)
			if uname == "" {
				ui.Error("input", "username cannot be empty")
				ui.Blank()
				continue
			}
			if err := a.DeleteOperator(uname); err != nil {
				ui.Errorf("auth", "%v", err)
				ui.Blank()
				continue
			}
			ui.Blank()
			ui.Success("operator", fmt.Sprintf("%q deleted", uname))
			ui.Blank()

		case "B", "":
			fmt.Println()
			return

		default:
			ui.Error("input", fmt.Sprintf("unknown choice %q — enter A, D, or B", choice))
			ui.Blank()
		}
	}
}
