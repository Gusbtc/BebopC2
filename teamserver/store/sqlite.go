package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS tasks (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	label      INTEGER NOT NULL,
	beacon_id  INTEGER NOT NULL,
	type       INTEGER NOT NULL,
	code       INTEGER NOT NULL DEFAULT 0,
	flags      INTEGER NOT NULL DEFAULT 0,
	identifier INTEGER NOT NULL DEFAULT 0,
	data       BLOB,
	status     TEXT NOT NULL DEFAULT 'PENDING',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tasks_beacon_status ON tasks(beacon_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_label ON tasks(label);

CREATE TABLE IF NOT EXISTS results (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	label       INTEGER NOT NULL,
	beacon_id   INTEGER NOT NULL,
	flags       INTEGER NOT NULL DEFAULT 0,
	type        INTEGER NOT NULL DEFAULT 0,
	filename    TEXT,
	output      TEXT,
	received_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_results_beacon ON results(beacon_id);
CREATE INDEX IF NOT EXISTS idx_results_received ON results(received_at);

CREATE TABLE IF NOT EXISTS chat_messages (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	operator   TEXT NOT NULL,
	message    TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at);
`

func openDB(dbPath string) (*sql.DB, error) {
	if strings.HasPrefix(dbPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir: %w", err)
		}
		dbPath = filepath.Join(home, dbPath[2:])
	}
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	db.SetMaxOpenConns(1)

	return db, nil
}
