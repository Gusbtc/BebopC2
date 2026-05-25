package store

import (
	"database/sql"
	"fmt"
	"net/url"
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
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	label          INTEGER NOT NULL,
	beacon_id      INTEGER NOT NULL,
	flags          INTEGER NOT NULL DEFAULT 0,
	type           INTEGER NOT NULL DEFAULT 0,
	filename       TEXT,
	output         TEXT,
	exit_code      INTEGER NOT NULL DEFAULT 0,
	stdout         TEXT NOT NULL DEFAULT '',
	stderr         TEXT NOT NULL DEFAULT '',
	exception      TEXT NOT NULL DEFAULT '',
	duration_ms    INTEGER NOT NULL DEFAULT 0,
	truncated      INTEGER NOT NULL DEFAULT 0,
	mode           TEXT NOT NULL DEFAULT '',
	bridge_version TEXT NOT NULL DEFAULT '',
	diagnostics    TEXT NOT NULL DEFAULT '',
	received_at    DATETIME DEFAULT CURRENT_TIMESTAMP
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

var resultColumnMigrations = []struct {
	name string
	stmt string
}{
	{name: "exit_code", stmt: `ALTER TABLE results ADD COLUMN exit_code INTEGER NOT NULL DEFAULT 0`},
	{name: "stdout", stmt: `ALTER TABLE results ADD COLUMN stdout TEXT NOT NULL DEFAULT ''`},
	{name: "stderr", stmt: `ALTER TABLE results ADD COLUMN stderr TEXT NOT NULL DEFAULT ''`},
	{name: "exception", stmt: `ALTER TABLE results ADD COLUMN exception TEXT NOT NULL DEFAULT ''`},
	{name: "duration_ms", stmt: `ALTER TABLE results ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0`},
	{name: "truncated", stmt: `ALTER TABLE results ADD COLUMN truncated INTEGER NOT NULL DEFAULT 0`},
	{name: "mode", stmt: `ALTER TABLE results ADD COLUMN mode TEXT NOT NULL DEFAULT ''`},
	{name: "bridge_version", stmt: `ALTER TABLE results ADD COLUMN bridge_version TEXT NOT NULL DEFAULT ''`},
	{name: "diagnostics", stmt: `ALTER TABLE results ADD COLUMN diagnostics TEXT NOT NULL DEFAULT ''`},
}

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

	dbURL := url.URL{Scheme: "file", Path: dbPath}
	q := dbURL.Query()
	q.Set("_journal_mode", "WAL")
	q.Set("_busy_timeout", "5000")
	q.Set("_foreign_keys", "ON")
	dbURL.RawQuery = q.Encode()
	dsn := dbURL.String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := migrateResultColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate result schema: %w", err)
	}

	db.SetMaxOpenConns(1)

	return db, nil
}

func migrateResultColumns(db *sql.DB) error {
	existing, err := getTableColumns(db, "results")
	if err != nil {
		return err
	}
	for _, migration := range resultColumnMigrations {
		if existing[migration.name] {
			continue
		}
		if _, err := db.Exec(migration.stmt); err != nil {
			if isDuplicateColumnError(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate column name")
}

func getTableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return columns, nil
}
