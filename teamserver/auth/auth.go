package auth

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	blacklistMu sync.RWMutex
	blacklist   = make(map[string]time.Time) // token -> expiry
)

func RevokeToken(tokenStr string, key []byte) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation())
	var exp time.Time
	if err == nil {
		if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		}
	}
	if exp.IsZero() {
		exp = time.Now().Add(24 * time.Hour)
	}
	blacklistMu.Lock()
	blacklist[tokenStr] = exp
	blacklistMu.Unlock()
}

func IsRevoked(tokenStr string) bool {
	blacklistMu.RLock()
	_, ok := blacklist[tokenStr]
	blacklistMu.RUnlock()
	return ok
}

func PurgeExpiredTokens() {
	blacklistMu.Lock()
	now := time.Now()
	for tok, exp := range blacklist {
		if now.After(exp) {
			delete(blacklist, tok)
		}
	}
	blacklistMu.Unlock()
}

const schema = `
CREATE TABLE IF NOT EXISTS operators (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created  DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

type Auth struct {
	db *sql.DB
}

func New(dbPath string) (*Auth, error) {
	if strings.HasPrefix(dbPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home: %w", err)
		}
		dbPath = filepath.Join(home, dbPath[2:])
	}
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &Auth{db: db}, nil
}

func (a *Auth) Close() error {
	return a.db.Close()
}

func (a *Auth) CreateOperator(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = a.db.Exec(`
		INSERT INTO operators (username, password) VALUES (?, ?)
		ON CONFLICT(username) DO UPDATE SET password = excluded.password
	`, username, string(hash))
	return err
}

var dummyHash []byte

func init() {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy"), 12)
	dummyHash = h
}

func (a *Auth) ValidatePassword(username, password string) bool {
	var hash string
	err := a.db.QueryRow("SELECT password FROM operators WHERE username = ?", username).Scan(&hash)
	if err != nil {
		// Equalize timing with a dummy bcrypt compare so attackers can't
		// distinguish "no such user" from "wrong password" by response time.
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (a *Auth) OperatorCount() (int, error) {
	var count int
	err := a.db.QueryRow("SELECT COUNT(*) FROM operators").Scan(&count)
	return count, err
}

func (a *Auth) ListOperators() ([]string, error) {
	rows, err := a.db.Query("SELECT username FROM operators ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (a *Auth) DeleteOperator(username string) error {
	res, err := a.db.Exec("DELETE FROM operators WHERE username = ?", username)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("operator %q not found", username)
	}
	return nil
}

func LoadOrCreateJWTKey(path string) ([]byte, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, path[2:])
	}

	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return key, nil
}

func SignToken(username string, key []byte) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   username,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func ValidateToken(tokenStr string, key []byte) (string, error) {
	if IsRevoked(tokenStr) {
		return "", fmt.Errorf("token revoked")
	}
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	return claims.Subject, nil
}
