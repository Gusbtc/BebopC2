package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func tempDB(t *testing.T) *Auth {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "operators.db")
	a, err := New(dbPath)
	if err != nil {
		t.Fatalf("New(%q): %v", dbPath, err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestCreateAndValidate(t *testing.T) {
	a := tempDB(t)
	if err := a.CreateOperator("admin", "secret123"); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	if !a.ValidatePassword("admin", "secret123") {
		t.Fatal("ValidatePassword returned false for correct password")
	}
	if a.ValidatePassword("admin", "wrong") {
		t.Fatal("ValidatePassword returned true for wrong password")
	}
	if a.ValidatePassword("noexist", "secret123") {
		t.Fatal("ValidatePassword returned true for nonexistent user")
	}
}

func TestCreateDuplicateUpdatesPassword(t *testing.T) {
	a := tempDB(t)
	if err := a.CreateOperator("admin", "pass1"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if err := a.CreateOperator("admin", "pass2"); err != nil {
		t.Fatalf("second create: %v", err)
	}
	if a.ValidatePassword("admin", "pass1") {
		t.Fatal("old password still works after update")
	}
	if !a.ValidatePassword("admin", "pass2") {
		t.Fatal("new password does not work after update")
	}
}

func TestOperatorCount(t *testing.T) {
	a := tempDB(t)
	n, err := a.OperatorCount()
	if err != nil {
		t.Fatalf("OperatorCount: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
	a.CreateOperator("op1", "pass")
	a.CreateOperator("op2", "pass")
	n, err = a.OperatorCount()
	if err != nil {
		t.Fatalf("OperatorCount: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
}

func TestJWTKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")

	key1, err := LoadOrCreateJWTKey(keyPath)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key1))
	}

	key2, err := LoadOrCreateJWTKey(keyPath)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("key changed between loads")
	}
}

func TestSignAndValidateToken(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	key, _ := LoadOrCreateJWTKey(keyPath)

	token, err := SignToken("admin", key)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	username, err := ValidateToken(token, key)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if username != "admin" {
		t.Fatalf("expected admin, got %s", username)
	}
}

func TestValidateTokenInvalid(t *testing.T) {
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := ValidateToken("garbage.token.here", key)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestDBPathExpandsHome(t *testing.T) {
	dir := t.TempDir()
	a, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.Close()

	if _, err := os.Stat(filepath.Join(dir, "test.db")); err != nil {
		t.Fatalf("db file not created: %v", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	key, _ := LoadOrCreateJWTKey(keyPath)

	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := ValidateToken(signed, key); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	for i := range keyA {
		keyA[i] = 0x11
		keyB[i] = 0x22
	}
	token, err := SignToken("admin", keyA)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ValidateToken(token, keyB); err == nil {
		t.Fatal("expected error when validating with wrong key")
	}
}

func TestWrongAlgorithmRejected(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x33
	}
	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ValidateToken(signed, key); err == nil {
		t.Fatal("expected error for HS512 token when HS256 is required")
	}
}

func TestListOperators(t *testing.T) {
	a := tempDB(t)
	ops, err := a.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	if len(ops) != 0 {
		t.Fatalf("expected 0 operators, got %d", len(ops))
	}

	a.CreateOperator("zoe", "pass")
	a.CreateOperator("alice", "pass")
	a.CreateOperator("bob", "pass")

	ops, err = a.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("expected 3 operators, got %d", len(ops))
	}
	expected := []string{"alice", "bob", "zoe"}
	for i, u := range expected {
		if ops[i] != u {
			t.Fatalf("expected ops[%d]=%q, got %q", i, u, ops[i])
		}
	}
}

func TestDeleteOperator(t *testing.T) {
	a := tempDB(t)
	a.CreateOperator("alice", "pass")
	a.CreateOperator("bob", "pass")

	if err := a.DeleteOperator("alice"); err != nil {
		t.Fatalf("DeleteOperator: %v", err)
	}
	if a.ValidatePassword("alice", "pass") {
		t.Fatal("deleted operator still validates")
	}
	if !a.ValidatePassword("bob", "pass") {
		t.Fatal("non-deleted operator stopped validating")
	}
}

func TestDeleteOperatorNotFound(t *testing.T) {
	a := tempDB(t)
	if err := a.DeleteOperator("ghost"); err == nil {
		t.Fatal("expected error when deleting nonexistent operator")
	}
}
