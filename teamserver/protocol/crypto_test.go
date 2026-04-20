package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func encryptWithPub(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("hello BypsC2 protocol test")

	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// IV(16) + HMAC(32) + ciphertext(>=16)
	if len(ct) < 64 {
		t.Fatalf("ciphertext too short: %d", len(ct))
	}

	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestDecrypt_InvalidHMAC(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ct, _ := Encrypt(key, []byte("data"))
	ct[20] ^= 0xFF // corrupt a byte inside the HMAC field

	_, err := Decrypt(key, ct)
	if err == nil {
		t.Fatal("expected HMAC error, got nil")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := Decrypt(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error on short input")
	}
}

func TestGenerateRSAKey(t *testing.T) {
	priv, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit key, got %d", priv.N.BitLen())
	}
}

func TestDecryptMetadata_RoundTrip(t *testing.T) {
	priv, _ := GenerateRSAKey()
	msg := []byte("implant metadata payload")

	ct, err := encryptWithPub(&priv.PublicKey, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptMetadata(priv, ct)
	if err != nil {
		t.Fatalf("DecryptMetadata: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("expected %q, got %q", msg, got)
	}
}
