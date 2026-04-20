package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
)

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func DecryptMetadata(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

// deriveKey produces a 32-byte sub-key via HMAC-SHA256(master, label).
// Must match beacon's derive_key() in crypto.c.
func deriveKey(master []byte, label string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// Encrypt returns IV(16) + HMAC-SHA256(32) + AES-CBC(plaintext).
// Uses domain-separated sub-keys derived from the session key.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aesKey := deriveKey(key, "aes-cbc")
	hmacKey := deriveKey(key, "hmac-sha256")

	padded := pkcs7Pad(plaintext, aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(ct)
	checksum := mac.Sum(nil)

	out := make([]byte, 16+32+len(ct))
	copy(out[:16], iv)
	copy(out[16:48], checksum)
	copy(out[48:], ct)
	return out, nil
}

// Decrypt verifies HMAC then AES-CBC-decrypts data produced by Encrypt.
// Uses domain-separated sub-keys derived from the session key.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < 48 {
		return nil, errors.New("ciphertext too short")
	}
	aesKey := deriveKey(key, "aes-cbc")
	hmacKey := deriveKey(key, "hmac-sha256")

	iv, checksum, ct := data[:16], data[16:48], data[48:]

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), checksum) {
		return nil, errors.New("HMAC verification failed")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	return pkcs7Unpad(plain)
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty plaintext after decrypt")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(b) {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for i := len(b) - pad; i < len(b); i++ {
		if b[i] != byte(pad) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return b[:len(b)-pad], nil
}
