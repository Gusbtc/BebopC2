#pragma once
#include <windows.h>
#include <stdint.h>

/* gen_session_key: fills key[32] with 32 cryptographically random bytes.
   Returns 0 on success, -1 on failure. */
int gen_session_key(uint8_t key[32]);

/* aes_encrypt: AES-CBC + HMAC-SHA256 encrypt.
   Output format: IV(16) + HMAC-SHA256(32) + AES-CBC(PKCS7(plain)).
   out must be at least plain_len + 64 bytes.
   Returns 0 on success, -1 on failure. */
int aes_encrypt(const uint8_t *key, const uint8_t *plain, DWORD plain_len,
                uint8_t *out, DWORD *out_len);

/* aes_decrypt: verifies HMAC-SHA256, then AES-CBC decrypts data from aes_encrypt.
   Returns 0 on success, -1 on HMAC mismatch or decryption error. */
int aes_decrypt(const uint8_t *key, const uint8_t *data, DWORD data_len,
                uint8_t *out, DWORD *out_len);

/* rsa_encrypt_pubkey: RSA-OAEP-SHA256 encrypt using PEM public key (SubjectPublicKeyInfo).
   pem: full PEM string including -----BEGIN/END PUBLIC KEY----- headers.
   out must be at least 256 bytes (RSA-2048 produces 256 bytes of ciphertext).
   *out_len must be initialized to the size of out before calling.
   Returns 0 on success, -1 on failure. */
int rsa_encrypt_pubkey(const char *pem, const uint8_t *plain, DWORD plain_len,
                       uint8_t *out, DWORD *out_len);
