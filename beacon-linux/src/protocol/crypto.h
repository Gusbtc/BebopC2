#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

extern mbedtls_entropy_context g_entropy;
extern mbedtls_ctr_drbg_context g_drbg;

int crypto_init(void);
void crypto_free(void);
int crypto_random(uint8_t *buf, size_t len);
int derive_key(const uint8_t *master, const char *label, uint8_t derived[32]);

int aes_encrypt(const uint8_t session_key[32],
                const uint8_t *plain, size_t plain_len,
                uint8_t *out, size_t *out_len);

int aes_decrypt(const uint8_t session_key[32],
                const uint8_t *data, size_t data_len,
                uint8_t *out, size_t *out_len);

int rsa_encrypt_pubkey(const char *pem,
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *out, size_t *out_len);

#endif
