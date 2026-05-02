#include <stdlib.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/constant_time.h>
#include "crypto.h"

mbedtls_entropy_context g_entropy;
mbedtls_ctr_drbg_context g_drbg;

int crypto_init(void) {
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    return mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func,
                                  &g_entropy, NULL, 0);
}

void crypto_free(void) {
    mbedtls_ctr_drbg_free(&g_drbg);
    mbedtls_entropy_free(&g_entropy);
}

int crypto_random(uint8_t *buf, size_t len) {
    return mbedtls_ctr_drbg_random(&g_drbg, buf, len);
}

int derive_key(const uint8_t *master, const char *label,
               uint8_t derived[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(md, master, 32,
                           (const uint8_t *)label, strlen(label),
                           derived);
}

static void pkcs7_pad(const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len) {
    size_t pad = 16 - (in_len % 16);
    memcpy(out, in, in_len);
    for (size_t i = 0; i < pad; i++)
        out[in_len + i] = (uint8_t)pad;
    *out_len = in_len + pad;
}

static int pkcs7_unpad(const uint8_t *in, size_t in_len, size_t *out_len) {
    if (in_len == 0) return -1;
    uint8_t pad = in[in_len - 1];
    if (pad == 0 || pad > 16 || pad > in_len) return -1;
    for (size_t i = in_len - pad; i < in_len; i++) {
        if (in[i] != pad) return -1;
    }
    *out_len = in_len - pad;
    return 0;
}

int aes_encrypt(const uint8_t session_key[32],
                const uint8_t *plain, size_t plain_len,
                uint8_t *out, size_t *out_len) {
    uint8_t aes_key[32], hmac_key[32];
    if (derive_key(session_key, "aes-cbc", aes_key) != 0) return -1;
    if (derive_key(session_key, "hmac-sha256", hmac_key) != 0) {
        explicit_bzero(aes_key, 32);
        return -1;
    }

    uint8_t iv[16];
    if (crypto_random(iv, 16) != 0) goto fail;

    size_t padded_len;
    uint8_t *padded = (uint8_t *)malloc(plain_len + 16);
    if (!padded) goto fail;
    pkcs7_pad(plain, plain_len, padded, &padded_len);

    size_t total = 48 + padded_len;
    if (*out_len < total) { free(padded); goto fail; }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_setkey_enc(&aes, aes_key, 256) != 0) {
        free(padded); mbedtls_aes_free(&aes); goto fail;
    }
    uint8_t *ct = out + 48;
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len,
                               iv_copy, padded, ct) != 0) {
        free(padded); mbedtls_aes_free(&aes); goto fail;
    }
    mbedtls_aes_free(&aes);
    free(padded);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t hctx;
    mbedtls_md_init(&hctx);
    mbedtls_md_setup(&hctx, md, 1);
    mbedtls_md_hmac_starts(&hctx, hmac_key, 32);
    mbedtls_md_hmac_update(&hctx, iv, 16);
    mbedtls_md_hmac_update(&hctx, ct, padded_len);
    uint8_t mac[32];
    mbedtls_md_hmac_finish(&hctx, mac);
    mbedtls_md_free(&hctx);

    memcpy(out, iv, 16);
    memcpy(out + 16, mac, 32);
    *out_len = 48 + padded_len;

    explicit_bzero(aes_key, 32);
    explicit_bzero(hmac_key, 32);
    return 0;

fail:
    explicit_bzero(aes_key, 32);
    explicit_bzero(hmac_key, 32);
    return -1;
}

int aes_decrypt(const uint8_t session_key[32],
                const uint8_t *data, size_t data_len,
                uint8_t *out, size_t *out_len) {
    if (data_len < 48) return -1;

    uint8_t aes_key[32], hmac_key[32];
    if (derive_key(session_key, "aes-cbc", aes_key) != 0) return -1;
    if (derive_key(session_key, "hmac-sha256", hmac_key) != 0) {
        explicit_bzero(aes_key, 32);
        return -1;
    }

    const uint8_t *iv  = data;
    const uint8_t *mac = data + 16;
    const uint8_t *ct  = data + 48;
    size_t ct_len = data_len - 48;

    if (ct_len == 0 || ct_len % 16 != 0) goto fail;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t hctx;
    mbedtls_md_init(&hctx);
    mbedtls_md_setup(&hctx, md, 1);
    mbedtls_md_hmac_starts(&hctx, hmac_key, 32);
    mbedtls_md_hmac_update(&hctx, iv, 16);
    mbedtls_md_hmac_update(&hctx, ct, ct_len);
    uint8_t computed[32];
    mbedtls_md_hmac_finish(&hctx, computed);
    mbedtls_md_free(&hctx);

    if (mbedtls_ct_memcmp(computed, mac, 32) != 0) goto fail;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_setkey_dec(&aes, aes_key, 256) != 0) {
        mbedtls_aes_free(&aes); goto fail;
    }
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ct_len,
                               iv_copy, ct, out) != 0) {
        mbedtls_aes_free(&aes); goto fail;
    }
    mbedtls_aes_free(&aes);

    if (pkcs7_unpad(out, ct_len, out_len) != 0) goto fail;

    explicit_bzero(aes_key, 32);
    explicit_bzero(hmac_key, 32);
    explicit_bzero(computed, 32);
    return 0;

fail:
    explicit_bzero(aes_key, 32);
    explicit_bzero(hmac_key, 32);
    explicit_bzero(computed, 32);
    return -1;
}

int rsa_encrypt_pubkey(const char *pem,
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *out, size_t *out_len) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk,
        (const uint8_t *)pem, strlen(pem) + 1);
    if (ret != 0) { mbedtls_pk_free(&pk); return -1; }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    size_t rsa_len = mbedtls_rsa_get_len(rsa);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa,
        mbedtls_ctr_drbg_random, &g_drbg,
        NULL, 0,
        plain_len, plain, out);

    mbedtls_pk_free(&pk);
    if (ret != 0) return -1;

    *out_len = rsa_len;
    return 0;
}
