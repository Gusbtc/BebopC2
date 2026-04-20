#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"
#include "../../include/dynapi.h"

int gen_session_key(uint8_t key[32]) {
    NTSTATUS s = fnBCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(s) ? 0 : -1;
}

/* Derive a sub-key via HMAC-SHA256(master, label).
   label must be a null-terminated ASCII string. */
static int derive_key(const uint8_t *master, const char *label,
                      uint8_t derived[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int ret = -1;

    if (!BCRYPT_SUCCESS(fnBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto done;
    if (!BCRYPT_SUCCESS(fnBCryptCreateHash(hAlg, &hHash, NULL, 0,
            (PUCHAR)master, 32, 0)))
        goto done;
    fnBCryptHashData(hHash, (PUCHAR)label, (ULONG)strlen(label), 0);
    if (!BCRYPT_SUCCESS(fnBCryptFinishHash(hHash, derived, 32, 0)))
        goto done;
    ret = 0;

done:
    if (hHash) fnBCryptDestroyHash(hHash);
    if (hAlg)  fnBCryptCloseAlgorithmProvider(hAlg, 0);
    return ret;
}

int aes_encrypt(const uint8_t *key, const uint8_t *plain, DWORD plain_len,
                uint8_t *out, DWORD *out_len) {
    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    BCRYPT_ALG_HANDLE hHmac = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    uint8_t *ct = NULL;
    int ret = -1;

    /* Derive separate sub-keys for AES and HMAC */
    uint8_t aes_key[32], hmac_key[32];
    if (derive_key(key, "aes-cbc", aes_key) != 0) goto cleanup;
    if (derive_key(key, "hmac-sha256", hmac_key) != 0) goto cleanup;

    /* 1. Generate random IV */
    uint8_t iv[16];
    if (!BCRYPT_SUCCESS(fnBCryptGenRandom(NULL, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        goto cleanup;

    /* 2. Open AES-CBC */
    if (!BCRYPT_SUCCESS(fnBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(fnBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(fnBCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, aes_key, 32, 0)))
        goto cleanup;

    /* 3. Get ciphertext size */
    DWORD ct_len = 0;
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (!BCRYPT_SUCCESS(fnBCryptEncrypt(hKey, (PUCHAR)plain, plain_len, NULL,
            iv_copy, 16, NULL, 0, &ct_len, BCRYPT_BLOCK_PADDING)))
        goto cleanup;

    ct = (uint8_t *)malloc(ct_len);
    if (!ct) goto cleanup;

    /* 4. Encrypt */
    memcpy(iv_copy, iv, 16);
    if (!BCRYPT_SUCCESS(fnBCryptEncrypt(hKey, (PUCHAR)plain, plain_len, NULL,
            iv_copy, 16, ct, ct_len, &ct_len, BCRYPT_BLOCK_PADDING)))
        goto cleanup;

    /* 5. HMAC-SHA256 over IV + ciphertext */
    if (!BCRYPT_SUCCESS(fnBCryptOpenAlgorithmProvider(&hHmac, BCRYPT_SHA256_ALGORITHM,
            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(fnBCryptCreateHash(hHmac, &hHash, NULL, 0, hmac_key, 32, 0)))
        goto cleanup;
    fnBCryptHashData(hHash, (PUCHAR)iv, 16, 0);
    fnBCryptHashData(hHash, ct, ct_len, 0);
    uint8_t mac[32];
    if (!BCRYPT_SUCCESS(fnBCryptFinishHash(hHash, mac, 32, 0)))
        goto cleanup;

    /* 6. Build output: IV(16) + HMAC(32) + ciphertext */
    memcpy(out,      iv,  16);
    memcpy(out + 16, mac, 32);
    memcpy(out + 48, ct,  ct_len);
    *out_len = 48 + ct_len;
    ret = 0;

cleanup:
    free(ct);
    if (hHash) fnBCryptDestroyHash(hHash);
    if (hHmac) fnBCryptCloseAlgorithmProvider(hHmac, 0);
    if (hKey)  fnBCryptDestroyKey(hKey);
    if (hAlg)  fnBCryptCloseAlgorithmProvider(hAlg, 0);
    SecureZeroMemory(aes_key, 32);
    SecureZeroMemory(hmac_key, 32);
    SecureZeroMemory(iv_copy, 16);
    return ret;
}

int aes_decrypt(const uint8_t *key, const uint8_t *data, DWORD data_len,
                uint8_t *out, DWORD *out_len) {
    if (data_len < 48) return -1;

    const uint8_t *iv  = data;
    const uint8_t *mac = data + 16;
    const uint8_t *ct  = data + 48;
    DWORD ct_len = data_len - 48;

    /* Derive separate sub-keys */
    uint8_t aes_key[32], hmac_key[32];
    if (derive_key(key, "aes-cbc", aes_key) != 0) return -1;
    if (derive_key(key, "hmac-sha256", hmac_key) != 0) {
        SecureZeroMemory(aes_key, 32);
        return -1;
    }

    /* 1. Verify HMAC first (encrypt-then-MAC) */
    BCRYPT_ALG_HANDLE hHmac = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int ret = -1;

    if (!BCRYPT_SUCCESS(fnBCryptOpenAlgorithmProvider(&hHmac, BCRYPT_SHA256_ALGORITHM,
            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(fnBCryptCreateHash(hHmac, &hHash, NULL, 0, hmac_key, 32, 0)))
        goto cleanup;
    fnBCryptHashData(hHash, (PUCHAR)iv, 16, 0);
    fnBCryptHashData(hHash, (PUCHAR)ct, ct_len, 0);
    uint8_t computed[32];
    if (!BCRYPT_SUCCESS(fnBCryptFinishHash(hHash, computed, 32, 0)))
        goto cleanup;

    /* Constant-time comparison */
    volatile int diff = 0;
    for (int i = 0; i < 32; i++) diff |= (computed[i] ^ mac[i]);
    if (diff != 0) goto cleanup;

    /* 2. AES-CBC decrypt */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (!BCRYPT_SUCCESS(fnBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(fnBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
        goto cleanup_aes;
    if (!BCRYPT_SUCCESS(fnBCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, aes_key, 32, 0)))
        goto cleanup_aes;

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    DWORD plain_len = 0;
    if (!BCRYPT_SUCCESS(fnBCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL, iv_copy, 16,
            NULL, 0, &plain_len, BCRYPT_BLOCK_PADDING)))
        goto cleanup_aes;
    memcpy(iv_copy, iv, 16);
    if (!BCRYPT_SUCCESS(fnBCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL, iv_copy, 16,
            out, plain_len, out_len, BCRYPT_BLOCK_PADDING)))
        goto cleanup_aes;

    ret = 0;

cleanup_aes:
    if (hKey) fnBCryptDestroyKey(hKey);
    if (hAlg) fnBCryptCloseAlgorithmProvider(hAlg, 0);
cleanup:
    if (hHash) fnBCryptDestroyHash(hHash);
    if (hHmac) fnBCryptCloseAlgorithmProvider(hHmac, 0);
    SecureZeroMemory(aes_key, 32);
    SecureZeroMemory(hmac_key, 32);
    SecureZeroMemory(computed, 32);
    SecureZeroMemory(iv_copy, 16);
    return ret;
}

int rsa_encrypt_pubkey(const char *pem, const uint8_t *plain, DWORD plain_len,
                       uint8_t *out, DWORD *out_len) {
    /* 1. PEM -> DER */
    DWORD der_len = 0;
    if (!fnCryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER,
                               NULL, &der_len, NULL, NULL))
        return -1;
    uint8_t *der = (uint8_t *)malloc(der_len);
    if (!der) return -1;
    if (!fnCryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER,
                               der, &der_len, NULL, NULL)) {
        free(der); return -1;
    }

    /* 2. DER -> CERT_PUBLIC_KEY_INFO */
    CERT_PUBLIC_KEY_INFO *pub_info = NULL;
    DWORD pub_info_len = 0;
    if (!fnCryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                              der, der_len, CRYPT_DECODE_ALLOC_FLAG,
                              NULL, &pub_info, &pub_info_len)) {
        free(der); return -1;
    }

    /* 3. Import as BCrypt key */
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!fnCryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pub_info, 0, NULL, &hKey)) {
        fnLocalFree(pub_info); free(der); return -1;
    }

    /* 4. RSA-OAEP-SHA256 encrypt */
    BCRYPT_OAEP_PADDING_INFO oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    ULONG result_len = 0;
    NTSTATUS status = fnBCryptEncrypt(hKey, (PUCHAR)plain, plain_len, &oaep,
                                    NULL, 0, out, *out_len, &result_len,
                                    BCRYPT_PAD_OAEP);
    *out_len = result_len;

    fnBCryptDestroyKey(hKey);
    fnLocalFree(pub_info);
    free(der);
    return BCRYPT_SUCCESS(status) ? 0 : -1;
}
