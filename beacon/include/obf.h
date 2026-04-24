#pragma once
#include <wchar.h>

#define OBF_KEY_LEN 8
#define OBF_KEY     { 0xA3, 0x7F, 0x2C, 0x91, 0xB4, 0x5E, 0xD8, 0x06 }

/* Decrypt narrow string enc[len] into out. Caller must provide len+1 bytes.
   O0 + noinline prevents GCC from constant-folding enc^k at compile time. */
static __attribute__((noinline, optimize("O0"))) void xor_dec(char *out, const unsigned char *enc, int len) {
    static const unsigned char k[] = OBF_KEY;
    for (int i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ k[i % OBF_KEY_LEN]);
    out[len] = '\0';
}

/* Decrypt wide string (UTF-16LE bytes) into out. Caller must provide wlen+1 wchar_t. */
static __attribute__((noinline, optimize("O0"))) void xor_dec_w(wchar_t *out, const unsigned char *enc, int wlen) {
    static const unsigned char k[] = OBF_KEY;
    for (int i = 0; i < wlen; i++) {
        unsigned char lo = enc[2*i]   ^ k[(2*i)   % OBF_KEY_LEN];
        unsigned char hi = enc[2*i+1] ^ k[(2*i+1) % OBF_KEY_LEN];
        out[i] = (wchar_t)((unsigned)lo | ((unsigned)hi << 8));
    }
    out[wlen] = L'\0';
}

/* Compare plain[0..len-1] against XOR-decrypted enc. Returns 1 if equal and plain[len]=='\0'. */
static __attribute__((noinline, optimize("O0"))) int xor_eq(const char *plain, const unsigned char *enc, int len) {
    static const unsigned char k[] = OBF_KEY;
    for (int i = 0; i < len; i++)
        if (plain[i] != (char)(enc[i] ^ k[i % OBF_KEY_LEN])) return 0;
    return plain[len] == '\0';
}

/* Returns 1 if plain starts with XOR-decrypted enc (len bytes). */
static __attribute__((noinline, optimize("O0"))) int xor_prefix(const char *plain, const unsigned char *enc, int len) {
    static const unsigned char k[] = OBF_KEY;
    for (int i = 0; i < len; i++)
        if (plain[i] != (char)(enc[i] ^ k[i % OBF_KEY_LEN])) return 0;
    return 1;
}
