#include "obf.h"

__attribute__((noinline, optimize("O0")))
void xor_dec(char *dst, const uint8_t *enc, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)(enc[i] ^ OBF_KEY[i % OBF_KEY_LEN]);
    }
    dst[len] = '\0';
}
