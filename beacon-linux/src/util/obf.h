#ifndef OBF_H
#define OBF_H

#include <stddef.h>
#include <stdint.h>

#define OBF_KEY_LEN 8

static const uint8_t OBF_KEY[OBF_KEY_LEN] = {
    0xA3, 0x7F, 0x2C, 0x91, 0xB4, 0x5E, 0xD8, 0x06
};

void xor_dec(char *dst, const uint8_t *enc, size_t len);

#endif
