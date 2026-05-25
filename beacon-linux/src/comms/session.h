#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stddef.h>

int  session_connect(const char *host, uint16_t port);
int  session_write(int sock, const uint8_t *data, int len);
int  session_read(int sock, uint8_t *out, int *out_len);
int  safe_session_write(int sock, const uint8_t *data, int len);

void session_loop(int sock, uint8_t *session_key, uint32_t beacon_id,
                  uint32_t *sleep_sec, uint32_t *jitter_pct);

int  send_result_session(int sock, uint32_t label, uint8_t type, uint8_t code,
                         uint16_t flags, const char *output,
                         const uint8_t session_key[32]);

int  send_result_session_len(int sock, uint32_t label, uint8_t type, uint8_t code,
                             uint16_t flags, const char *output, size_t output_len,
                             const uint8_t session_key[32]);

int  send_result_raw_session(int sock, uint32_t label, uint8_t type,
                             uint16_t flags, uint32_t identifier,
                             const uint8_t *data, uint32_t data_len,
                             const uint8_t session_key[32]);

#endif
