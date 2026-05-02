#ifndef SHELL_H
#define SHELL_H

#include <stdint.h>

int  shell_start(const char *host, uint16_t port,
                 uint8_t *session_key, uint32_t beacon_id, uint32_t label,
                 int session_sock);
void shell_stop(void);
int  shell_is_active(void);

#endif
