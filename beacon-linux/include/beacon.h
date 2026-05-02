#ifndef BEACON_H
#define BEACON_H

#include <stdint.h>

#define MAX_CMD_OUTPUT  (512 * 1024)
#define CMD_TIMEOUT_SEC 30
#define REG_RETRIES     3
#define REG_RETRY_SEC   5
#define RECV_TIMEOUT_SEC 10
#define MAX_RESP_SIZE   (2 * 1024 * 1024)
#define MAX_ENVELOPE        (10 * 1024 * 1024)
#define SHELL_COLS          120
#define SHELL_ROWS          30

#endif
