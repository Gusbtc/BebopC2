#pragma once
#include <stdint.h>

typedef struct {
    int32_t exit_code;
    char *output;
    uint32_t output_len;
} bof_result_t;

int bof_execute(const uint8_t *obj, uint32_t obj_len,
                const uint8_t *args, uint32_t args_len,
                bof_result_t *result);
int bof_execute_packet(const uint8_t *data, uint32_t data_len, bof_result_t *result);
void bof_status_message(int status, char *out, int out_len);
void bof_free_result(bof_result_t *result);
