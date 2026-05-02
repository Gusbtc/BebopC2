#pragma once
#include <windows.h>
#include <stdint.h>

#define EXEC_ASM_TIMEOUT_MS  120000
#define EXEC_ASM_MAX_OUTPUT  65536

int exec_assembly(const uint8_t *shellcode, uint32_t sc_len,
                  const wchar_t *spawnto,
                  char *output, int output_size);
