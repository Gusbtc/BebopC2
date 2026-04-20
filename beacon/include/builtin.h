#pragma once
#include <windows.h>

/* builtin_dispatch: handles built-in WinAPI commands without spawning any child process.
   Returns 1 if the command was recognized and output was written to out_buf.
   Returns 0 if the command is not a built-in — caller should fall through to exec.
   out_buf must be caller-allocated with at least buf_size bytes. */
int builtin_dispatch(const char *cmd, char *out_buf, int buf_size);
