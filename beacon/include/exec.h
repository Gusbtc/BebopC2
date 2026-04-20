#pragma once
#include <windows.h>

/* run_command_direct: runs the command string via CreateProcessA directly,
   WITHOUT a "cmd.exe /c" wrapper. Works for any .exe reachable via PATH.
   Does NOT support shell built-ins (dir, echo, type). Use run_command_shell for those.
   out_buf: caller-allocated; buf_size: capacity. NUL-terminated. Waits 30s max. */
void run_command_direct(const char *cmd, char *out_buf, int buf_size);

/* run_command_shell: wraps cmd in "cmd.exe /c <cmd>".
   Supports shell built-ins, pipelines, redirection.
   Same buffer semantics as run_command_direct. */
void run_command_shell(const char *cmd, char *out_buf, int buf_size);
