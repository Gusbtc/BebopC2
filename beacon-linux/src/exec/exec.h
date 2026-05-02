#ifndef EXEC_H
#define EXEC_H

#include <stddef.h>

/* Direct execution via execvp (no shell) — splits cmd on spaces */
char *exec_command(const char *cmd, size_t *out_len);

/* Shell execution via /bin/sh -c <cmd> */
char *exec_command_shell(const char *cmd, size_t *out_len);

#endif
