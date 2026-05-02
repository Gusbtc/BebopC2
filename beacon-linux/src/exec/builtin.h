#ifndef BUILTIN_H
#define BUILTIN_H

/*
 * builtin_dispatch - check if cmd is a known builtin; if so, execute it and
 * write output into out_buf (NUL-terminated, max buf_size bytes).
 *
 * Returns 1 if handled, 0 if not a builtin (caller should fall through to
 * exec_command / shell execution).
 */
int builtin_dispatch(const char *cmd, char *out_buf, int buf_size);

#endif /* BUILTIN_H */
