#pragma once
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <windns.h>
#include <iphlpapi.h>
#include <lm.h>

/* WinHTTP */
typedef HINTERNET (WINAPI *PFN_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
extern PFN_WinHttpOpen fnWinHttpOpen;
typedef HINTERNET (WINAPI *PFN_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
extern PFN_WinHttpConnect fnWinHttpConnect;
typedef HINTERNET (WINAPI *PFN_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
extern PFN_WinHttpOpenRequest fnWinHttpOpenRequest;
typedef BOOL (WINAPI *PFN_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
extern PFN_WinHttpSendRequest fnWinHttpSendRequest;
typedef BOOL (WINAPI *PFN_WinHttpReceiveResponse)(HINTERNET, LPVOID);
extern PFN_WinHttpReceiveResponse fnWinHttpReceiveResponse;
typedef BOOL (WINAPI *PFN_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
extern PFN_WinHttpQueryHeaders fnWinHttpQueryHeaders;
typedef BOOL (WINAPI *PFN_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
extern PFN_WinHttpReadData fnWinHttpReadData;
typedef BOOL (WINAPI *PFN_WinHttpCloseHandle)(HINTERNET);
extern PFN_WinHttpCloseHandle fnWinHttpCloseHandle;
typedef BOOL (WINAPI *PFN_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
extern PFN_WinHttpSetOption fnWinHttpSetOption;
typedef BOOL (WINAPI *PFN_WinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
extern PFN_WinHttpQueryDataAvailable fnWinHttpQueryDataAvailable;

/* BCrypt */
typedef NTSTATUS (WINAPI *PFN_BCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
extern PFN_BCryptGenRandom fnBCryptGenRandom;
typedef NTSTATUS (WINAPI *PFN_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
extern PFN_BCryptOpenAlgorithmProvider fnBCryptOpenAlgorithmProvider;
typedef NTSTATUS (WINAPI *PFN_BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
extern PFN_BCryptCloseAlgorithmProvider fnBCryptCloseAlgorithmProvider;
typedef NTSTATUS (WINAPI *PFN_BCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
extern PFN_BCryptSetProperty fnBCryptSetProperty;
typedef NTSTATUS (WINAPI *PFN_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
extern PFN_BCryptGenerateSymmetricKey fnBCryptGenerateSymmetricKey;
typedef NTSTATUS (WINAPI *PFN_BCryptDestroyKey)(BCRYPT_KEY_HANDLE);
extern PFN_BCryptDestroyKey fnBCryptDestroyKey;
typedef NTSTATUS (WINAPI *PFN_BCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
extern PFN_BCryptEncrypt fnBCryptEncrypt;
typedef NTSTATUS (WINAPI *PFN_BCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
extern PFN_BCryptDecrypt fnBCryptDecrypt;
typedef NTSTATUS (WINAPI *PFN_BCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
extern PFN_BCryptCreateHash fnBCryptCreateHash;
typedef NTSTATUS (WINAPI *PFN_BCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
extern PFN_BCryptHashData fnBCryptHashData;
typedef NTSTATUS (WINAPI *PFN_BCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
extern PFN_BCryptFinishHash fnBCryptFinishHash;
typedef NTSTATUS (WINAPI *PFN_BCryptDestroyHash)(BCRYPT_HASH_HANDLE);
extern PFN_BCryptDestroyHash fnBCryptDestroyHash;

/* Crypt32 */
typedef BOOL (WINAPI *PFN_CryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
extern PFN_CryptStringToBinaryA fnCryptStringToBinaryA;
typedef BOOL (WINAPI *PFN_CryptDecodeObjectEx)(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
extern PFN_CryptDecodeObjectEx fnCryptDecodeObjectEx;
typedef BOOL (WINAPI *PFN_CryptImportPublicKeyInfoEx2)(DWORD, PCERT_PUBLIC_KEY_INFO, DWORD, void*, BCRYPT_KEY_HANDLE*);
extern PFN_CryptImportPublicKeyInfoEx2 fnCryptImportPublicKeyInfoEx2;

/* Advapi32 */
typedef BOOL (WINAPI *PFN_GetUserNameA)(LPSTR, LPDWORD);
extern PFN_GetUserNameA fnGetUserNameA;
typedef BOOL (WINAPI *PFN_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
extern PFN_OpenProcessToken fnOpenProcessToken;
typedef BOOL (WINAPI *PFN_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
extern PFN_GetTokenInformation fnGetTokenInformation;
typedef BOOL (WINAPI *PFN_LookupPrivilegeNameA)(LPCSTR, PLUID, LPSTR, LPDWORD);
extern PFN_LookupPrivilegeNameA fnLookupPrivilegeNameA;
typedef PDWORD (WINAPI *PFN_GetSidSubAuthority)(PSID, DWORD);
extern PFN_GetSidSubAuthority fnGetSidSubAuthority;
typedef PUCHAR (WINAPI *PFN_GetSidSubAuthorityCount)(PSID);
extern PFN_GetSidSubAuthorityCount fnGetSidSubAuthorityCount;
typedef SC_HANDLE (WINAPI *PFN_OpenSCManagerA)(LPCSTR, LPCSTR, DWORD);
extern PFN_OpenSCManagerA fnOpenSCManagerA;
typedef BOOL (WINAPI *PFN_CloseServiceHandle)(SC_HANDLE);
extern PFN_CloseServiceHandle fnCloseServiceHandle;
typedef BOOL (WINAPI *PFN_EnumServicesStatusExA)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
extern PFN_EnumServicesStatusExA fnEnumServicesStatusExA;
typedef BOOL (WINAPI *PFN_CreateProcessWithLogonW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
extern PFN_CreateProcessWithLogonW fnCreateProcessWithLogonW;
typedef LONG (WINAPI *PFN_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
extern PFN_RegOpenKeyExA fnRegOpenKeyExA;
typedef LONG (WINAPI *PFN_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
extern PFN_RegQueryValueExA fnRegQueryValueExA;
typedef LONG (WINAPI *PFN_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
extern PFN_RegSetValueExA fnRegSetValueExA;
typedef LONG (WINAPI *PFN_RegCloseKey)(HKEY);
extern PFN_RegCloseKey fnRegCloseKey;

/* Kernel32 — Toolhelp32 */
typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
extern PFN_CreateToolhelp32Snapshot fnCreateToolhelp32Snapshot;
typedef BOOL (WINAPI *PFN_Process32First)(HANDLE, LPPROCESSENTRY32);
extern PFN_Process32First fnProcess32First;
typedef BOOL (WINAPI *PFN_Process32Next)(HANDLE, LPPROCESSENTRY32);
extern PFN_Process32Next fnProcess32Next;

/* Kernel32 */
typedef BOOL (WINAPI *PFN_GetComputerNameA)(LPSTR, LPDWORD);
extern PFN_GetComputerNameA fnGetComputerNameA;
typedef BOOL (WINAPI *PFN_GetComputerNameExA)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
extern PFN_GetComputerNameExA fnGetComputerNameExA;
typedef DWORD (WINAPI *PFN_GetCurrentDirectoryA)(DWORD, LPSTR);
extern PFN_GetCurrentDirectoryA fnGetCurrentDirectoryA;
typedef BOOL (WINAPI *PFN_SetCurrentDirectoryA)(LPCSTR);
extern PFN_SetCurrentDirectoryA fnSetCurrentDirectoryA;
typedef BOOL (WINAPI *PFN_CreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
extern PFN_CreateDirectoryA fnCreateDirectoryA;
typedef BOOL (WINAPI *PFN_RemoveDirectoryA)(LPCSTR);
extern PFN_RemoveDirectoryA fnRemoveDirectoryA;
typedef BOOL (WINAPI *PFN_DeleteFileA)(LPCSTR);
extern PFN_DeleteFileA fnDeleteFileA;
typedef BOOL (WINAPI *PFN_CopyFileA)(LPCSTR, LPCSTR, BOOL);
extern PFN_CopyFileA fnCopyFileA;
typedef BOOL (WINAPI *PFN_MoveFileA)(LPCSTR, LPCSTR);
extern PFN_MoveFileA fnMoveFileA;
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
extern PFN_CreateProcessA fnCreateProcessA;
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
extern PFN_LoadLibraryA fnLoadLibraryA;
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
extern PFN_GetProcAddress fnGetProcAddress;
typedef HMODULE (WINAPI *PFN_GetModuleHandleA)(LPCSTR);
extern PFN_GetModuleHandleA fnGetModuleHandleA;

/* User32 */
typedef BOOL (WINAPI *PFN_OpenClipboard)(HWND);
extern PFN_OpenClipboard fnOpenClipboard;
typedef BOOL (WINAPI *PFN_CloseClipboard)(void);
extern PFN_CloseClipboard fnCloseClipboard;
typedef HANDLE (WINAPI *PFN_GetClipboardData)(UINT);
extern PFN_GetClipboardData fnGetClipboardData;

/* Iphlpapi */
typedef DWORD (WINAPI *PFN_GetIpNetTable)(PMIB_IPNETTABLE, PULONG, BOOL);
extern PFN_GetIpNetTable fnGetIpNetTable;
typedef ULONG (WINAPI *PFN_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PVOID, PULONG);
extern PFN_GetAdaptersAddresses fnGetAdaptersAddresses;
typedef DWORD (WINAPI *PFN_GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
extern PFN_GetExtendedTcpTable fnGetExtendedTcpTable;
typedef DWORD (WINAPI *PFN_GetExtendedUdpTable)(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);
extern PFN_GetExtendedUdpTable fnGetExtendedUdpTable;

/* Dnsapi */
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_A)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORD*, PVOID*);
extern PFN_DnsQuery_A fnDnsQuery_A;
typedef void (WINAPI *PFN_DnsRecordListFree)(PDNS_RECORD, DNS_FREE_TYPE);
extern PFN_DnsRecordListFree fnDnsRecordListFree;

/* Netapi32 */
typedef NET_API_STATUS (WINAPI *PFN_NetUserGetLocalGroups)(LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD);
extern PFN_NetUserGetLocalGroups fnNetUserGetLocalGroups;
typedef NET_API_STATUS (WINAPI *PFN_NetApiBufferFree)(LPVOID);
extern PFN_NetApiBufferFree fnNetApiBufferFree;

/* Kernel32 — IAT cleanup */
typedef HLOCAL (WINAPI *PFN_LocalAlloc)(UINT, SIZE_T);
extern PFN_LocalAlloc fnLocalAlloc;
typedef HLOCAL (WINAPI *PFN_LocalFree)(HLOCAL);
extern PFN_LocalFree fnLocalFree;
typedef BOOL (WINAPI *PFN_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
extern PFN_ReadFile fnReadFile;
typedef BOOL (WINAPI *PFN_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
extern PFN_WriteFile fnWriteFile;
typedef HANDLE (WINAPI *PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
extern PFN_CreateFileA fnCreateFileA2;
typedef DWORD (WINAPI *PFN_GetModuleFileNameA)(HMODULE, LPSTR, DWORD);
extern PFN_GetModuleFileNameA fnGetModuleFileNameA;
typedef void (WINAPI *PFN_GetNativeSystemInfo)(LPSYSTEM_INFO);
extern PFN_GetNativeSystemInfo fnGetNativeSystemInfo;
typedef int (WINAPI *PFN_MultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int);
extern PFN_MultiByteToWideChar fnMultiByteToWideChar;
typedef int (WINAPI *PFN_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
extern PFN_WideCharToMultiByte fnWideCharToMultiByte;
typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
extern PFN_OpenProcess fnOpenProcess2;
typedef BOOL (WINAPI *PFN_SetHandleInformation)(HANDLE, DWORD, DWORD);
extern PFN_SetHandleInformation fnSetHandleInformation;
typedef DWORD (WINAPI *PFN_GetLogicalDriveStringsA)(DWORD, LPSTR);
extern PFN_GetLogicalDriveStringsA fnGetLogicalDriveStringsA;
typedef BOOL (WINAPI *PFN_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
extern PFN_GlobalMemoryStatusEx fnGlobalMemoryStatusEx;
typedef LPVOID (WINAPI *PFN_GlobalLock)(HGLOBAL);
extern PFN_GlobalLock fnGlobalLock;
typedef BOOL (WINAPI *PFN_GlobalUnlock)(HGLOBAL);
extern PFN_GlobalUnlock fnGlobalUnlock;
typedef BOOL (WINAPI *PFN_GetExitCodeProcess)(HANDLE, LPDWORD);
extern PFN_GetExitCodeProcess fnGetExitCodeProcess;
typedef BOOL (WINAPI *PFN_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
extern PFN_CreatePipe fnCreatePipe;
typedef BOOL (WINAPI *PFN_GetFileSizeEx)(HANDLE, PLARGE_INTEGER);
extern PFN_GetFileSizeEx fnGetFileSizeEx;
typedef VOID (WINAPI *PFN_ExitProcess)(UINT);
extern PFN_ExitProcess fnExitProcess;
typedef DWORD (WINAPI *PFN_GetLastError)(void);
extern PFN_GetLastError fnGetLastError;
typedef HANDLE (WINAPI *PFN_GetCurrentProcess)(void);
extern PFN_GetCurrentProcess fnGetCurrentProcess;
typedef DWORD (WINAPI *PFN_GetCurrentProcessId)(void);
extern PFN_GetCurrentProcessId fnGetCurrentProcessId;
typedef HANDLE (WINAPI *PFN_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
extern PFN_FindFirstFileA fnFindFirstFileA;
typedef BOOL (WINAPI *PFN_FindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
extern PFN_FindNextFileA fnFindNextFileA;
typedef BOOL (WINAPI *PFN_FindClose)(HANDLE);
extern PFN_FindClose fnFindClose;
typedef BOOL (WINAPI *PFN_GetFileAttributesExA)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
extern PFN_GetFileAttributesExA fnGetFileAttributesExA;
typedef BOOL (WINAPI *PFN_FileTimeToSystemTime)(const FILETIME*, LPSYSTEMTIME);
extern PFN_FileTimeToSystemTime fnFileTimeToSystemTime;
typedef UINT (WINAPI *PFN_GetDriveTypeA)(LPCSTR);
extern PFN_GetDriveTypeA fnGetDriveTypeA;
typedef BOOL (WINAPI *PFN_GetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
extern PFN_GetDiskFreeSpaceExA fnGetDiskFreeSpaceExA;
typedef LPCH (WINAPI *PFN_GetEnvironmentStringsA)(void);
extern PFN_GetEnvironmentStringsA fnGetEnvironmentStringsA;
typedef BOOL (WINAPI *PFN_FreeEnvironmentStringsA)(LPCH);
extern PFN_FreeEnvironmentStringsA fnFreeEnvironmentStringsA;
typedef DWORD (WINAPI *PFN_GetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
extern PFN_GetEnvironmentVariableA fnGetEnvironmentVariableA;
typedef BOOL (WINAPI *PFN_TerminateProcess)(HANDLE, UINT);
extern PFN_TerminateProcess fnTerminateProcess;
typedef ULONGLONG (WINAPI *PFN_GetTickCount64)(void);
extern PFN_GetTickCount64 fnGetTickCount64;

/* Kernel32 — misc */
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
extern PFN_VirtualProtect fnVirtualProtect;
typedef DWORD (WINAPI *PFN_WaitForSingleObject)(HANDLE, DWORD);
extern PFN_WaitForSingleObject fnWaitForSingleObject;
typedef HANDLE (WINAPI *PFN_CreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
extern PFN_CreateEventW fnCreateEventW;
typedef BOOL (WINAPI *PFN_SetEvent)(HANDLE);
extern PFN_SetEvent fnSetEvent;
typedef BOOL (WINAPI *PFN_CloseHandle)(HANDLE);
extern PFN_CloseHandle fnCloseHandle2;
typedef VOID (WINAPI *PFN_Sleep)(DWORD);
extern PFN_Sleep fnSleep;
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
extern PFN_VirtualAlloc fnVirtualAlloc;
typedef BOOL (WINAPI *PFN_VirtualFree)(LPVOID, SIZE_T, DWORD);
extern PFN_VirtualFree fnVirtualFree;

void resolve_apis(void);
