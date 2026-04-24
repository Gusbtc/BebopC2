// teamserver/hashgen/hashgen.go
package hashgen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func DJB2(s string) uint32 {
	h := uint32(5381)
	for _, c := range []byte(s) {
		h = h*33 ^ uint32(c)
	}
	return h
}

type fnEntry struct {
	name  string
	group string
}

var functions = []fnEntry{
	// WinHTTP
	{"WinHttpOpen", "WinHTTP"},
	{"WinHttpConnect", "WinHTTP"},
	{"WinHttpOpenRequest", "WinHTTP"},
	{"WinHttpSendRequest", "WinHTTP"},
	{"WinHttpReceiveResponse", "WinHTTP"},
	{"WinHttpQueryHeaders", "WinHTTP"},
	{"WinHttpReadData", "WinHTTP"},
	{"WinHttpCloseHandle", "WinHTTP"},
	{"WinHttpSetOption", "WinHTTP"},
	{"WinHttpQueryDataAvailable", "WinHTTP"},
	// BCrypt
	{"BCryptGenRandom", "BCrypt"},
	{"BCryptOpenAlgorithmProvider", "BCrypt"},
	{"BCryptCloseAlgorithmProvider", "BCrypt"},
	{"BCryptSetProperty", "BCrypt"},
	{"BCryptGenerateSymmetricKey", "BCrypt"},
	{"BCryptDestroyKey", "BCrypt"},
	{"BCryptEncrypt", "BCrypt"},
	{"BCryptDecrypt", "BCrypt"},
	{"BCryptCreateHash", "BCrypt"},
	{"BCryptHashData", "BCrypt"},
	{"BCryptFinishHash", "BCrypt"},
	{"BCryptDestroyHash", "BCrypt"},
	// Crypt32
	{"CryptStringToBinaryA", "Crypt32"},
	{"CryptDecodeObjectEx", "Crypt32"},
	{"CryptImportPublicKeyInfoEx2", "Crypt32"},
	// Advapi32 (Detected in PE-bear)
	{"GetUserNameA", "Advapi32"},
	{"OpenProcessToken", "Advapi32"},
	{"GetTokenInformation", "Advapi32"},
	{"LookupPrivilegeNameA", "Advapi32"},
	{"GetSidSubAuthority", "Advapi32"},
	{"GetSidSubAuthorityCount", "Advapi32"},
	{"OpenSCManagerA", "Advapi32"},
	{"CloseServiceHandle", "Advapi32"},
	{"EnumServicesStatusExA", "Advapi32"},
	{"CreateProcessWithLogonW", "Advapi32"},
	{"RegOpenKeyExA", "Advapi32"},
	{"RegQueryValueExA", "Advapi32"},
	{"RegSetValueExA", "Advapi32"},
	{"RegCloseKey", "Advapi32"},
	// Kernel32
	{"GetComputerNameA", "Kernel32"},
	{"GetComputerNameExA", "Kernel32"},
	{"GetCurrentDirectoryA", "Kernel32"},
	{"SetCurrentDirectoryA", "Kernel32"},
	{"CreateDirectoryA", "Kernel32"},
	{"RemoveDirectoryA", "Kernel32"},
	{"DeleteFileA", "Kernel32"},
	{"CopyFileA", "Kernel32"},
	{"MoveFileA", "Kernel32"},
	{"CreateProcessA", "Kernel32"},
	{"VirtualAlloc", "Kernel32"},
	{"VirtualFree", "Kernel32"},
	{"LoadLibraryA", "Kernel32"},
	{"GetProcAddress", "Kernel32"},
	{"GetModuleHandleA", "Kernel32"},
	// User32 (Detected in PE-bear)
	{"OpenClipboard", "User32"},
	{"CloseClipboard", "User32"},
	{"GetClipboardData", "User32"},
	// Kernel32 (Toolhelp32 — process enumeration)
	{"CreateToolhelp32Snapshot", "Kernel32"},
	{"Process32First", "Kernel32"},
	{"Process32Next", "Kernel32"},
	// Iphlpapi (Detected in PE-bear)
	{"GetAdaptersInfo", "Iphlpapi"},
	{"GetIpNetTable", "Iphlpapi"},
	{"GetTcpTable", "Iphlpapi"},
	{"GetAdaptersAddresses", "Iphlpapi"},
	{"GetExtendedTcpTable", "Iphlpapi"},
	{"GetExtendedUdpTable", "Iphlpapi"},
	// Dnsapi (Detected in PE-bear)
	{"DnsQuery_A", "Dnsapi"},
	{"DnsRecordListFree", "Dnsapi"},
	// Netapi32 (Detected in PE-bear)
	{"NetUserGetLocalGroups", "Netapi32"},
	{"NetApiBufferFree", "Netapi32"},
	// Kernel32 — IAT cleanup
	{"LocalAlloc", "Kernel32"},
	{"LocalFree", "Kernel32"},
	{"ReadFile", "Kernel32"},
	{"WriteFile", "Kernel32"},
	{"CreateFileA", "Kernel32"},
	{"GetModuleFileNameA", "Kernel32"},
	{"GetNativeSystemInfo", "Kernel32"},
	{"MultiByteToWideChar", "Kernel32"},
	{"WideCharToMultiByte", "Kernel32"},
	{"OpenProcess", "Kernel32"},
	{"SetHandleInformation", "Kernel32"},
	{"GetLogicalDriveStringsA", "Kernel32"},
	{"GlobalMemoryStatusEx", "Kernel32"},
	{"GlobalLock", "Kernel32"},
	{"GlobalUnlock", "Kernel32"},
	{"GetExitCodeProcess", "Kernel32"},
	{"CreatePipe", "Kernel32"},
	{"GetFileSizeEx", "Kernel32"},
	{"ExitProcess", "Kernel32"},
	{"GetLastError", "Kernel32"},
	{"GetCurrentProcess", "Kernel32"},
	{"GetCurrentProcessId", "Kernel32"},
	{"FindFirstFileA", "Kernel32"},
	{"FindNextFileA", "Kernel32"},
	{"FindClose", "Kernel32"},
	{"GetFileAttributesExA", "Kernel32"},
	{"FileTimeToSystemTime", "Kernel32"},
	{"GetDriveTypeA", "Kernel32"},
	{"GetDiskFreeSpaceExA", "Kernel32"},
	{"GetEnvironmentStringsA", "Kernel32"},
	{"FreeEnvironmentStringsA", "Kernel32"},
	{"GetEnvironmentVariableA", "Kernel32"},
	{"TerminateProcess", "Kernel32"},
	{"GetTickCount64", "Kernel32"},
	// Kernel32 — misc
	{"VirtualProtect", "Kernel32"},
	{"WaitForSingleObject", "Kernel32"},
	{"CreateEventW", "Kernel32"},
	{"SetEvent", "Kernel32"},
	{"CloseHandle", "Kernel32"},
	{"Sleep", "Kernel32"},
	// Winsock2 — session mode
	{"WSAStartup", "Winsock2"},
	{"WSACleanup", "Winsock2"},
	{"socket", "Winsock2"},
	{"connect", "Winsock2"},
	{"send", "Winsock2"},
	{"recv", "Winsock2"},
	{"closesocket", "Winsock2"},
	// Winsock2 — shell TCP
	{"inet_addr", "Winsock2"},
	{"htons", "Winsock2"},
	// Winsock2 — SOCKS5 pivoting
	{"getaddrinfo", "Winsock2"},
	{"freeaddrinfo", "Winsock2"},
	{"ioctlsocket", "Winsock2"},
	{"select", "Winsock2"},
	// Kernel32 — threading (session mode)
	{"CreateThread", "Kernel32"},
	{"InitializeCriticalSection", "Kernel32"},
	{"EnterCriticalSection", "Kernel32"},
	{"LeaveCriticalSection", "Kernel32"},
	{"DeleteCriticalSection", "Kernel32"},
	{"WaitForMultipleObjects", "Kernel32"},
	// Kernel32 — process/pipe (session shell)
	{"PeekNamedPipe", "Kernel32"},
	{"CreateProcessW", "Kernel32"},
	// Kernel32 — ConPTY (session shell)
	{"CreatePseudoConsole", "Kernel32"},
	{"ClosePseudoConsole", "Kernel32"},
	{"ResizePseudoConsole", "Kernel32"},
	{"InitializeProcThreadAttributeList", "Kernel32"},
	{"UpdateProcThreadAttribute", "Kernel32"},
	{"DeleteProcThreadAttributeList", "Kernel32"},
	{"HeapAlloc", "Kernel32"},
	{"GetProcessHeap", "Kernel32"},
	{"HeapFree", "Kernel32"},
}

func Generate(outDir string) error {
	var sb strings.Builder
	sb.WriteString("/* AUTO-GENERATED by gen_hashes — DO NOT EDIT */\n#pragma once\n\n")
	cur := ""
	for _, f := range functions {
		if f.group != cur {
			cur = f.group
			fmt.Fprintf(&sb, "/* %s */\n", cur)
		}
		fmt.Fprintf(&sb, "#define HASH_%-35s 0x%08XUL\n", f.name, DJB2(f.name))
	}
	return os.WriteFile(filepath.Join(outDir, "api_hashes.h"), []byte(sb.String()), 0644)
}
