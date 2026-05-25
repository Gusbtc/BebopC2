package server

import "strings"

type mcpCommandSpec struct {
	Name        string          `json:"name"`
	Platform    string          `json:"platform"`
	Category    string          `json:"category"`
	Description string          `json:"description"`
	Args        []mcpCommandArg `json:"args,omitempty"`
}

type mcpCommandArg struct {
	Name        string `json:"name"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

func mcpCommandCatalog() []mcpCommandSpec {
	return []mcpCommandSpec{
		{Name: "whoami", Platform: "all", Category: "identity", Description: "Current user context"},
		{Name: "hostname", Platform: "all", Category: "identity", Description: "Target hostname"},
		{Name: "sysinfo", Platform: "windows", Category: "identity", Description: "Windows system information"},
		{Name: "id", Platform: "linux", Category: "identity", Description: "Linux user and group identity"},
		{Name: "pwd", Platform: "all", Category: "files", Description: "Current working directory"},
		{Name: "ls", Platform: "all", Category: "files", Description: "List directory", Args: []mcpCommandArg{{Name: "path", Description: "Directory path"}}},
		{Name: "cat", Platform: "all", Category: "files", Description: "Read file", Args: []mcpCommandArg{{Name: "path", Required: true, Description: "File path"}}},
		{Name: "cd", Platform: "all", Category: "files", Description: "Change working directory", Args: []mcpCommandArg{{Name: "path", Required: true, Description: "Directory path"}}},
		{Name: "download", Platform: "all", Category: "files", Description: "Queue remote file exfiltration", Args: []mcpCommandArg{{Name: "remote_path", Required: true, Description: "Remote file path"}}},
		{Name: "upload", Platform: "all", Category: "files", Description: "Stage file bytes to remote path"},
		{Name: "ps", Platform: "all", Category: "process", Description: "List processes"},
		{Name: "kill", Platform: "all", Category: "process", Description: "Terminate process", Args: []mcpCommandArg{{Name: "pid", Required: true, Description: "Process ID"}}},
		{Name: "services", Platform: "windows", Category: "process", Description: "Enumerate Windows services"},
		{Name: "ipconfig", Platform: "all", Category: "network", Description: "List network interfaces"},
		{Name: "netstat", Platform: "all", Category: "network", Description: "List network connections"},
		{Name: "arp", Platform: "windows", Category: "network", Description: "List ARP table"},
		{Name: "dns", Platform: "windows", Category: "network", Description: "Resolve DNS name", Args: []mcpCommandArg{{Name: "name", Required: true, Description: "DNS name"}}},
		{Name: "privs", Platform: "windows", Category: "identity", Description: "List token privileges"},
		{Name: "groups", Platform: "windows", Category: "identity", Description: "List user groups"},
		{Name: "env", Platform: "all", Category: "system", Description: "List environment variables"},
		{Name: "getenv", Platform: "all", Category: "system", Description: "Read environment variable", Args: []mcpCommandArg{{Name: "name", Required: true, Description: "Variable name"}}},
		{Name: "reg_query", Platform: "windows", Category: "system", Description: "Query registry", Args: []mcpCommandArg{{Name: "path", Required: true, Description: "Registry path"}}},
		{Name: "shell", Platform: "all", Category: "execution", Description: "Run shell command", Args: []mcpCommandArg{{Name: "command", Required: true, Description: "Shell command"}}},
		{Name: "socks5", Platform: "all", Category: "network", Description: "Start or stop SOCKS5 proxy"},
		{Name: "execute-assembly", Platform: "windows", Category: "dotnet", Description: "Run .NET assembly out of process"},
		{Name: "inline-assembly", Platform: "windows", Category: "dotnet", Description: "Run .NET assembly in process through managed bridge"},
		{Name: "bof-execute", Platform: "windows", Category: "bof", Description: "Run BOF object"},
		{Name: "ldapsearch", Platform: "windows", Category: "domain", Description: "LDAP search BOF", Args: []mcpCommandArg{{Name: "filter", Required: true, Description: "LDAP filter"}, {Name: "attrs", Description: "Attribute list"}}},
		{Name: "adcs_enum", Platform: "windows", Category: "domain", Description: "ADCS enumeration BOF", Args: []mcpCommandArg{{Name: "args", Description: "Optional ADCS arguments"}}},
		{Name: "password-policy", Platform: "windows", Category: "domain", Description: "Domain password policy BOF"},
		{Name: "local-sessions", Platform: "windows", Category: "domain", Description: "Local/RDP session BOF"},
		{Name: "net-shares", Platform: "windows", Category: "domain", Description: "Network shares BOF"},
		{Name: "schtasks-enum", Platform: "windows", Category: "system", Description: "Scheduled task enumeration BOF"},
	}
}

func mcpCommandCatalogFiltered(platform string) []mcpCommandSpec {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" || platform == "all" {
		return mcpCommandCatalog()
	}
	out := make([]mcpCommandSpec, 0)
	for _, spec := range mcpCommandCatalog() {
		if spec.Platform == "all" || spec.Platform == platform {
			out = append(out, spec)
		}
	}
	return out
}

func mcpFindCommandSpec(name string) (mcpCommandSpec, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, spec := range mcpCommandCatalog() {
		if strings.ToLower(spec.Name) == name {
			return spec, true
		}
	}
	return mcpCommandSpec{}, false
}
