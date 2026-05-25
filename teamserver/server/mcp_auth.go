package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type mcpContextKey string

const mcpAuthKey mcpContextKey = "mcp-auth"
const mcpDefaultOperator = "operator"
const mcpMaxOperatorNameLen = 64
const mcpOperatorTokenTTL = 30 * 24 * time.Hour

type mcpScope string

const (
	mcpScopeRead     mcpScope = "read"
	mcpScopeTask     mcpScope = "task"
	mcpScopeFile     mcpScope = "file"
	mcpScopeLibrary  mcpScope = "library"
	mcpScopeListener mcpScope = "listener"
	mcpScopeBuild    mcpScope = "build"
	mcpScopeAdmin    mcpScope = "admin"
)

type mcpAuthContext struct {
	Operator string
	Scopes   map[mcpScope]bool
}

type mcpTokenConfig struct {
	Secret string
	Scopes map[mcpScope]bool
}

func normalizeMCPOperator(operator string) string {
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return mcpDefaultOperator
	}
	var b strings.Builder
	for i := 0; i < len(operator) && b.Len() < mcpMaxOperatorNameLen; i++ {
		c := operator[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '_',
			c == '-',
			c == '.',
			c == '@':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	normalized := strings.TrimSpace(b.String())
	if normalized == "" {
		return mcpDefaultOperator
	}
	return normalized
}

func configuredMCPAuth() mcpTokenConfig {
	raw := strings.TrimSpace(os.Getenv("BEBOP_MCP_TOKEN"))
	if raw == "" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			data, err := os.ReadFile(filepath.Join(home, ".bebop", "mcp.token"))
			if err == nil {
				raw = strings.TrimSpace(string(data))
			}
		}
	}
	return parseMCPTokenConfig(raw)
}

func configuredMCPToken() string {
	return configuredMCPAuth().Secret
}

func parseMCPTokenConfig(raw string) mcpTokenConfig {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return mcpTokenConfig{}
	}
	config := mcpTokenConfig{Secret: raw, Scopes: mcpFullScopes()}
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "=") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "token":
			config.Secret = strings.TrimSpace(value)
		case "scopes":
			config.Scopes = parseMCPScopes(value)
		}
	}
	return config
}

func parseMCPScopes(raw string) map[mcpScope]bool {
	scopes := map[mcpScope]bool{}
	for _, part := range strings.Split(raw, ",") {
		scope := mcpScope(strings.ToLower(strings.TrimSpace(part)))
		if scope != "" {
			scopes[scope] = true
		}
	}
	if len(scopes) == 0 {
		return mcpFullScopes()
	}
	return scopes
}

func mcpFullScopes() map[mcpScope]bool {
	return map[mcpScope]bool{
		mcpScopeRead:     true,
		mcpScopeTask:     true,
		mcpScopeFile:     true,
		mcpScopeLibrary:  true,
		mcpScopeListener: true,
		mcpScopeBuild:    true,
		mcpScopeAdmin:    true,
	}
}

func makeMCPOperatorToken(secret string, operator string) string {
	secret = strings.TrimSpace(secret)
	operator = normalizeMCPOperator(operator)
	if secret == "" || operator == "" {
		return ""
	}
	var nonceRaw [24]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return ""
	}
	encodedOperator := base64.RawURLEncoding.EncodeToString([]byte(operator))
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw[:])
	issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
	expiresAt := strconv.FormatInt(time.Now().Add(mcpOperatorTokenTTL).Unix(), 10)
	signature := signMCPOperatorTokenV3(secret, operator, issuedAt, expiresAt, nonce)
	if signature == "" {
		return ""
	}
	return "mcp3." + encodedOperator + "." + issuedAt + "." + expiresAt + "." + nonce + "." + signature
}

func signMCPOperatorToken(secret string, version string, operator string, nonce string) string {
	return signMCPParts(secret, version, operator, nonce)
}

func signMCPOperatorTokenV3(secret string, operator string, issuedAt string, expiresAt string, nonce string) string {
	return signMCPParts(secret, "mcp3", operator, issuedAt, expiresAt, nonce)
}

func signMCPParts(secret string, parts ...string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" || len(parts) == 0 {
		return ""
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			return ""
		}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("bebop-mcp-operator-token\x00"))
	for i, part := range parts {
		if i > 0 {
			mac.Write([]byte{0})
		}
		mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func parseMCPOperatorToken(raw string, secret string) (string, bool) {
	parts := strings.Split(raw, ".")
	switch {
	case len(parts) == 6 && parts[0] == "mcp3":
		operator, ok := decodeMCPOperator(parts[1])
		if !ok {
			return "", false
		}
		issuedAt, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return "", false
		}
		now := time.Now().Unix()
		expiresAt, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil || expiresAt <= issuedAt || issuedAt > now+300 || now > expiresAt {
			return "", false
		}
		if _, err := base64.RawURLEncoding.DecodeString(parts[4]); err != nil {
			return "", false
		}
		expectedSignature := signMCPOperatorTokenV3(secret, operator, parts[2], parts[3], parts[4])
		if expectedSignature == "" || !hmac.Equal([]byte(parts[5]), []byte(expectedSignature)) {
			return "", false
		}
		return operator, true
	case len(parts) == 4 && parts[0] == "mcp2":
		operator, ok := decodeMCPOperator(parts[1])
		if !ok {
			return "", false
		}
		if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
			return "", false
		}
		expectedSignature := signMCPOperatorToken(secret, "mcp2", operator, parts[2])
		if expectedSignature == "" || !hmac.Equal([]byte(parts[3]), []byte(expectedSignature)) {
			return "", false
		}
		return operator, true
	default:
		return "", false
	}
}

func decodeMCPOperator(encoded string) (string, bool) {
	operatorBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	operator := normalizeMCPOperator(string(operatorBytes))
	if operator == "" {
		return "", false
	}
	return operator, true
}

func (a mcpAuthContext) HasScope(scope mcpScope) bool {
	if scope == "" {
		return true
	}
	if a.Scopes == nil {
		return true
	}
	return a.Scopes[scope] || a.Scopes[mcpScopeAdmin]
}

func mcpToolScope(name string) mcpScope {
	name = mcpInternalToolName(name)
	switch {
	case name == "bebop.beacon.exit" || strings.HasPrefix(name, "bebop.session."):
		return mcpScopeAdmin
	case strings.Contains(name, ".delete"):
		if strings.Contains(name, "loot") || strings.Contains(name, "file") {
			return mcpScopeFile
		}
		if strings.Contains(name, "library") || strings.Contains(name, "assembly") {
			return mcpScopeLibrary
		}
		if strings.Contains(name, "listener") {
			return mcpScopeListener
		}
		return mcpScopeAdmin
	case strings.Contains(name, "file.") || strings.Contains(name, "loot."):
		if strings.HasSuffix(name, ".list") || strings.HasSuffix(name, ".get") {
			return mcpScopeRead
		}
		return mcpScopeFile
	case strings.Contains(name, "library.") || strings.Contains(name, "assembly."):
		if strings.HasSuffix(name, ".list") {
			return mcpScopeRead
		}
		return mcpScopeLibrary
	case strings.Contains(name, "listener"):
		if strings.HasSuffix(name, ".list") {
			return mcpScopeRead
		}
		return mcpScopeListener
	case name == "bebop.beacon.build":
		return mcpScopeBuild
	case strings.Contains(name, "command") ||
		strings.Contains(name, "bof") ||
		strings.Contains(name, "inline-assembly") ||
		strings.Contains(name, "beacon.sleep") ||
		strings.Contains(name, "beacon.interactive") ||
		strings.Contains(name, "socks.") ||
		strings.Contains(name, "filebrowser.list") ||
		strings.HasPrefix(name, "bebop.fs.") ||
		strings.HasPrefix(name, "bebop.identity.") ||
		strings.HasPrefix(name, "bebop.process.") ||
		strings.HasPrefix(name, "bebop.net.") ||
		strings.HasPrefix(name, "bebop.domain."):
		return mcpScopeTask
	case strings.Contains(name, "terminal.put") ||
		strings.Contains(name, "cache.set") ||
		strings.Contains(name, "events.add") ||
		strings.Contains(name, "events.post") ||
		strings.Contains(name, "chat.send"):
		return mcpScopeTask
	default:
		return mcpScopeRead
	}
}

func mcpToolRequiresConfirm(name string) bool {
	name = mcpInternalToolName(name)
	switch name {
	case "bebop.beacon.exit", "bebop.loot.delete", "bebop.library.delete", "bebop.assembly.delete", "bebop.listeners.delete":
		return true
	default:
		return false
	}
}
