package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
			"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	RequestInterceptor bool `json:"request_interceptor"`
}

type InterceptRequestPayload struct {
	SourceFormat string         `json:"source_format"`
	ToFormat     string         `json:"to_format"`
	Model        string         `json:"model"`
	Stream       bool           `json:"stream"`
	Headers      map[string][]string `json:"headers"`
	Body         []byte         `json:"body"`
	Metadata     map[string]any `json:"metadata"`
}

type InterceptResponsePayload struct {
	Headers      map[string][]string `json:"headers"`
	Body         []byte              `json:"body"`
	ClearHeaders []string            `json:"clear_headers"`
}

var (
	providerPatterns []string
	sharedSecret     string
)

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration()), nil
	case pluginabi.MethodRequestInterceptAfter:
		return handleInterceptAfter(request)
	case pluginabi.MethodPluginShutdown:
		return okEnvelope(map[string]string{"status": "shutdown"}), nil
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	if len(req.ConfigYAML) > 0 {
		parseConfig(req.ConfigYAML)
	}
	sharedSecret = os.Getenv("AGY_PLUGIN_SECRET")
	return nil
}

func parseConfig(raw []byte) {
	type pluginConfig struct {
		MatchProviders []string `yaml:"match_providers"`
	}
	// Simple approach: parse YAML for match_providers list
	// In production use yaml.v3 proper parsing
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- name_pattern:") || strings.HasPrefix(trimmed, "- base_url_pattern:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				pattern := strings.TrimSpace(parts[1])
				pattern = strings.Trim(pattern, "\"'")
				if pattern != "" {
					providerPatterns = append(providerPatterns, pattern)
				}
			}
		}
	}
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "agy-identity-bridge",
			Version:          "0.1.0",
			Author:           "ngojclee",
			GitHubRepository: "https://github.com/ngojclee/agy-identity-bridge",
		},
		Capabilities: registrationCapability{
			RequestInterceptor: true,
		},
	}
}

func handleInterceptAfter(request []byte) ([]byte, error) {
	var payload InterceptRequestPayload
	if errUnmarshal := json.Unmarshal(request, &payload); errUnmarshal != nil {
		return errorEnvelope("parse_error", errUnmarshal.Error()), nil
	}

	// Check if this request matches our target providers.
	if !shouldIntercept(payload.Headers) {
		// Pass through unchanged.
		return okEnvelope(InterceptResponsePayload{}), nil
	}

	// Extract original Bearer token.
	bearerToken := extractBearerToken(payload.Headers)
	if bearerToken == "" {
		// No Bearer token; pass through.
		return okEnvelope(InterceptResponsePayload{}), nil
	}

	// Derive principal hash.
	principalHash := derivePrincipal(bearerToken)

	// Extract client app from User-Agent or custom header.
	clientApp := extractClientApp(payload.Headers)

	// Build response with injected headers.
	headers := map[string][]string{}
	headers["X-AGY-Principal"] = []string{principalHash}
	if clientApp != "" {
		headers["X-AGY-Client-App"] = []string{clientApp}
	}

	// HMAC signature if secret is configured.
	if sharedSecret != "" {
		sig := computeHMAC(principalHash, sharedSecret)
		headers["X-AGY-Signature"] = []string{sig}
	}

	return okEnvelope(InterceptResponsePayload{Headers: headers}), nil
}

func shouldIntercept(headers map[string][]string) bool {
	// Check provider patterns against the To-Format or metadata.
	// For now, always intercept since the plugin is only configured for agy2api providers.
	return true
}

func extractBearerToken(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, "Authorization") && len(values) > 0 {
			value := values[0]
			if strings.HasPrefix(strings.ToLower(value), "bearer ") {
				return strings.TrimPrefix(value, strings.SplitN(value, " ", 2)[0]+" ")
			}
		}
	}
	return ""
}

func extractClientApp(headers map[string][]string) string {
	// Check custom header first.
	for key, values := range headers {
		if strings.EqualFold(key, "X-AGY-Client-App") && len(values) > 0 {
			return values[0]
		}
	}
	// Check User-Agent.
	for key, values := range headers {
		if strings.EqualFold(key, "User-Agent") && len(values) > 0 {
			ua := values[0]
			uaLower := strings.ToLower(ua)
			if strings.Contains(uaLower, "codex") {
				return "codex"
			}
			if strings.Contains(uaLower, "hermes") {
				return "hermes"
			}
			if strings.Contains(uaLower, "cursor") {
				return "cursor"
			}
			return ua
		}
	}
	return ""
}

func derivePrincipal(bearerToken string) string {
	hash := sha256.Sum256([]byte(bearerToken))
	return hex.EncodeToString(hash[:])
}

func computeHMAC(principalHash string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(principalHash))
	return hex.EncodeToString(mac.Sum(nil))
}

func okEnvelope(v any) []byte {
	raw, _ := json.Marshal(map[string]any{"ok": v})
	return raw
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": message}})
	return raw
}

