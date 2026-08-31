package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	SourceFormat string              `json:"source_format"`
	ToFormat     string              `json:"to_format"`
	Model        string              `json:"model"`
	Stream       bool                `json:"stream"`
	Headers      map[string][]string `json:"headers"`
	Body         []byte              `json:"body"`
	Metadata     map[string]any      `json:"metadata"`
}

type InterceptResponsePayload struct {
	Headers      map[string][]string `json:"headers"`
	Body         []byte              `json:"body"`
	ClearHeaders []string            `json:"clear_headers"`
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		var req lifecycleRequest
		if len(request) > 0 {
			if err := json.Unmarshal(request, &req); err != nil {
				return errorEnvelope("config_error", err.Error()), nil
			}
		}
		pluginSettings = decodePluginSettings(req.ConfigYAML)
		return okEnvelope(pluginRegistration()), nil
	case pluginabi.MethodRequestInterceptAfter:
		return handleInterceptAfter(request)
	case pluginabi.MethodPluginShutdown:
		return okEnvelope(map[string]string{"status": "shutdown"}), nil
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "agy-identity-bridge",
			Version:          "0.1.3",
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
	if err := json.Unmarshal(request, &payload); err != nil {
		return errorEnvelope("parse_error", err.Error()), nil
	}

	providerName := payload.Model
	providerURL := ""
	if payload.Metadata != nil {
		if v, ok := payload.Metadata["provider_name"].(string); ok {
			providerName = v
		}
		if v, ok := payload.Metadata["base_url"].(string); ok {
			providerURL = v
		}
	}

	if !pluginSettings.shouldIntercept(providerName, providerURL) {
		return okEnvelope(InterceptResponsePayload{}), nil
	}

	bearerToken := extractBearerToken(payload.Headers)
	if bearerToken == "" {
		return okEnvelope(InterceptResponsePayload{}), nil
	}

	principalHash := derivePrincipal(bearerToken)
	clientApp := extractClientApp(payload.Headers)

	headers := map[string][]string{
		"X-AGY-Principal": {principalHash},
	}
	if clientApp != "" {
		headers["X-AGY-Client-App"] = []string{clientApp}
	}

	if secret := pluginSettings.hmacSecret(); secret != "" {
		sig := computeHMAC(principalHash, secret)
		headers["X-AGY-Signature"] = []string{sig}
	}

	return okEnvelope(InterceptResponsePayload{Headers: headers}), nil
}

func extractBearerToken(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, "Authorization") && len(values) > 0 {
			value := values[0]
			parts := strings.SplitN(value, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				return parts[1]
			}
		}
	}
	return ""
}

func extractClientApp(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, "X-AGY-Client-App") && len(values) > 0 {
			return values[0]
		}
	}
	for key, values := range headers {
		if strings.EqualFold(key, "User-Agent") && len(values) > 0 {
			ua := strings.ToLower(values[0])
			if strings.Contains(ua, "codex") {
				return "codex"
			}
			if strings.Contains(ua, "hermes") {
				return "hermes"
			}
			if strings.Contains(ua, "cursor") {
				return "cursor"
			}
			return values[0]
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
