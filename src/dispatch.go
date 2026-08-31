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
	ManagementAPI      bool `json:"management_api"`
}

type InterceptRequestPayload struct {
	SourceFormat   string              `json:"source_format"`
	ToFormat       string              `json:"to_format"`
	Model          string              `json:"model"`
	RequestedModel string              `json:"requested_model"`
	Stream         bool                `json:"stream"`
	Headers        map[string][]string `json:"headers"`
	Body           []byte              `json:"body"`
	Metadata       map[string]any      `json:"metadata"`
}

type InterceptResponsePayload struct {
	Headers      map[string][]string `json:"headers"`
	Body         []byte              `json:"body"`
	ClearHeaders []string            `json:"clear_headers"`
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configurePlugin(request); errConfigure != nil {
			return errorEnvelope("config_error", errConfigure.Error()), nil
		}
		return okEnvelope(pluginRegistration()), nil
	case pluginabi.MethodRequestInterceptAfter:
		return handleInterceptAfter(request)
	case pluginabi.MethodManagementRegister:
		return handleManagementRegister(), nil
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	case pluginabi.MethodPluginShutdown:
		return okEnvelope(map[string]string{"status": "shutdown"}), nil
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configurePlugin(raw []byte) error {
	var request lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	snapshot := loadPluginConfiguration(request.ConfigYAML)
	applyPluginConfiguration(snapshot)

	diagnostics := scanProviderDiagnostics()
	hostLog("info", "provider discovery completed", map[string]any{
		"config_path_found":        diagnostics.ConfigPathFound,
		"plugin_config_found":      diagnostics.PluginConfigFound,
		"scanned_records":          diagnostics.ScannedRecordCount,
		"matched_records":          diagnostics.MatchedRecordCount,
		"matched_providers":        diagnostics.MatchedProviderCount,
		"runtime_auth_count":       diagnostics.RuntimeAuthCount,
		"auto_discover":            diagnostics.AutoDiscover,
		"match_mode":               diagnostics.MatchMode,
		"match_api_key_configured": diagnostics.MatchAPIKeyConfigured,
	})
	return nil
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "agy-identity-bridge",
			Version:          pluginVersion,
			Author:           "ngojclee",
			GitHubRepository: "https://github.com/ngojclee/agy-identity-bridge",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "auto_discover",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "When true, match native Antigravity or provider names/URLs containing antigravity or agy2api when no explicit rule is set. Default true.",
				},
				{
					Name:        "include_native_antigravity",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Allow automatic matching of the native CPA Antigravity format. Default true.",
				},
				{
					Name:        "match_mode",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{"any", "all"},
					Description: "With explicit rules, match any configured criterion or require all configured criteria. Default any.",
				},
				{
					Name:        "match_name",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Provider name selector. Case-insensitive substring or * and ? wildcard matching.",
				},
				{
					Name:        "match_provider",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Single provider name/key selector. This legacy-compatible alias is merged into match_providers.",
				},
				{
					Name:        "match_url",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Provider base URL selector. Case-insensitive substring or * and ? wildcard matching.",
				},
				{
					Name:        "match_api_key",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Exact provider API key selector. It is never returned by diagnostics; leave empty for OAuth/native providers.",
				},
				{
					Name:        "match_providers",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Additional provider name/key selectors. Legacy match_provider is also accepted.",
				},
				{
					Name:        "hmac_secret_source",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{"env", "config", "provider_api_key", "none"},
					Description: "Signature source: AGY_PLUGIN_SECRET from the CPA environment, the selected provider API key, or none. Default env.",
				},
				{
					Name:        "hmac_secret",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Optional HMAC secret when hmac_secret_source is config. Prefer AGY_PLUGIN_SECRET so secrets stay out of config exports.",
				},
			},
		},
		Capabilities: registrationCapability{
			RequestInterceptor: true,
			ManagementAPI:      true,
		},
	}
}

func handleInterceptAfter(request []byte) ([]byte, error) {
	var payload InterceptRequestPayload
	if errUnmarshal := json.Unmarshal(request, &payload); errUnmarshal != nil {
		return errorEnvelope("parse_error", errUnmarshal.Error()), nil
	}

	settings := currentPluginSettings()
	if !settings.Enabled {
		return okEnvelope(InterceptResponsePayload{}), nil
	}
	candidate := candidateFromPayload(payload)
	matched, _ := settings.shouldInterceptCandidate(candidate)
	if !matched {
		return okEnvelope(InterceptResponsePayload{}), nil
	}
	recordIntercept(candidate)

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

	if secret := hmacSecretForCandidate(settings, candidate); secret != "" {
		headers["X-AGY-Signature"] = []string{computeHMAC(principalHash, secret)}
	}

	return okEnvelope(InterceptResponsePayload{Headers: headers}), nil
}

func extractBearerToken(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, "Authorization") && len(values) > 0 {
			parts := strings.SplitN(strings.TrimSpace(values[0]), " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func extractClientApp(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, "X-AGY-Client-App") && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	for key, values := range headers {
		if strings.EqualFold(key, "User-Agent") && len(values) > 0 {
			ua := strings.ToLower(values[0])
			switch {
			case strings.Contains(ua, "codex"):
				return "codex"
			case strings.Contains(ua, "hermes"):
				return "hermes"
			case strings.Contains(ua, "cursor"):
				return "cursor"
			default:
				return strings.TrimSpace(values[0])
			}
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
	result, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return errorEnvelope("serialization_error", errMarshal.Error())
	}
	raw, errMarshal := json.Marshal(pluginabi.Envelope{
		OK:     true,
		Result: result,
	})
	if errMarshal != nil {
		return []byte(`{"ok":false,"error":{"code":"serialization_error","message":"failed to encode plugin envelope"}}`)
	}
	return raw
}

func errorEnvelope(code, message string) []byte {
	raw, errMarshal := json.Marshal(pluginabi.Envelope{
		OK: false,
		Error: &pluginabi.Error{
			Code:    code,
			Message: message,
		},
	})
	if errMarshal != nil {
		return []byte(`{"ok":false,"error":{"code":"serialization_error","message":"failed to encode plugin error"}}`)
	}
	return raw
}
