package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	RequestInterceptor    bool     `json:"request_interceptor"`
	ManagementAPI         bool     `json:"management_api"`
	ModelRegistrar        bool     `json:"model_registrar"`
	ModelProvider         bool     `json:"model_provider"`
	Executor              bool     `json:"executor"`
	ExecutorModelScope    string   `json:"executor_model_scope,omitempty"`
	ExecutorInputFormats  []string `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string `json:"executor_output_formats,omitempty"`
}

type InterceptRequestPayload struct {
	SourceFormat   string
	ToFormat       string
	Model          string
	RequestedModel string
	Stream         bool
	Headers        map[string][]string
	Body           []byte
	Metadata       map[string]any
}

type InterceptResponsePayload struct {
	// Field names are deliberately untagged. CLIProxyAPI declares
	// pluginapi.RequestInterceptResponse without json tags, so it decodes the
	// Go field names. Tagging these snake_case silently drops every value and
	// turns the interceptor into a no-op.
	Headers      map[string][]string
	Body         []byte
	ClearHeaders []string
}

// parseInterceptPayload accepts the Go-style keys CLIProxyAPI actually sends as
// well as snake_case variants. mapValue normalises separators, so "ToFormat"
// and "to_format" both resolve to the same field.
func parseInterceptPayload(raw []byte) (InterceptRequestPayload, error) {
	var payload InterceptRequestPayload
	if len(raw) == 0 {
		return payload, nil
	}
	var decoded map[string]any
	if errJSON := json.Unmarshal(raw, &decoded); errJSON != nil {
		return payload, errJSON
	}
	if decoded == nil {
		return payload, nil
	}
	payload.SourceFormat, _ = stringValue(decoded, "source_format")
	payload.ToFormat, _ = stringValue(decoded, "to_format")
	payload.Model, _ = stringValue(decoded, "model")
	payload.RequestedModel, _ = stringValue(decoded, "requested_model")
	payload.Stream, _ = boolValue(decoded, "stream")
	if value, ok := mapValue(decoded, "metadata"); ok {
		payload.Metadata = asMap(value)
	}
	if value, ok := mapValue(decoded, "headers"); ok {
		payload.Headers = headerMapFromAny(asMap(value))
	}
	if value, ok := stringValue(decoded, "body"); ok {
		if decodedBody, errDecode := base64.StdEncoding.DecodeString(value); errDecode == nil {
			payload.Body = decodedBody
		}
	}
	return payload, nil
}

func headerMapFromAny(raw map[string]any) map[string][]string {
	if raw == nil {
		return nil
	}
	out := make(map[string][]string, len(raw))
	for key, value := range raw {
		switch typed := value.(type) {
		case []any:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				if text, ok := item.(string); ok {
					values = append(values, text)
				}
			}
			if len(values) > 0 {
				out[key] = values
			}
		case string:
			out[key] = []string{typed}
		}
	}
	return out
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configurePlugin(request); errConfigure != nil {
			return errorEnvelope("config_error", errConfigure.Error()), nil
		}
		return okEnvelope(pluginRegistration()), nil
	case pluginabi.MethodRequestInterceptBefore:
		// Provider identity and the client bearer key are available after CPA
		// selects auth. The before-auth hook is intentionally a no-op, but it
		// must still be handled because RequestInterceptor enables both hooks.
		return okEnvelope(InterceptResponsePayload{}), nil
	case pluginabi.MethodRequestInterceptAfter:
		return handleInterceptAfter(request)
	case pluginabi.MethodModelRegister:
		return handleModelRegister(), nil
	case pluginabi.MethodModelStatic:
		return handleModelStatic(), nil
	case pluginabi.MethodModelForAuth:
		return handleModelForAuth(request)
	case pluginabi.MethodExecutorIdentifier:
		return handleExecutorIdentifier(), nil
	case pluginabi.MethodExecutorExecute:
		return handleExecutorExecute(request)
	case pluginabi.MethodExecutorExecuteStream:
		return handleExecutorExecuteStream(request)
	case pluginabi.MethodExecutorCountTokens:
		return handleExecutorCountTokens(request)
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
	resetExecutorAuthRecordState()

	// The mirrored provider record can change when CPA config changes, so the
	// cache is dropped and rebuilt from the freshly loaded config.
	storeProviderSpec(providerSpec{}, false)
	spec, mirrored := resolveProviderSpec()
	settings := currentPluginSettings()
	hostLog("info", "provider mirror resolved", map[string]any{
		"executor_provider": settings.ExecutorProvider,
		"mirrored":          spec.Name,
		"found":             mirrored,
		"models":            len(spec.Models),
		"has_api_key":       spec.primaryAPIKey() != "",
		"executor_enabled":  settings.ExecutorEnabled,
		"model_namespace":   settings.ModelNamespace,
	})

	if settings.ExecutorEnabled && mirrored {
		if errAuth := ensureAuthRecord(spec, settings); errAuth != nil {
			// Non-fatal: the plugin still registers and models still list.
			// Without an auth record, requests routed to this executor will
			// fail with auth_not_found, which the status page will show.
			hostLog("warn", "auth record creation failed", map[string]any{
				"error": errAuth.Error(),
			})
			recordDashboardEvent("error", "Plugin executor auth record could not be created")
		} else {
			hostLog("info", "auth record ensured", map[string]any{
				"provider": settings.ExecutorProvider,
			})
		}
	}

	diagnostics := scanProviderDiagnostics()
	recordDashboardEvent("info", fmt.Sprintf(
		"Configuration applied: %d matched provider record(s), replacement mode %s",
		diagnostics.MatchedRecordCount, diagnostics.ReplacementMode,
	))
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
					Name:        "match_model",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Requested model selector such as agy/* . CLIProxyAPI exposes the model, not the provider, to interceptors, so this is the reliable way to pin one OpenAI-compatible provider.",
				},
				{
					Name:        "match_models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Additional requested model selectors. Legacy match_model is also accepted.",
				},
				{
					Name:        "allow_explicit_client_identity_headers",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Allow trusted client identity headers such as X-AGY-Client-App, X-AGY-Client-Instance, and X-AGY-Connector-Id to influence principal derivation. Default true.",
				},
				{
					Name:        "principal_fallback_mode",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{"client_key_hash", "user_agent_plus_session", "disabled"},
					Description: "Fallback strategy when explicit client identity headers are absent. Default client_key_hash.",
				},
				{
					Name:        "debug_logging",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Emit safe metadata only to the dashboard event log. Secrets, tokens, and raw authorization values are never logged.",
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
				{
					Name:        "agy2api_identity_secret",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Dedicated HMAC secret matching agy2api AGY_IDENTITY_BRIDGE_SECRET. Takes priority over hmac_secret and AGY_PLUGIN_SECRET. Write-only: never returned by GET settings.",
				},
				{
					Name:        "executor_enabled",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Serve the mirrored provider from this plugin instead of CLIProxyAPI, so identity headers reach agy2api. Default false, which keeps routing unchanged.",
				},
				{
					Name:        "executor_provider",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Plugin-owned provider key used in executor mode. It must not be a key CLIProxyAPI already serves natively. Default ln.Antigravity.",
				},
				{
					Name:        "model_namespace",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Optional prefix applied to published model IDs while testing, to avoid colliding with the still-enabled mirrored provider. Leave empty to publish the exact configured model names.",
				},
			},
		},
		Capabilities: registrationCapabilities(),
	}
}

// registrationCapabilities keeps model and executor capabilities undeclared
// until the owner opts in, so installing a new plugin version cannot change
// which provider serves a model.
func registrationCapabilities() registrationCapability {
	capabilities := registrationCapability{
		RequestInterceptor: true,
		ManagementAPI:      true,
	}
	settings := currentPluginSettings()
	spec, mirrored := cachedProviderSpec()
	if settings.ExecutorEnabled && mirrored && canServeModels(settings, spec) {
		capabilities.ModelRegistrar = true
		capabilities.ModelProvider = true
		capabilities.Executor = true
		capabilities.ExecutorModelScope = "both"
		capabilities.ExecutorInputFormats = []string{"chat-completions", "openai-image"}
		capabilities.ExecutorOutputFormats = []string{"chat-completions", "openai-image"}
	}
	return capabilities
}

func handleInterceptAfter(request []byte) ([]byte, error) {
	payload, errParse := parseInterceptPayload(request)
	if errParse != nil {
		return errorEnvelope("parse_error", errParse.Error()), nil
	}

	settings := currentPluginSettings()
	if !settings.Enabled {
		return okEnvelope(InterceptResponsePayload{}), nil
	}
	candidate := candidateFromPayload(payload, settings)
	matched, _ := settings.shouldInterceptCandidate(candidate)
	if !matched {
		return okEnvelope(InterceptResponsePayload{}), nil
	}
	identity := deriveClientIdentityFromIntercept(payload, settings)
	if identity.Principal == "" {
		recordDashboardEvent("warning", "Client request matched the mirrored provider but no stable identity could be derived")
		return okEnvelope(InterceptResponsePayload{}), nil
	}
	identity.ProviderName = candidate.Name
	recordIntercept(candidate, identity)

	headers := map[string][]string{
		"X-AGY-Principal":         {identity.Principal},
		"X-AGY-Timestamp":         {identity.Timestamp},
		"X-AGY-Client-App":        {identity.ClientApp},
		"X-AGY-Plugin-Version":    {pluginVersion},
		"X-AGY-CPA-Provider-Name": {candidate.Name},
	}
	if identity.ClientInstance != "" {
		headers["X-AGY-Client-Instance"] = []string{identity.ClientInstance}
	}
	if identity.CapabilityProfile != "" {
		headers["X-AGY-Capability-Profile"] = []string{identity.CapabilityProfile}
	}
	if identity.ConnectorID != "" {
		headers["X-AGY-Connector-Id"] = []string{identity.ConnectorID}
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
	return hashString(bearerToken)
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
