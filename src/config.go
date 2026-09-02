package main

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const pluginID = "agy-identity-bridge"

// PluginSettings contains the plugin-owned configuration under
// plugins.configs.agy-identity-bridge.
//
// MatchAPIKey is only a provider selector. It is deliberately separate from
// the HMAC secret so a provider credential cannot be exposed accidentally by
// diagnostics or used for signing unless that mode is explicitly selected.
type PluginSettings struct {
	Enabled                            bool     `yaml:"enabled" json:"enabled"`
	Priority                           int      `yaml:"priority" json:"priority"`
	AutoDiscover                       bool     `yaml:"auto_discover" json:"auto_discover"`
	IncludeNativeAntigravity           bool     `yaml:"include_native_antigravity" json:"include_native_antigravity"`
	AllowExplicitClientIdentityHeaders bool     `yaml:"allow_explicit_client_identity_headers" json:"allow_explicit_client_identity_headers"`
	PrincipalFallbackMode              string   `yaml:"principal_fallback_mode" json:"principal_fallback_mode"`
	DebugLogging                       bool     `yaml:"debug_logging" json:"debug_logging"`
	MatchMode                          string   `yaml:"match_mode" json:"match_mode"`
	MatchName                          string   `yaml:"match_name" json:"match_name"`
	MatchURL                           string   `yaml:"match_url" json:"match_url"`
	MatchAPIKey                        string   `yaml:"match_api_key" json:"match_api_key"`
	MatchProvider                      string   `yaml:"match_provider" json:"match_provider"`
	MatchProviders                     []string `yaml:"match_providers" json:"match_providers"`
	MatchModel                         string   `yaml:"match_model" json:"match_model"`
	MatchModels                        []string `yaml:"match_models" json:"match_models"`
	HMACSecret                         string   `yaml:"hmac_secret" json:"hmac_secret"`
	HMACSecretSource                   string   `yaml:"hmac_secret_source" json:"hmac_secret_source"`
	Agy2apiIdentitySecret              string   `yaml:"agy2api_identity_secret" json:"agy2api_identity_secret"`

	// Executor mode makes this plugin the caller for the mirrored provider, so
	// identity headers survive to agy2api. Disabled by default: installing a
	// new plugin version must not change live routing until the owner opts in.
	ExecutorEnabled  bool   `yaml:"executor_enabled" json:"executor_enabled"`
	ExecutorProvider string `yaml:"executor_provider" json:"executor_provider"`
	ModelNamespace   string `yaml:"model_namespace" json:"model_namespace"`
}

type pluginConfigSnapshot struct {
	Settings          PluginSettings
	ConfigYAML        []byte
	ConfigPath        string
	ConfigPathFound   bool
	PluginConfigFound bool
	Warnings          []string
}

var (
	pluginSettingsMu sync.RWMutex
	pluginSettings   = defaultPluginSettings()

	pluginConfigMu        sync.RWMutex
	pluginConfigYAML      []byte
	pluginConfigPath      string
	pluginConfigPathFound bool
	pluginConfigFound     bool
	pluginConfigWarnings  []string
)

func defaultPluginSettings() PluginSettings {
	return PluginSettings{
		Enabled:                            true,
		AutoDiscover:                       true,
		IncludeNativeAntigravity:           true,
		AllowExplicitClientIdentityHeaders: true,
		PrincipalFallbackMode:              "client_key_hash",
		MatchMode:                          "any",
		HMACSecretSource:                   "env",
		ExecutorProvider:                   defaultExecutorProvider,
	}
}

// defaultExecutorProvider is the plugin-owned provider key. It must not be a
// key CLIProxyAPI already serves with a native executor, because the host skips
// plugin executors in that case.
const defaultExecutorProvider = "ln.Antigravity"

func normalizeSettings(s PluginSettings) PluginSettings {
	s.MatchMode = strings.ToLower(strings.TrimSpace(s.MatchMode))
	if s.MatchMode != "all" {
		s.MatchMode = "any"
	}
	s.PrincipalFallbackMode = strings.ToLower(strings.TrimSpace(s.PrincipalFallbackMode))
	switch s.PrincipalFallbackMode {
	case "", "client_key_hash":
		s.PrincipalFallbackMode = "client_key_hash"
	case "user_agent_plus_session":
	case "disabled":
	default:
		s.PrincipalFallbackMode = "client_key_hash"
	}
	s.HMACSecretSource = strings.ToLower(strings.TrimSpace(s.HMACSecretSource))
	if s.HMACSecretSource == "" {
		s.HMACSecretSource = "env"
	}
	switch s.HMACSecretSource {
	case "env", "config", "provider_api_key", "none":
	default:
		s.HMACSecretSource = "env"
	}
	s.MatchName = strings.TrimSpace(s.MatchName)
	s.MatchURL = strings.TrimSpace(s.MatchURL)
	s.MatchAPIKey = strings.TrimSpace(s.MatchAPIKey)
	s.MatchProvider = strings.TrimSpace(s.MatchProvider)
	s.MatchModel = strings.TrimSpace(s.MatchModel)
	s.HMACSecret = strings.TrimSpace(s.HMACSecret)
	s.Agy2apiIdentitySecret = strings.TrimSpace(s.Agy2apiIdentitySecret)

	seen := make(map[string]struct{}, len(s.MatchProviders)+1)
	providers := make([]string, 0, len(s.MatchProviders)+1)
	for _, value := range append(s.MatchProviders, s.MatchProvider) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		providers = append(providers, value)
	}
	s.MatchProviders = providers

	modelSeen := make(map[string]struct{}, len(s.MatchModels)+1)
	models := make([]string, 0, len(s.MatchModels)+1)
	for _, value := range append(s.MatchModels, s.MatchModel) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := modelSeen[key]; exists {
			continue
		}
		modelSeen[key] = struct{}{}
		models = append(models, value)
	}
	s.MatchModels = models

	s.ModelNamespace = strings.TrimSpace(s.ModelNamespace)
	s.ExecutorProvider = normalizeExecutorProviderKey(s.ExecutorProvider)
	if s.ExecutorProvider == "" {
		s.ExecutorProvider = defaultExecutorProvider
	}
	if !s.AllowExplicitClientIdentityHeaders {
		s.AllowExplicitClientIdentityHeaders = false
	} else {
		s.AllowExplicitClientIdentityHeaders = true
	}
	return s
}

// normalizeProviderKey keeps a provider key usable in model routing: no
// spaces, no path separators, lowercase.
func normalizeProviderKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			builder.WriteRune(r)
		case r == ' ' || r == '/' || r == '\\':
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

// normalizeExecutorProviderKey keeps the plugin-owned provider identifier
// stable when it is round-tripped through a UI or usage consumer. Some
// consumers combine the executor provider with its auth label; accepting a
// value such as "ln.Antigravity-ln.Antigravity" would make that duplication
// permanent and would also create a second executor key in CPA.
func normalizeExecutorProviderKey(value string) string {
	value = normalizeProviderKey(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "-")
	if len(parts) == 2 && strings.EqualFold(parts[0], parts[1]) {
		return parts[0]
	}
	return value
}

// decodePluginSettings is kept as a compatibility helper for tests and older
// callers. The lifecycle path uses loadPluginConfiguration so it can retain
// the config source and diagnostics metadata too.
func decodePluginSettings(configYAML []byte) PluginSettings {
	return loadPluginConfiguration(configYAML).Settings
}

func currentPluginSettings() PluginSettings {
	pluginSettingsMu.RLock()
	defer pluginSettingsMu.RUnlock()
	return pluginSettings
}

func currentConfigSnapshot() pluginConfigSnapshot {
	settings := currentPluginSettings()
	pluginConfigMu.RLock()
	defer pluginConfigMu.RUnlock()
	return pluginConfigSnapshot{
		Settings:          settings,
		ConfigYAML:        append([]byte(nil), pluginConfigYAML...),
		ConfigPath:        pluginConfigPath,
		ConfigPathFound:   pluginConfigPathFound,
		PluginConfigFound: pluginConfigFound,
		Warnings:          append([]string(nil), pluginConfigWarnings...),
	}
}

func applyPluginConfiguration(snapshot pluginConfigSnapshot) {
	pluginSettingsMu.Lock()
	pluginSettings = normalizeSettings(snapshot.Settings)
	pluginSettingsMu.Unlock()

	pluginConfigMu.Lock()
	pluginConfigYAML = append([]byte(nil), snapshot.ConfigYAML...)
	pluginConfigPath = snapshot.ConfigPath
	pluginConfigPathFound = snapshot.ConfigPathFound
	pluginConfigFound = snapshot.PluginConfigFound
	pluginConfigWarnings = append([]string(nil), snapshot.Warnings...)
	pluginConfigMu.Unlock()
}

// loadPluginConfiguration accepts all payload shapes seen in CPA versions:
// the full root config, the plugins subtree, the plugin subtree itself, and
// the legacy plugins.<plugin-id> form.
func loadPluginConfiguration(configYAML []byte) pluginConfigSnapshot {
	snapshot := pluginConfigSnapshot{Settings: defaultPluginSettings()}
	lifecycleRaw := append([]byte(nil), configYAML...)
	lifecycleRoot, lifecycleErr := parseYAMLMap(configYAML)
	if lifecycleErr != nil {
		snapshot.Warnings = append(snapshot.Warnings, "lifecycle config YAML could not be parsed")
	}

	if lifecycleRoot != nil {
		if cfg, found := findPluginConfig(lifecycleRoot); found {
			snapshot.Settings = settingsFromMap(snapshot.Settings, cfg)
			snapshot.PluginConfigFound = true
		}
	}

	fileRaw, filePath, fileFound := readConfigFile()
	snapshot.ConfigPath = filePath
	snapshot.ConfigPathFound = fileFound

	// The mounted config file is authoritative for provider discovery. It is
	// also a fallback when CPA sends only a trimmed plugin subtree.
	sourceRaw := lifecycleRaw
	if fileFound {
		fileRoot, errFile := parseYAMLMap(fileRaw)
		if errFile == nil {
			if cfg, found := findPluginConfig(fileRoot); found {
				if !snapshot.PluginConfigFound {
					snapshot.Settings = settingsFromMap(snapshot.Settings, cfg)
					snapshot.PluginConfigFound = true
				}
			}
			if hasConfigSection(lifecycleRoot, "openai-compatibility") ||
				hasConfigSection(lifecycleRoot, "openai_compatibility") {
				sourceRaw = lifecycleRaw
			} else {
				sourceRaw = fileRaw
			}
		} else {
			snapshot.Warnings = append(snapshot.Warnings, "mounted CPA config YAML could not be parsed")
		}
	}

	if len(sourceRaw) == 0 {
		sourceRaw = fileRaw
	}
	snapshot.ConfigYAML = append([]byte(nil), sourceRaw...)
	snapshot.Settings = normalizeSettings(snapshot.Settings)
	if lifecycleErr != nil && len(fileRaw) == 0 {
		snapshot.Warnings = append(snapshot.Warnings, lifecycleErr.Error())
	}
	return snapshot
}

// decodeConfigFile preserves the old helper signature while using the more
// tolerant config path and shape handling above.
func decodeConfigFile() (PluginSettings, bool) {
	raw, _, ok := readConfigFile()
	if !ok {
		return PluginSettings{}, false
	}
	snapshot := loadPluginConfiguration(raw)
	return snapshot.Settings, snapshot.PluginConfigFound
}

func readConfigFile() ([]byte, string, bool) {
	candidates := []string{
		os.Getenv("CPA_CONFIG_PATH"),
		"/CLIProxyAPI/config.yaml",
		"/cpa-config.yaml",
		"C:\\CLIProxyAPI\\config.yaml",
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		raw, errRead := os.ReadFile(candidate)
		if errRead == nil {
			return raw, candidate, true
		}
	}
	return nil, "", false
}

func parseYAMLMap(raw []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var value any
	if errUnmarshal := yaml.Unmarshal(raw, &value); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return asMap(value), nil
}

func findPluginConfig(root map[string]any) (map[string]any, bool) {
	if root == nil {
		return nil, false
	}

	if plugins, ok := mapValue(root, "plugins"); ok {
		if pluginMap := asMap(plugins); pluginMap != nil {
			if configs, ok := mapValue(pluginMap, "configs"); ok {
				if configMap := asMap(configs); configMap != nil {
					if cfg, found := mapValueByNormalizedKey(configMap, pluginID); found {
						if result := asMap(cfg); result != nil {
							return result, true
						}
					}
				}
			}
			if cfg, found := mapValueByNormalizedKey(pluginMap, pluginID); found {
				if result := asMap(cfg); result != nil {
					return result, true
				}
			}
		}
	}

	if configs, ok := mapValue(root, "configs"); ok {
		if configMap := asMap(configs); configMap != nil {
			if cfg, found := mapValueByNormalizedKey(configMap, pluginID); found {
				if result := asMap(cfg); result != nil {
					return result, true
				}
			}
		}
	}

	if cfg, found := mapValueByNormalizedKey(root, pluginID); found {
		if result := asMap(cfg); result != nil {
			return result, true
		}
	}

	// A direct plugin subtree has at least one plugin-owned key. Do not treat a
	// full CPA root containing unrelated global "enabled" as our config.
	for _, key := range []string{
		"enabled",
		"priority",
		"auto_discover",
		"include_native_antigravity",
		"allow_explicit_client_identity_headers",
		"principal_fallback_mode",
		"debug_logging",
		"match_mode",
		"match_name",
		"match_url",
		"match_api_key",
		"match_provider",
		"match_providers",
		"match_model",
		"match_models",
		"hmac_secret",
		"hmac_secret_source",
		"agy2api_identity_secret",
		"executor_enabled",
		"executor_provider",
		"model_namespace",
	} {
		if _, ok := mapValue(root, key); ok {
			return root, true
		}
	}
	return nil, false
}

func settingsFromMap(base PluginSettings, raw map[string]any) PluginSettings {
	if raw == nil {
		return normalizeSettings(base)
	}
	if value, ok := boolValue(raw, "enabled"); ok {
		base.Enabled = value
	}
	if value, ok := intValue(raw, "priority"); ok {
		base.Priority = value
	}
	if value, ok := boolValue(raw, "auto_discover", "auto-discover"); ok {
		base.AutoDiscover = value
	}
	if value, ok := boolValue(raw, "include_native_antigravity", "include-native-antigravity"); ok {
		base.IncludeNativeAntigravity = value
	}
	if value, ok := boolValue(raw, "allow_explicit_client_identity_headers", "allow-explicit-client-identity-headers"); ok {
		base.AllowExplicitClientIdentityHeaders = value
	}
	if value, ok := stringValue(raw, "principal_fallback_mode", "principal-fallback-mode"); ok {
		base.PrincipalFallbackMode = value
	}
	if value, ok := boolValue(raw, "debug_logging", "debug-logging"); ok {
		base.DebugLogging = value
	}
	if value, ok := stringValue(raw, "match_mode", "match-mode"); ok {
		base.MatchMode = value
	}
	if value, ok := stringValue(raw, "match_name", "match-name"); ok {
		base.MatchName = value
	}
	if value, ok := stringValue(raw, "match_url", "match-url", "base_url", "base-url"); ok {
		base.MatchURL = value
	}
	if value, ok := stringValue(raw, "match_api_key", "match-api-key", "api_key", "api-key"); ok {
		base.MatchAPIKey = value
	}
	if value, ok := stringValue(raw, "match_provider", "match-provider"); ok {
		base.MatchProvider = value
	}
	if values, ok := stringSliceValue(raw, "match_providers", "match-providers"); ok {
		base.MatchProviders = values
	}
	if value, ok := stringValue(raw, "match_model", "match-model"); ok {
		base.MatchModel = value
	}
	if values, ok := stringSliceValue(raw, "match_models", "match-models"); ok {
		base.MatchModels = values
	}
	if value, ok := stringValue(raw, "hmac_secret", "hmac-secret"); ok {
		base.HMACSecret = value
	}
	if value, ok := stringValue(raw, "hmac_secret_source", "hmac-secret-source"); ok {
		base.HMACSecretSource = value
	}
	if value, ok := stringValue(raw, "agy2api_identity_secret", "agy2api-identity-secret"); ok {
		base.Agy2apiIdentitySecret = value
	}
	if value, ok := boolValue(raw, "executor_enabled", "executor-enabled"); ok {
		base.ExecutorEnabled = value
	}
	if value, ok := stringValue(raw, "executor_provider", "executor-provider"); ok {
		base.ExecutorProvider = value
	}
	if value, ok := stringValue(raw, "model_namespace", "model-namespace"); ok {
		base.ModelNamespace = value
	}
	return normalizeSettings(base)
}

func hasConfigSection(root map[string]any, key string) bool {
	_, ok := mapValue(root, key)
	return ok
}

func normalizedMapKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("-", "", "_", "", " ", "").Replace(value)
	return value
}

func mapValue(raw map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := mapValueByNormalizedKey(raw, key); ok {
			return value, true
		}
	}
	return nil, false
}

func mapValueByNormalizedKey(raw map[string]any, wanted string) (any, bool) {
	if raw == nil {
		return nil, false
	}
	target := normalizedMapKey(wanted)
	for key, value := range raw {
		if normalizedMapKey(key) == target {
			return value, true
		}
	}
	return nil, false
}

func asMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if text, ok := key.(string); ok {
				out[text] = item
			}
		}
		return out
	default:
		return nil
	}
}

func asSlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	default:
		return nil
	}
}

func stringValue(raw map[string]any, keys ...string) (string, bool) {
	value, ok := mapValue(raw, keys...)
	if !ok {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed), true
	default:
		return "", false
	}
}

func boolValue(raw map[string]any, keys ...string) (bool, bool) {
	value, ok := mapValue(raw, keys...)
	if !ok {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "on", "1":
			return true, true
		case "false", "no", "off", "0":
			return false, true
		}
	}
	return false, false
}

func intValue(raw map[string]any, keys ...string) (int, bool) {
	value, ok := mapValue(raw, keys...)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case string:
		var parsed int
		if _, err := fmt.Sscanf(strings.TrimSpace(typed), "%d", &parsed); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func stringSliceValue(raw map[string]any, keys ...string) ([]string, bool) {
	value, ok := mapValue(raw, keys...)
	if !ok {
		return nil, false
	}
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out, true
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				out = append(out, strings.TrimSpace(item))
			}
		}
		return out, true
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil, true
		}
		return []string{strings.TrimSpace(typed)}, true
	default:
		return nil, false
	}
}

// hmacSecret returns the HMAC signing key, resolved in priority order:
//  1. agy2api_identity_secret (dedicated plugin config field)
//  2. hmac_secret (legacy plugin config field)
//  3. AGY_PLUGIN_SECRET environment variable (CPA container env)
//  4. provider_api_key (only when hmac_secret_source=provider_api_key, resolved
//     per candidate in hmacSecretForCandidate)
//  5. empty, which leaves requests unsigned. agy2api rejects unsigned requests,
//     so an empty result with executor mode on is a configuration error the
//     status page surfaces.
func (s PluginSettings) hmacSecret() string {
	if s.Agy2apiIdentitySecret != "" {
		return s.Agy2apiIdentitySecret
	}
	if s.HMACSecret != "" {
		return s.HMACSecret
	}
	if value := strings.TrimSpace(os.Getenv("AGY_PLUGIN_SECRET")); value != "" {
		return value
	}
	return ""
}

// hmacSecretSource reports which entry in the priority chain will actually
// sign, for diagnostics. provider_api_key mode only applies when no stronger
// source is configured, because the dedicated and config secrets are static
// and safer than reusing the upstream provider key.
func (s PluginSettings) hmacSecretSource() string {
	if s.Agy2apiIdentitySecret != "" {
		return "agy2api_identity_secret"
	}
	if s.HMACSecret != "" {
		return "config"
	}
	if strings.TrimSpace(os.Getenv("AGY_PLUGIN_SECRET")) != "" {
		return "env"
	}
	if s.HMACSecretSource == "provider_api_key" {
		return "provider_api_key"
	}
	return "none"
}

func (s PluginSettings) shouldIntercept(providerName, providerURL string) bool {
	candidate := providerCandidate{
		Name: providerName,
		URL:  providerURL,
	}
	matched, _ := s.shouldInterceptCandidate(candidate)
	return matched
}

func (s PluginSettings) shouldInterceptCandidate(candidate providerCandidate) (bool, []string) {
	s = normalizeSettings(s)
	nameValues := []string{candidate.Name, candidate.ProviderKey, candidate.ToFormat}
	modelValues := []string{candidate.RequestedModel, candidate.Model}
	criteriaCount := 0
	matchedCount := 0
	matchedBy := make([]string, 0, 4)

	if s.MatchName != "" {
		criteriaCount++
		if anyTextMatch([]string{s.MatchName}, nameValues) {
			matchedCount++
			matchedBy = append(matchedBy, "name")
		}
	}
	for _, pattern := range s.MatchProviders {
		criteriaCount++
		if anyTextMatch([]string{pattern}, nameValues) {
			matchedCount++
			matchedBy = append(matchedBy, "provider")
		}
	}
	if s.MatchURL != "" {
		criteriaCount++
		if matchText(s.MatchURL, candidate.URL) {
			matchedCount++
			matchedBy = append(matchedBy, "url")
		}
	}
	if s.MatchAPIKey != "" {
		criteriaCount++
		if constantTimeEqual(s.MatchAPIKey, candidate.APIKey) {
			matchedCount++
			matchedBy = append(matchedBy, "api_key")
		}
	}
	for _, pattern := range s.MatchModels {
		criteriaCount++
		if anyTextMatch([]string{pattern}, modelValues) {
			matchedCount++
			matchedBy = append(matchedBy, "model")
		}
	}

	if criteriaCount == 0 {
		if !s.AutoDiscover {
			return false, nil
		}
		if candidate.Native {
			if !s.IncludeNativeAntigravity {
				return false, nil
			}
			return true, []string{"native-antigravity"}
		}
		// CLIProxyAPI does not expose the provider name or base URL to the
		// after-auth interceptor for OpenAI-compatible providers, so the model
		// prefix resolved back to a matching config provider is the reliable
		// signal for auto discovery.
		if candidate.ResolvedPrefix != "" {
			return true, []string{"model-prefix:" + candidate.ResolvedPrefix}
		}
		if anyTextMatch([]string{"*antigravity*", "*agy2api*"}, nameValues) ||
			matchText("*antigravity*", candidate.URL) ||
			matchText("*agy2api*", candidate.URL) {
			return true, []string{"auto-discovery"}
		}
		return false, nil
	}

	if s.MatchMode == "all" {
		return matchedCount == criteriaCount, uniqueStrings(matchedBy)
	}
	return matchedCount > 0, uniqueStrings(matchedBy)
}

func (s PluginSettings) configuredSelectorCount() int {
	s = normalizeSettings(s)
	count := 0
	if s.MatchName != "" {
		count++
	}
	if s.MatchURL != "" {
		count++
	}
	if s.MatchAPIKey != "" {
		count++
	}
	count += len(s.MatchProviders)
	count += len(s.MatchModels)
	return count
}

func anyTextMatch(patterns, values []string) bool {
	for _, pattern := range patterns {
		for _, value := range values {
			if matchText(pattern, value) {
				return true
			}
		}
	}
	return false
}

func matchText(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" || value == "" {
		return false
	}
	if !strings.ContainsAny(pattern, "*?") {
		return strings.Contains(value, pattern)
	}

	// Simple glob matcher. It intentionally supports only '*' and '?' so
	// provider matching cannot become a regular-expression injection surface.
	p := []rune(pattern)
	v := []rune(value)
	dp := make([][]bool, len(p)+1)
	for i := range dp {
		dp[i] = make([]bool, len(v)+1)
	}
	dp[0][0] = true
	for i := 1; i <= len(p); i++ {
		if p[i-1] == '*' {
			dp[i][0] = dp[i-1][0]
		}
		for j := 1; j <= len(v); j++ {
			switch p[i-1] {
			case '*':
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			case '?':
				dp[i][j] = dp[i-1][j-1]
			default:
				dp[i][j] = dp[i-1][j-1] && p[i-1] == v[j-1]
			}
		}
	}
	return dp[len(p)][len(v)]
}

func constantTimeEqual(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func providerNameMatchesAutoDiscovery(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "antigravity") || strings.Contains(value, "agy2api")
}

func isNativeAntigravity(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "antigravity")
}

func configBaseName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
