package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type providerCandidate struct {
	Name        string
	ProviderKey string
	URL         string
	APIKey      string
	ToFormat    string
	AuthID      string
	Native      bool
}

type discoveredProvider struct {
	Name        string
	Label       string
	ProviderKey string
	URL         string
	Source      string
	AuthIndex   string
	Active      bool
	Disabled    bool
	Native      bool
	APIKeys     []string
}

type providerStatus struct {
	Name             string   `json:"name"`
	Label            string   `json:"label,omitempty"`
	ProviderKey      string   `json:"provider_key,omitempty"`
	URL              string   `json:"url,omitempty"`
	Source           string   `json:"source"`
	AuthIndex        string   `json:"auth_index,omitempty"`
	Native           bool     `json:"native"`
	Active           bool     `json:"active"`
	Disabled         bool     `json:"disabled"`
	Matched          bool     `json:"matched"`
	APIKeyConfigured bool     `json:"api_key_configured"`
	APIKeyCount      int      `json:"api_key_count,omitempty"`
	MatchedBy        []string `json:"matched_by"`
}

type providerDiagnostics struct {
	Version                  string           `json:"version"`
	Enabled                  bool             `json:"enabled"`
	Priority                 int              `json:"priority"`
	AutoDiscover             bool             `json:"auto_discover"`
	IncludeNativeAntigravity bool             `json:"include_native_antigravity"`
	MatchMode                string           `json:"match_mode"`
	MatchName                string           `json:"match_name,omitempty"`
	MatchURL                 string           `json:"match_url,omitempty"`
	MatchAPIKeyConfigured    bool             `json:"match_api_key_configured"`
	MatchProvider            string           `json:"match_provider,omitempty"`
	MatchProviders           []string         `json:"match_providers,omitempty"`
	ConfiguredSelectorCount  int              `json:"configured_selector_count"`
	HMACSecretConfigured     bool             `json:"hmac_secret_configured"`
	HMACSecretSource         string           `json:"hmac_secret_source"`
	ConfigPathFound          bool             `json:"config_path_found"`
	ConfigPath               string           `json:"config_path,omitempty"`
	PluginConfigFound        bool             `json:"plugin_config_found"`
	ScannedRecordCount       int              `json:"scanned_record_count"`
	ConfiguredRecordCount    int              `json:"configured_record_count"`
	RuntimeRecordCount       int              `json:"runtime_record_count"`
	RuntimeAuthCount         int              `json:"runtime_auth_count"`
	MatchedRecordCount       int              `json:"matched_record_count"`
	MatchedProviderCount     int              `json:"matched_provider_count"`
	UnmatchedRecordCount     int              `json:"unmatched_record_count"`
	LastScanAt               string           `json:"last_scan_at,omitempty"`
	ScannedProviders         []providerStatus `json:"scanned_providers,omitempty"`
	Providers                []providerStatus `json:"providers"`
	InterceptCount           uint64           `json:"intercept_count"`
	LastInterceptAt          string           `json:"last_intercept_at,omitempty"`
	LastInterceptProvider    string           `json:"last_intercept_provider,omitempty"`
	Warnings                 []string         `json:"warnings"`
}

var interceptState struct {
	sync.RWMutex
	count    uint64
	lastAt   time.Time
	lastName string
}

func candidateFromPayload(payload InterceptRequestPayload) providerCandidate {
	candidate := providerCandidate{
		ToFormat: strings.TrimSpace(payload.ToFormat),
	}
	if payload.Metadata != nil {
		candidate.Name = metadataString(payload.Metadata,
			"provider_name", "provider-name", "provider", "auth_provider", "auth-provider",
			"compat_name", "compat-name")
		candidate.ProviderKey = metadataString(payload.Metadata,
			"provider_key", "provider-key", "compat_name", "compat-name")
		candidate.URL = metadataString(payload.Metadata,
			"base_url", "base-url", "provider_url", "provider-url", "url")
		candidate.APIKey = metadataString(payload.Metadata,
			"api_key", "api-key", "upstream_api_key", "upstream-api-key")
		candidate.AuthID = metadataString(payload.Metadata,
			"selected_auth_id", "selected-auth-id", "auth_id", "auth-id")
	}

	if candidate.Name == "" {
		candidate.Name = firstHeaderValue(payload.Headers,
			"X-Provider-Name", "X-AGY-Provider-Name", "X-Auth-Provider")
	}
	if candidate.ProviderKey == "" {
		candidate.ProviderKey = firstHeaderValue(payload.Headers,
			"X-Provider-Key", "X-AGY-Provider-Key")
	}
	if candidate.URL == "" {
		candidate.URL = firstHeaderValue(payload.Headers,
			"X-Provider-Base-URL", "X-Provider-URL", "X-AGY-Provider-URL")
	}
	if candidate.APIKey == "" {
		// After-auth requests normally carry the selected upstream key here.
		// It is used only for constant-time matching/signing and is never
		// returned in diagnostics.
		candidate.APIKey = extractBearerToken(payload.Headers)
	}
	if candidate.Name == "" {
		candidate.Name = candidate.ProviderKey
	}
	if candidate.Name == "" {
		candidate.Name = candidate.ToFormat
	}
	candidate.Native = isNativeAntigravity(candidate.ToFormat) ||
		isNativeAntigravity(candidate.Name) ||
		isNativeAntigravity(candidate.ProviderKey)
	return candidate
}

func metadataString(metadata map[string]any, keys ...string) string {
	if value, ok := mapValue(metadata, keys...); ok {
		switch typed := value.(type) {
		case string:
			return strings.TrimSpace(typed)
		case fmt.Stringer:
			return strings.TrimSpace(typed.String())
		}
	}
	for _, nestedKey := range []string{"provider", "auth", "selected_auth", "selected-auth"} {
		if nested, ok := mapValue(metadata, nestedKey); ok {
			if nestedMap := asMap(nested); nestedMap != nil {
				if value := metadataString(nestedMap, keys...); value != "" {
					return value
				}
			}
		}
	}
	return ""
}

func firstHeaderValue(headers map[string][]string, keys ...string) string {
	for key, values := range headers {
		for _, wanted := range keys {
			if strings.EqualFold(key, wanted) && len(values) > 0 {
				return strings.TrimSpace(values[0])
			}
		}
	}
	return ""
}

func hmacSecretForCandidate(settings PluginSettings, candidate providerCandidate) string {
	if settings.HMACSecretSource == "provider_api_key" {
		return strings.TrimSpace(candidate.APIKey)
	}
	return settings.hmacSecret()
}

func recordIntercept(candidate providerCandidate) {
	interceptState.Lock()
	interceptState.count++
	interceptState.lastAt = time.Now().UTC()
	interceptState.lastName = displayProviderName(candidate.Name, candidate.ProviderKey, candidate.ToFormat)
	interceptState.Unlock()
}

func scanProviderDiagnostics() providerDiagnostics {
	snapshot := currentConfigSnapshot()
	settings := normalizeSettings(snapshot.Settings)
	out := providerDiagnostics{
		Version:                  pluginVersion,
		Enabled:                  settings.Enabled,
		Priority:                 settings.Priority,
		AutoDiscover:             settings.AutoDiscover,
		IncludeNativeAntigravity: settings.IncludeNativeAntigravity,
		MatchMode:                settings.MatchMode,
		MatchName:                settings.MatchName,
		MatchURL:                 redactURL(settings.MatchURL),
		MatchAPIKeyConfigured:    settings.MatchAPIKey != "",
		MatchProvider:            settings.MatchProvider,
		MatchProviders:           append([]string(nil), settings.MatchProviders...),
		ConfiguredSelectorCount:  settings.configuredSelectorCount(),
		HMACSecretConfigured:     settings.hmacSecret() != "",
		HMACSecretSource:         settings.hmacSecretSource(),
		ConfigPathFound:          snapshot.ConfigPathFound,
		ConfigPath:               snapshot.ConfigPath,
		PluginConfigFound:        snapshot.PluginConfigFound,
		Providers:                []providerStatus{},
		ScannedProviders:         []providerStatus{},
		Warnings:                 append([]string(nil), snapshot.Warnings...),
	}

	var discovered []discoveredProvider
	if len(snapshot.ConfigYAML) > 0 {
		root, errParse := parseYAMLMap(snapshot.ConfigYAML)
		if errParse != nil {
			out.Warnings = append(out.Warnings, "provider config scan could not parse YAML")
		} else {
			discovered = append(discovered, discoverOpenAICompatibility(root)...)
		}
	}

	runtimeAuths, errAuth := listHostAuthFiles()
	if errAuth != nil {
		// A plugin can still match configured openai-compatibility providers
		// without the optional host auth callback.
		out.Warnings = append(out.Warnings, "runtime auth scan unavailable: "+errAuth.Error())
	} else {
		out.RuntimeAuthCount = len(runtimeAuths)
		runtimeProviders, warnings := discoverRuntimeAuths(runtimeAuths)
		discovered = append(discovered, runtimeProviders...)
		out.Warnings = append(out.Warnings, warnings...)
	}

	out.ScannedRecordCount = len(discovered)
	matchedKeys := make(map[string]struct{})
	for _, item := range discovered {
		switch item.Source {
		case "openai-compatibility":
			out.ConfiguredRecordCount++
		case "runtime-auth":
			out.RuntimeRecordCount++
		}
		matched, matchedBy := matchDiscoveredProvider(settings, item)
		status := providerStatus{
			Name:             displayProviderName(item.Name, item.ProviderKey, ""),
			Label:            item.Label,
			ProviderKey:      item.ProviderKey,
			URL:              redactURL(item.URL),
			Source:           item.Source,
			AuthIndex:        item.AuthIndex,
			Native:           item.Native,
			Active:           item.Active && !item.Disabled,
			Disabled:         item.Disabled,
			Matched:          matched,
			APIKeyConfigured: len(item.APIKeys) > 0,
			APIKeyCount:      len(item.APIKeys),
			MatchedBy:        matchedBy,
		}
		out.ScannedProviders = append(out.ScannedProviders, status)
		if !matched {
			out.UnmatchedRecordCount++
			continue
		}
		out.MatchedRecordCount++
		key := providerIdentityKey(item)
		matchedKeys[key] = struct{}{}
		out.Providers = append(out.Providers, status)
	}
	out.MatchedProviderCount = len(matchedKeys)

	sortProviderStatuses := func(values []providerStatus) {
		sort.SliceStable(values, func(i, j int) bool {
			left := strings.ToLower(values[i].Name + "\x00" + values[i].Source + "\x00" + values[i].ProviderKey)
			right := strings.ToLower(values[j].Name + "\x00" + values[j].Source + "\x00" + values[j].ProviderKey)
			return left < right
		})
	}
	sortProviderStatuses(out.Providers)
	sortProviderStatuses(out.ScannedProviders)
	out.LastScanAt = time.Now().UTC().Format(time.RFC3339)

	if settings.HMACSecretSource == "provider_api_key" && out.MatchedRecordCount > 0 {
		for _, item := range out.Providers {
			if item.APIKeyConfigured {
				out.HMACSecretConfigured = true
				break
			}
		}
	}

	if settings.MatchAPIKey != "" {
		for _, item := range discovered {
			if item.Native && len(item.APIKeys) == 0 {
				out.Warnings = append(out.Warnings,
					"match_api_key is configured, but native OAuth Antigravity auth has no API key to compare")
				break
			}
		}
	}
	if out.MatchedRecordCount == 0 && out.ScannedRecordCount > 0 {
		out.Warnings = append(out.Warnings,
			"no scanned provider matches the current plugin rules")
	}
	if out.ScannedRecordCount == 0 {
		out.Warnings = append(out.Warnings,
			"no provider records were discovered; verify the mounted CPA config and runtime auth list")
	}

	interceptState.RLock()
	out.InterceptCount = interceptState.count
	if !interceptState.lastAt.IsZero() {
		out.LastInterceptAt = interceptState.lastAt.Format(time.RFC3339)
	}
	out.LastInterceptProvider = interceptState.lastName
	interceptState.RUnlock()
	out.Warnings = uniqueStrings(out.Warnings)
	return out
}

func discoverOpenAICompatibility(root map[string]any) []discoveredProvider {
	if root == nil {
		return nil
	}
	raw, ok := mapValue(root, "openai-compatibility", "openai_compatibility")
	if !ok {
		return nil
	}
	entries := asSlice(raw)
	out := make([]discoveredProvider, 0, len(entries))
	for _, item := range entries {
		providerMap := asMap(item)
		if providerMap == nil {
			continue
		}
		name, _ := stringValue(providerMap, "name")
		baseURL, _ := stringValue(providerMap, "base-url", "base_url", "url")
		disabled, _ := boolValue(providerMap, "disabled")
		providerKey := name
		apiKeys := make([]string, 0)
		if rawKeys, exists := mapValue(providerMap, "api-key-entries", "api_key_entries"); exists {
			for _, rawKey := range asSlice(rawKeys) {
				keyMap := asMap(rawKey)
				if keyMap == nil {
					continue
				}
				if key, ok := stringValue(keyMap, "api-key", "api_key", "key"); ok && key != "" {
					apiKeys = append(apiKeys, key)
				}
			}
		}
		// A provider with no key entries is still a meaningful record: it
		// tells the operator that the provider exists but has no API key.
		out = append(out, discoveredProvider{
			Name:        name,
			ProviderKey: providerKey,
			URL:         baseURL,
			Source:      "openai-compatibility",
			Active:      !disabled,
			Disabled:    disabled,
			APIKeys:     uniqueStrings(apiKeys),
		})
	}
	return out
}

func discoverRuntimeAuths(entries []pluginapi.HostAuthFileEntry) ([]discoveredProvider, []string) {
	out := make([]discoveredProvider, 0, len(entries))
	warnings := make([]string, 0)
	for _, entry := range entries {
		provider := strings.TrimSpace(entry.Provider)
		if provider == "" {
			provider = strings.TrimSpace(entry.Type)
		}
		name := displayProviderName(provider, entry.Label, entry.Name)
		item := discoveredProvider{
			Name:        name,
			Label:       strings.TrimSpace(entry.Label),
			ProviderKey: provider,
			Source:      "runtime-auth",
			AuthIndex:   strings.TrimSpace(entry.AuthIndex),
			Active: !entry.Disabled && !entry.Unavailable &&
				!strings.EqualFold(strings.TrimSpace(entry.Status), "disabled"),
			Disabled: entry.Disabled || entry.Unavailable,
			Native:   isNativeAntigravity(provider) || isNativeAntigravity(entry.Type),
		}

		authIndex := item.AuthIndex
		if authIndex == "" {
			authIndex = strings.TrimSpace(entry.ID)
		}
		if authIndex != "" {
			raw, errGet := getHostAuthJSON(authIndex)
			if errGet == nil {
				if baseURL, ok := stringValue(raw, "base_url", "base-url", "url"); ok {
					item.URL = baseURL
				}
				if key, ok := stringValue(raw, "api_key", "api-key"); ok && key != "" {
					item.APIKeys = []string{key}
				}
				if rawProvider, ok := stringValue(raw, "provider", "type"); ok {
					item.Native = item.Native || isNativeAntigravity(rawProvider)
					if item.ProviderKey == "" {
						item.ProviderKey = rawProvider
					}
				}
			} else if item.Native {
				warnings = append(warnings, "native auth details unavailable")
			}
		}
		out = append(out, item)
	}
	return out, warnings
}

func matchDiscoveredProvider(settings PluginSettings, item discoveredProvider) (bool, []string) {
	candidates := make([]providerCandidate, 0, maxInt(1, len(item.APIKeys)))
	if len(item.APIKeys) == 0 {
		candidates = append(candidates, providerCandidate{
			Name:        item.Name,
			ProviderKey: item.ProviderKey,
			URL:         item.URL,
			Native:      item.Native,
		})
	} else {
		for _, key := range item.APIKeys {
			candidates = append(candidates, providerCandidate{
				Name:        item.Name,
				ProviderKey: item.ProviderKey,
				URL:         item.URL,
				APIKey:      key,
				Native:      item.Native,
			})
		}
	}
	for _, candidate := range candidates {
		if matched, matchedBy := settings.shouldInterceptCandidate(candidate); matched {
			return true, matchedBy
		}
	}
	return false, nil
}

func providerIdentityKey(item discoveredProvider) string {
	key := strings.ToLower(strings.TrimSpace(item.ProviderKey))
	if key != "" {
		return key
	}
	name := strings.ToLower(strings.TrimSpace(item.Name))
	if name != "" {
		return name
	}
	return strings.ToLower(strings.TrimSpace(redactURL(item.URL)))
}

func displayProviderName(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return "unknown"
}

func redactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, errParse := url.Parse(raw); errParse == nil {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return strings.TrimRight(parsed.String(), "/")
	}
	if index := strings.IndexAny(raw, "?#"); index >= 0 {
		raw = raw[:index]
	}
	return strings.TrimRight(raw, "/")
}

func publicProviderDiagnostics(in providerDiagnostics) providerDiagnostics {
	out := in
	out.ConfigPath = ""
	out.MatchName = ""
	out.MatchURL = ""
	out.MatchProvider = ""
	out.MatchProviders = nil
	out.MatchAPIKeyConfigured = in.MatchAPIKeyConfigured
	out.HMACSecretConfigured = in.HMACSecretConfigured
	out.ConfigPathFound = false
	out.ScannedProviders = nil
	out.Providers = make([]providerStatus, 0, len(in.Providers))
	for _, item := range in.Providers {
		// CPA serves resource routes without management authentication, so
		// anything that can identify an operator account must be dropped here.
		// Auth labels are account emails for native Antigravity credentials.
		item.URL = ""
		item.AuthIndex = ""
		item.Label = ""
		out.Providers = append(out.Providers, item)
	}
	return out
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func jsonObject(value any) []byte {
	raw, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return []byte(`{"error":"serialization failed"}`)
	}
	return raw
}
