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
	Name           string
	ProviderKey    string
	URL            string
	APIKey         string
	ToFormat       string
	AuthID         string
	Model          string
	RequestedModel string
	ResolvedPrefix string
	ClientToken    string
	Native         bool
}

type discoveredProvider struct {
	Name        string
	Label       string
	ProviderKey string
	URL         string
	Prefix      string
	Source      string
	AuthIndex   string
	Active      bool
	Disabled    bool
	Native      bool
	APIKeys     []string
}

// matchedProviderRecord is the runtime view of a provider the plugin decided it
// owns. CLIProxyAPI only tells the interceptor which model was requested, so
// the provider prefix is what maps a live request back to its config record.
type matchedProviderRecord struct {
	Name   string
	Prefix string
	URL    string
	APIKey string
}

var matchedRecords struct {
	sync.RWMutex
	items []matchedProviderRecord
}

func refreshMatchedRecords(items []matchedProviderRecord) {
	matchedRecords.Lock()
	matchedRecords.items = items
	matchedRecords.Unlock()
}

func currentMatchedRecords() []matchedProviderRecord {
	matchedRecords.RLock()
	defer matchedRecords.RUnlock()
	return append([]matchedProviderRecord(nil), matchedRecords.items...)
}

// resolveRecordByModel maps a requested model such as "agy/gemini-pro" back to
// the config provider that owns the "agy" prefix. The longest prefix wins so a
// nested prefix stays with the more specific provider.
func resolveRecordByModel(models ...string) (matchedProviderRecord, bool) {
	records := currentMatchedRecords()
	if len(records) == 0 {
		return matchedProviderRecord{}, false
	}
	for _, model := range models {
		model = strings.ToLower(strings.TrimSpace(model))
		if model == "" {
			continue
		}
		var best matchedProviderRecord
		bestLen := -1
		for _, record := range records {
			prefix := strings.ToLower(strings.TrimSpace(record.Prefix))
			if prefix == "" {
				continue
			}
			if strings.HasPrefix(model, prefix+"/") && len(prefix) > bestLen {
				best = record
				bestLen = len(prefix)
			}
		}
		if bestLen > 0 {
			return best, true
		}
	}
	return matchedProviderRecord{}, false
}

type providerStatus struct {
	Name             string   `json:"name"`
	Label            string   `json:"label,omitempty"`
	ProviderKey      string   `json:"provider_key,omitempty"`
	URL              string   `json:"url,omitempty"`
	Prefix           string   `json:"prefix,omitempty"`
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
	MatchModel               string           `json:"match_model,omitempty"`
	MatchModels              []string         `json:"match_models,omitempty"`
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
	MirroredProvider         string           `json:"mirrored_provider,omitempty"`
	MirroredModelCount       int              `json:"mirrored_model_count"`
	MirroredHasAPIKey        bool             `json:"mirrored_has_api_key"`
	MirroredBaseURL          string           `json:"mirrored_base_url,omitempty"`
	ExecutorEnabled          bool             `json:"executor_enabled"`
	ExecutorProvider         string           `json:"executor_provider"`
	ModelNamespace           string           `json:"model_namespace,omitempty"`
	MirroredProviderEnabled  bool             `json:"mirrored_provider_enabled"`
	ReplacementMode          string           `json:"replacement_mode,omitempty"`
	ProviderOriginalEnabled  bool             `json:"provider_original_enabled"`
	Agy2apiSecretConfigured  bool             `json:"agy2api_identity_secret_configured"`
	ModelsServed             bool             `json:"models_served"`
	LastExecutorStatus       int              `json:"last_executor_status,omitempty"`
	LastExecutorErrorAt      string           `json:"last_executor_error_at,omitempty"`
	InterceptCount           uint64           `json:"intercept_count"`
	LastInterceptAt          string           `json:"last_intercept_at,omitempty"`
	LastInterceptProvider    string           `json:"last_intercept_provider,omitempty"`
	ActivePrefixes           []string         `json:"active_prefixes,omitempty"`
	Warnings                 []string         `json:"warnings"`
}

var interceptState struct {
	sync.RWMutex
	count    uint64
	lastAt   time.Time
	lastName string
}

// executorRuntimeState tracks the most recent executor upstream response so
// diagnostics can flag a signature mismatch (agy2api configured with a
// different AGY_IDENTITY_BRIDGE_SECRET) instead of leaving the operator to
// guess why requests fail with 401.
var executorRuntimeState struct {
	sync.Mutex
	lastStatus int
	lastAt     time.Time
}

func recordExecutorUpstreamStatus(status int) {
	executorRuntimeState.Lock()
	executorRuntimeState.lastStatus = status
	executorRuntimeState.lastAt = time.Now().UTC()
	executorRuntimeState.Unlock()
}

func candidateFromPayload(payload InterceptRequestPayload, settings PluginSettings) providerCandidate {
	candidate := providerCandidate{
		ToFormat:       strings.TrimSpace(payload.ToFormat),
		Model:          strings.TrimSpace(payload.Model),
		RequestedModel: strings.TrimSpace(payload.RequestedModel),
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
		// The Authorization header at this point still holds the *client* key,
		// not the upstream credential, so it must never be treated as a
		// provider API key for matching or signing.
		candidate.ClientToken = extractBearerToken(payload.Headers)
	}

	// CLIProxyAPI does not expose provider identity to the after-auth
	// interceptor for OpenAI-compatible providers. Resolving the requested
	// model prefix back to the config record that owns it is what makes
	// per-provider matching and signing possible at request time.
	// Native means the request is served by CPA's own Antigravity executor,
	// which is only ever visible through ToFormat. Deriving it from a config
	// display name would misclassify an OpenAI-compatible provider that happens
	// to be called Antigravity.
	candidate.Native = isNativeAntigravity(candidate.ToFormat)
	if record, ok := resolveRecordByModel(candidate.RequestedModel, candidate.Model); ok {
		candidate.ResolvedPrefix = record.Prefix
		if candidate.Name == "" {
			candidate.Name = record.Name
		}
		if candidate.ProviderKey == "" {
			candidate.ProviderKey = record.Name
		}
		if candidate.URL == "" {
			candidate.URL = record.URL
		}
		if candidate.APIKey == "" {
			candidate.APIKey = record.APIKey
		}
	}
	if candidate.Name == "" {
		candidate.Name = candidate.ProviderKey
	}
	if candidate.Name == "" {
		candidate.Name = candidate.ToFormat
	}
	if candidate.ResolvedPrefix == "" {
		candidate.Native = candidate.Native ||
			isNativeAntigravity(candidate.Name) ||
			isNativeAntigravity(candidate.ProviderKey)
	}
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
	if settings.Agy2apiIdentitySecret != "" {
		return settings.Agy2apiIdentitySecret
	}
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
		MatchModel:               settings.MatchModel,
		MatchModels:              append([]string(nil), settings.MatchModels...),
		ConfiguredSelectorCount:  settings.configuredSelectorCount(),
		HMACSecretConfigured:     settings.hmacSecret() != "",
		HMACSecretSource:         settings.hmacSecretSource(),
		ConfigPathFound:          snapshot.ConfigPathFound,
		ConfigPath:               snapshot.ConfigPath,
		PluginConfigFound:        snapshot.PluginConfigFound,
		Providers:                []providerStatus{},
		ScannedProviders:         []providerStatus{},
		ExecutorEnabled:          settings.ExecutorEnabled,
		ExecutorProvider:         settings.ExecutorProvider,
		ModelNamespace:           settings.ModelNamespace,
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
	matchedRecordsSeen := make(map[string]matchedProviderRecord)
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
			Prefix:           item.Prefix,
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
		if item.Source == "openai-compatibility" && len(item.APIKeys) > 0 {
			for _, apiKey := range item.APIKeys {
				record := matchedProviderRecord{
					Name:   status.Name,
					Prefix: item.Prefix,
					URL:    item.URL,
					APIKey: apiKey,
				}
				matchedRecordsSeen[strings.ToLower(record.Prefix)+"\x00"+apiKey] = record
			}
		} else if item.Source == "openai-compatibility" {
			matchedRecordsSeen[strings.ToLower(item.Prefix)+"\x00"] = matchedProviderRecord{
				Name:   status.Name,
				Prefix: item.Prefix,
				URL:    item.URL,
			}
		}
	}
	out.MatchedProviderCount = len(matchedKeys)

	records := make([]matchedProviderRecord, 0, len(matchedRecordsSeen))
	for _, record := range matchedRecordsSeen {
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool {
		return strings.ToLower(records[i].Prefix) < strings.ToLower(records[j].Prefix)
	})
	refreshMatchedRecords(records)
	prefixes := make([]string, 0, len(records))
	for _, record := range records {
		if record.Prefix == "" {
			out.Warnings = append(out.Warnings,
				"matched provider "+record.Name+" has no prefix, so live requests to it cannot be identified by model prefix")
			continue
		}
		prefixes = append(prefixes, record.Prefix)
	}
	out.ActivePrefixes = uniqueStrings(prefixes)

	if spec, mirrored := resolveProviderSpec(); mirrored {
		out.MirroredProvider = spec.Name
		out.MirroredBaseURL = redactURL(spec.BaseURL)
		out.MirroredHasAPIKey = spec.primaryAPIKey() != ""
		out.MirroredProviderEnabled = spec.Enabled
		out.ProviderOriginalEnabled = spec.Enabled
		out.MirroredModelCount = len(spec.modelInfos(settings.ModelNamespace))
		out.ModelsServed = canServeModels(settings, spec)
		switch {
		case strings.TrimSpace(settings.ModelNamespace) != "":
			out.ReplacementMode = "namespace"
		case !spec.Enabled:
			out.ReplacementMode = "active"
		default:
			out.ReplacementMode = "withheld"
		}
		if settings.ExecutorEnabled && !out.ModelsServed {
			out.Warnings = append(out.Warnings,
				"executor mode is on but models are withheld: the mirrored provider is still enabled and model_namespace is empty, so publishing the same model IDs would let CLIProxyAPI load balance across both paths. Set model_namespace for a test, or disable the mirrored provider.")
		}
		if settings.ExecutorEnabled && out.MirroredModelCount == 0 {
			out.Warnings = append(out.Warnings,
				"executor mode is on but the mirrored provider declares no models; clients would see an empty model list")
		}
		if out.ReplacementMode == "active" {
			out.Warnings = append(out.Warnings,
				"executor mode is the only serving path for these models: re-enable the mirrored provider before disabling or uninstalling this plugin, or traffic will break")
		}
	} else {
		out.Warnings = append(out.Warnings,
		"no configured openai-compatibility provider matched, so executor mode has nothing to mirror")
	}

	out.Agy2apiSecretConfigured = settings.Agy2apiIdentitySecret != ""
	executorRuntimeState.Lock()
	lastStatus := executorRuntimeState.lastStatus
	lastAt := executorRuntimeState.lastAt
	executorRuntimeState.Unlock()
	if lastStatus == 401 || lastStatus == 403 {
		out.LastExecutorStatus = lastStatus
		if !lastAt.IsZero() {
			out.LastExecutorErrorAt = lastAt.Format(time.RFC3339)
		}
		if settings.hmacSecret() != "" {
			out.Warnings = append(out.Warnings,
				"agy2api signature mismatch - verify AGY_IDENTITY_BRIDGE_SECRET matches the configured plugin secret")
		} else {
			out.Warnings = append(out.Warnings,
				"agy2api rejected the upstream request - configure agy2api_identity_secret or AGY_PLUGIN_SECRET so the plugin can sign identity headers")
		}
	}

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
	entries := openAICompatEntries(root)
	if len(entries) == 0 {
		return nil
	}
	out := make([]discoveredProvider, 0, len(entries))
	for _, providerMap := range entries {
		name, _ := stringValue(providerMap, "name")
		baseURL, _ := stringValue(providerMap, "base-url", "base_url", "url")
		prefix, _ := stringValue(providerMap, "prefix")
		disabled, _ := boolValue(providerMap, "disabled")
		// A provider with no key entries is still a meaningful record: it
		// tells the operator that the provider exists but has no API key.
		out = append(out, discoveredProvider{
			Name:        name,
			ProviderKey: name,
			URL:         baseURL,
			Prefix:      prefix,
			Source:      "openai-compatibility",
			Active:      !disabled,
			Disabled:    disabled,
			APIKeys:     compatAPIKeys(providerMap),
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
			ToFormat:    prefixCandidateFormat(item),
			Native:      item.Native,
		})
	} else {
		for _, key := range item.APIKeys {
			candidates = append(candidates, providerCandidate{
				Name:        item.Name,
				ProviderKey: item.ProviderKey,
				URL:         item.URL,
				APIKey:      key,
				ToFormat:    prefixCandidateFormat(item),
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

// prefixCandidateFormat keeps the provider prefix visible to name selectors so
// an operator can match on the same namespace clients type in the model field.
func prefixCandidateFormat(item discoveredProvider) string {
	return strings.TrimSpace(item.Prefix)
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
	out.MatchModel = ""
	out.MatchModels = nil
	out.MatchAPIKeyConfigured = in.MatchAPIKeyConfigured
	out.HMACSecretConfigured = in.HMACSecretConfigured
	out.ConfigPathFound = false
	out.ScannedProviders = nil
	out.MirroredBaseURL = ""
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
