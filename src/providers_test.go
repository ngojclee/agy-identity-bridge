package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderMatchingDefaultsAndExplicitRules(t *testing.T) {
	defaults := defaultPluginSettings()
	if matched, by := defaults.shouldInterceptCandidate(providerCandidate{
		ToFormat: "antigravity",
		Native:   true,
	}); !matched || len(by) != 1 || by[0] != "native-antigravity" {
		t.Fatalf("native default match = %v, %v", matched, by)
	}
	if matched, _ := defaults.shouldInterceptCandidate(providerCandidate{
		Name:     "OpenRouter",
		ToFormat: "openai",
	}); matched {
		t.Fatal("unrelated provider matched automatic discovery")
	}
	if matched, _ := defaults.shouldInterceptCandidate(providerCandidate{
		Name: "My AGY2API Gateway",
		URL:  "https://gateway.example/v1",
	}); !matched {
		t.Fatal("agy2api provider did not match automatic discovery")
	}

	explicit := PluginSettings{
		MatchName:   "Antigravity",
		MatchURL:    "*agy.internal*",
		MatchAPIKey: "secret-key",
		MatchMode:   "all",
	}
	if matched, _ := explicit.shouldInterceptCandidate(providerCandidate{
		Name:   "Antigravity",
		URL:    "https://agy.internal/v1",
		APIKey: "secret-key",
	}); !matched {
		t.Fatal("all explicit rules should match")
	}
	if matched, _ := explicit.shouldInterceptCandidate(providerCandidate{
		Name:   "Antigravity",
		URL:    "https://other.internal/v1",
		APIKey: "secret-key",
	}); matched {
		t.Fatal("all explicit rules matched with a non-matching URL")
	}

	any := explicit
	any.MatchMode = "any"
	if matched, by := any.shouldInterceptCandidate(providerCandidate{
		Name: "Antigravity",
	}); !matched || !strings.Contains(strings.Join(by, ","), "name") {
		t.Fatalf("any explicit rules = %v, %v", matched, by)
	}
	if matched, _ := any.shouldInterceptCandidate(providerCandidate{
		Name:   "Unrelated",
		APIKey: "wrong",
	}); matched {
		t.Fatal("wrong explicit API key matched")
	}

	if got := hmacSecretForCandidate(
		PluginSettings{HMACSecretSource: "provider_api_key"},
		providerCandidate{APIKey: "selected-provider-key"},
	); got != "selected-provider-key" {
		t.Fatalf("provider API key HMAC source = %q", got)
	}
}

func TestCandidateFromPayloadUsesProviderContextInsteadOfModelName(t *testing.T) {
	candidate := candidateFromPayload(InterceptRequestPayload{
		Model:    "gemini-3.1-pro",
		ToFormat: "openai",
		Headers: map[string][]string{
			"Authorization": {"Bearer upstream-key"},
		},
		Metadata: map[string]any{
			"provider_name":    "Antigravity",
			"base_url":         "https://agy.internal/v1",
			"selected_auth_id": "auth-1",
		},
	})
	if candidate.Name != "Antigravity" || candidate.URL != "https://agy.internal/v1" {
		t.Fatalf("candidate provider context = %+v", candidate)
	}
	if candidate.APIKey != "upstream-key" || candidate.AuthID != "auth-1" {
		t.Fatalf("candidate auth context = %+v", candidate)
	}
	if candidate.Name == candidate.ToFormat || candidate.Name == "gemini-3.1-pro" {
		t.Fatalf("candidate fell back to model name: %+v", candidate)
	}
}

func TestHandleInterceptAfterMatchesNativeAntigravity(t *testing.T) {
	previous := currentPluginSettings()
	defer func() {
		pluginSettingsMu.Lock()
		pluginSettings = previous
		pluginSettingsMu.Unlock()
	}()

	pluginSettingsMu.Lock()
	pluginSettings = defaultPluginSettings()
	pluginSettingsMu.Unlock()

	raw := []byte(`{"to_format":"antigravity","model":"gemini-pro","headers":{"Authorization":["Bearer client-key"],"User-Agent":["Hermes/1.0"]}}`)
	response, errHandle := handleInterceptAfter(raw)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	if !strings.Contains(string(response), "X-AGY-Principal") {
		t.Fatalf("native request did not receive identity headers: %s", response)
	}
}

func TestHandleInterceptAfterHonorsDisabledSetting(t *testing.T) {
	previous := currentPluginSettings()
	defer func() {
		pluginSettingsMu.Lock()
		pluginSettings = previous
		pluginSettingsMu.Unlock()
	}()

	disabled := defaultPluginSettings()
	disabled.Enabled = false
	pluginSettingsMu.Lock()
	pluginSettings = disabled
	pluginSettingsMu.Unlock()

	raw := []byte(`{"to_format":"antigravity","model":"gemini-pro","headers":{"Authorization":["Bearer client-key"]}}`)
	response, errHandle := handleInterceptAfter(raw)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	if strings.Contains(string(response), "X-AGY-Principal") {
		t.Fatalf("disabled plugin injected identity headers: %s", response)
	}
}

func TestDiscoverOpenAICompatibilityAndRedaction(t *testing.T) {
	root, errParse := parseYAMLMap([]byte(`
openai-compatibility:
  - name: Antigravity
    base-url: https://admin:password@agy.internal/v1?secret=hidden
    api-key-entries:
      - api-key: provider-secret
      - api-key: second-secret
  - name: Other
    disabled: true
`))
	if errParse != nil {
		t.Fatal(errParse)
	}
	providers := discoverOpenAICompatibility(root)
	if len(providers) != 2 {
		t.Fatalf("providers = %#v", providers)
	}
	if len(providers[0].APIKeys) != 2 {
		t.Fatalf("API keys = %#v", providers[0].APIKeys)
	}
	if got := redactURL(providers[0].URL); got != "https://agy.internal/v1" {
		t.Fatalf("redacted URL = %q", got)
	}
}

func TestDiagnosticsReportsConfiguredAndMatchedProviders(t *testing.T) {
	previous := currentConfigSnapshot()
	defer applyPluginConfiguration(previous)

	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")
	applyPluginConfiguration(loadPluginConfiguration([]byte(`
plugins:
  configs:
    agy-identity-bridge:
      enabled: true
      match_name: Antigravity
openai-compatibility:
  - name: Antigravity
    base-url: https://agy.internal/v1
    api-key-entries:
      - api-key: provider-secret
  - name: OpenRouter
    base-url: https://openrouter.example/v1
    api-key-entries:
      - api-key: other-secret
`)))

	diagnostics := scanProviderDiagnostics()
	if diagnostics.ConfiguredRecordCount != 2 {
		t.Fatalf("configured records = %d, want 2", diagnostics.ConfiguredRecordCount)
	}
	if diagnostics.RuntimeRecordCount != 0 {
		t.Fatalf("runtime records = %d, want 0", diagnostics.RuntimeRecordCount)
	}
	if diagnostics.MatchedRecordCount != 1 || diagnostics.MatchedProviderCount != 1 {
		t.Fatalf("matched counts = %d/%d, want 1/1", diagnostics.MatchedRecordCount, diagnostics.MatchedProviderCount)
	}
	if diagnostics.UnmatchedRecordCount != 1 {
		t.Fatalf("unmatched records = %d, want 1", diagnostics.UnmatchedRecordCount)
	}
	if len(diagnostics.ScannedProviders) != 2 {
		t.Fatalf("scanned providers = %d, want 2", len(diagnostics.ScannedProviders))
	}
	if len(diagnostics.Providers) != 1 || diagnostics.Providers[0].Name != "Antigravity" {
		t.Fatalf("matched providers = %#v", diagnostics.Providers)
	}
	if diagnostics.Providers[0].MatchedBy[0] != "name" {
		t.Fatalf("matched by = %#v, want name", diagnostics.Providers[0].MatchedBy)
	}
	raw, errMarshal := json.Marshal(diagnostics)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	text := string(raw)
	for _, secret := range []string{"provider-secret", "other-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("diagnostics leaked %q: %s", secret, text)
		}
	}
}

func TestDiagnosticsNeverExposeSecrets(t *testing.T) {
	previous := currentConfigSnapshot()
	defer applyPluginConfiguration(previous)

	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")
	applyPluginConfiguration(loadPluginConfiguration([]byte(`
plugins:
  configs:
    agy-identity-bridge:
      match_name: Antigravity
      match_api_key: provider-secret
      hmac_secret: hmac-secret
      hmac_secret_source: config
openai-compatibility:
  - name: Antigravity
    base-url: https://user:pass@agy.internal/v1?token=private
    api-key-entries:
      - api-key: provider-secret
`)))

	diagnostics := scanProviderDiagnostics()
	raw, errMarshal := json.Marshal(diagnostics)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	text := string(raw)
	for _, secret := range []string{"provider-secret", "hmac-secret", "user:pass", "private"} {
		if strings.Contains(text, secret) {
			t.Fatalf("diagnostics leaked %q: %s", secret, text)
		}
	}
	if diagnostics.MatchedRecordCount != 1 {
		t.Fatalf("matched records = %d, want 1", diagnostics.MatchedRecordCount)
	}
}

func TestPublicStatusPageShowsSummaryWithoutPrivateSelectors(t *testing.T) {
	page := publicStatusPage(providerDiagnostics{
		ScannedRecordCount:   1,
		MatchedRecordCount:   1,
		MatchedProviderCount: 1,
		Providers: []providerStatus{{
			Name:        "Antigravity",
			ProviderKey: "openai-compatible-antigravity",
			URL:         "https://private.example/v1",
			Source:      "openai-compatibility",
			Active:      true,
			Matched:     true,
			MatchedBy:   []string{"name"},
		}},
		MatchName:  "private-selector",
		ConfigPath: "/private/config.yaml",
	})
	if !strings.Contains(page, "Scanned records") || !strings.Contains(page, "Antigravity") {
		t.Fatalf("public status page is missing summary/provider data: %s", page)
	}
	for _, privateValue := range []string{"private-selector", "/private/config.yaml", "private.example"} {
		if strings.Contains(page, privateValue) {
			t.Fatalf("public status page leaked %q", privateValue)
		}
	}
}

func TestManagementRegistrationDeclaresStatusAndConfigFields(t *testing.T) {
	registration := pluginRegistration()
	if registration.Metadata.Version == "" {
		t.Fatal("plugin version is empty")
	}
	if len(registration.Metadata.ConfigFields) < 6 {
		t.Fatalf("config fields = %d, want provider matching fields", len(registration.Metadata.ConfigFields))
	}
	if !registration.Capabilities.ManagementAPI {
		t.Fatal("management API capability = false")
	}

	raw := handleManagementRegister()
	text := string(raw)
	for _, required := range []string{"/status", "AGY Identity Bridge", "rescan"} {
		if !strings.Contains(text, required) {
			t.Fatalf("management registration missing %q: %s", required, text)
		}
	}

	fields := make(map[string]bool)
	for _, field := range registration.Metadata.ConfigFields {
		fields[field.Name] = true
	}
	if !fields["match_provider"] || !fields["match_name"] || !fields["match_url"] || !fields["match_api_key"] {
		t.Fatalf("provider selector fields missing: %#v", fields)
	}
}
