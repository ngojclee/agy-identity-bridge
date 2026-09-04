package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestDashboardShowsOperationalState(t *testing.T) {
	diagnostics := providerDiagnostics{
		Version:                 "test",
		Enabled:                 true,
		ExecutorEnabled:         true,
		ExecutorProvider:        "ln.Antigravity",
		ExecutorAuthEnsured:     true,
		ReplacementMode:         "active",
		MirroredProvider:        "Antigravity",
		MirroredModelCount:      15,
		ProviderOriginalEnabled: false,
		Agy2apiSecretConfigured: true,
		ModelsServed:            true,
		LastExecutorStatus:      200,
		InterceptCount:          7,
		RuntimeAuthCount:        12,
		MatchedRecordCount:      1,
		ActivePrefixes:          []string{"agy"},
		RecentEvents: []dashboardEvent{
			{At: "2026-09-01T00:00:00Z", Level: "success", Message: "Plugin executor auth record is ready"},
			{At: "2026-09-01T00:00:01Z", Level: "info", Message: "Client request intercepted for the mirrored provider"},
		},
	}
	page := publicStatusPage(diagnostics)
	for _, expected := range []string{
		"Single dashboard for the mirrored provider and its runtime telemetry",
		"Open editor",
		"Replacement mode",
		"Runtime log",
		"API key entries",
		"Custom models",
		"Runtime log",
		"Plugin executor auth record is ready",
		"background:#22221f;color:#eceae5",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("dashboard missing %q", expected)
		}
	}
}

func TestProviderDetailPageShowsLiveModelsAndConfig(t *testing.T) {
	diagnostics := providerDiagnostics{
		Version:                 "test",
		Enabled:                 true,
		ExecutorEnabled:         true,
		ExecutorProvider:        "ln.Antigravity",
		ExecutorAuthEnsured:     true,
		ReplacementMode:         "active",
		MirroredProvider:        "Antigravity",
		MirroredPriority:        120,
		MirroredDisableCooling:  true,
		MirroredBaseURL:         "http://10.21.4.101:8123/v1",
		MirroredModelCount:      2,
		MirroredModelIDs:        []string{"gemini-3.7-flash-high", "gemini-3.7-flash-low"},
		PublishedModelIDs:       []string{"agy/gemini-3.7-flash-high", "agy/gemini-3.7-flash-low"},
		ProviderOriginalEnabled: false,
		Agy2apiSecretConfigured: true,
		ModelsServed:            true,
		LastExecutorStatus:      200,
		InterceptCount:          7,
		RuntimeAuthCount:        12,
		MatchedRecordCount:      1,
		ActivePrefixes:          []string{"agy"},
		RecentEvents: []dashboardEvent{
			{At: "2026-09-01T00:00:00Z", Level: "success", Message: "Plugin executor auth record is ready"},
		},
	}
	page := providerDetailPage(diagnostics)
	for _, expected := range []string{
		"Close editor",
		"Source provider",
		"Request headers",
		"Custom models",
		"Allowed thinking levels",
		"Base URL",
		"gemini-3.7-flash-high",
		"gemini-3.7-flash-low",
		"ln.Antigravity",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("provider detail page missing %q", expected)
		}
	}
}

func TestDashboardEventBufferStaysBoundedAndNewestFirst(t *testing.T) {
	for i := 0; i < maxDashboardEvents+2; i++ {
		recordDashboardEvent("info", "event")
	}
	events := recentDashboardEvents()
	if len(events) != maxDashboardEvents {
		t.Fatalf("event count = %d, want %d", len(events), maxDashboardEvents)
	}
}

func TestRequestInterceptBeforeIsHandledAsNoop(t *testing.T) {
	raw, errHandle := handleMethod(pluginabi.MethodRequestInterceptBefore, nil)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	var response envelope
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !response.OK {
		t.Fatalf("before interceptor failed: %s", raw)
	}
}

func TestDashboardRouteStateReflectsReadiness(t *testing.T) {
	tests := []struct {
		name  string
		input providerDiagnostics
		label string
		tone  string
	}{
		{
			name:  "disabled plugin",
			input: providerDiagnostics{Enabled: false, ExecutorEnabled: true},
			label: "Plugin disabled",
			tone:  "muted",
		},
		{
			name:  "executor auth missing",
			input: providerDiagnostics{Enabled: true, ExecutorEnabled: true},
			label: "Executor not ready",
			tone:  "error",
		},
		{
			name: "upstream error",
			input: providerDiagnostics{
				Enabled:             true,
				ExecutorEnabled:     true,
				ExecutorAuthEnsured: true,
				ModelsServed:        true,
				LastExecutorStatus:  401,
			},
			label: "Executor degraded",
			tone:  "error",
		},
		{
			name: "withheld models",
			input: providerDiagnostics{
				Enabled:             true,
				ExecutorEnabled:     true,
				ExecutorAuthEnsured: true,
				ModelsServed:        false,
			},
			label: "Models withheld",
			tone:  "warning",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, tone := dashboardRouteState(test.input)
			if state.label != test.label || tone != test.tone {
				t.Fatalf("state = %#v, tone = %q, want label %q/tone %q", state, tone, test.label, test.tone)
			}
		})
	}
}

func TestDashboardPublishedModelCountOnlyCountsServedModels(t *testing.T) {
	if count := dashboardPublishedModelCount(providerDiagnostics{
		MirroredModelCount: 9,
		ModelsServed:       false,
	}); count != 0 {
		t.Fatalf("withheld published model count = %d, want 0", count)
	}
	if count := dashboardPublishedModelCount(providerDiagnostics{
		MirroredModelCount: 9,
		ModelsServed:       true,
	}); count != 9 {
		t.Fatalf("served published model count = %d, want 9", count)
	}
}

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
	}, defaultPluginSettings())
	if candidate.Name != "Antigravity" || candidate.URL != "https://agy.internal/v1" {
		t.Fatalf("candidate provider context = %+v", candidate)
	}
	// The Authorization header is the client key, never a provider credential.
	if candidate.APIKey != "" || candidate.ClientToken != "upstream-key" || candidate.AuthID != "auth-1" {
		t.Fatalf("candidate auth context = %+v", candidate)
	}
	if candidate.Name == candidate.ToFormat || candidate.Name == "gemini-3.1-pro" {
		t.Fatalf("candidate fell back to model name: %+v", candidate)
	}
}

// CLIProxyAPI marshals pluginapi.RequestInterceptRequest without json tags, so
// the wire keys are the Go field names. A snake_case-only parser silently read
// nothing and made the whole interceptor a no-op.
func TestParseInterceptPayloadAcceptsCPAGoStyleKeys(t *testing.T) {
	raw := []byte(`{"SourceFormat":"openai","ToFormat":"openai","Model":"gemini-3.5-flash-low","RequestedModel":"agy/gemini-3.5-flash-low","Stream":false,"Headers":{"Authorization":["Bearer client-key"],"User-Agent":["Hermes/1.0"]},"Metadata":{"selected_auth_id":"auth-9"}}`)
	payload, errParse := parseInterceptPayload(raw)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if payload.ToFormat != "openai" || payload.RequestedModel != "agy/gemini-3.5-flash-low" {
		t.Fatalf("Go-style keys lost: %+v", payload)
	}
	if payload.Headers["Authorization"][0] != "Bearer client-key" {
		t.Fatalf("headers not parsed: %+v", payload.Headers)
	}
	if metadataString(payload.Metadata, "selected_auth_id") != "auth-9" {
		t.Fatalf("metadata not parsed: %+v", payload.Metadata)
	}

	snake, errSnake := parseInterceptPayload([]byte(`{"to_format":"openai","requested_model":"agy/x","headers":{"Authorization":["Bearer k"]}}`))
	if errSnake != nil || snake.ToFormat != "openai" || snake.RequestedModel != "agy/x" {
		t.Fatalf("snake_case compatibility broken: %+v %v", snake, errSnake)
	}
}

// The response must decode into pluginapi.RequestInterceptResponse, whose
// fields are also untagged.
func TestInterceptResponseUsesCPAGoStyleKeys(t *testing.T) {
	raw := okEnvelope(InterceptResponsePayload{
		Headers: map[string][]string{"X-AGY-Principal": {"abc"}},
	})
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			Headers      map[string][]string
			Body         []byte
			ClearHeaders []string
		}
	}
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !decoded.OK || len(decoded.Result.Headers["X-AGY-Principal"]) != 1 {
		t.Fatalf("CPA could not decode the interceptor response: %s", raw)
	}
}

// End to end for the real deployment shape: an OpenAI-compatible provider named
// Antigravity with prefix agy, identified only by the requested model.
func TestInterceptResolvesProviderFromModelPrefix(t *testing.T) {
	previousSettings := currentPluginSettings()
	defer func() {
		pluginSettingsMu.Lock()
		pluginSettings = previousSettings
		pluginSettingsMu.Unlock()
		refreshMatchedRecords(nil)
	}()
	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")

	applyPluginConfiguration(loadPluginConfiguration([]byte(`
plugins:
  configs:
    agy-identity-bridge:
      enabled: true
      auto_discover: true
      include_native_antigravity: false
openai-compatibility:
  - name: Antigravity
    prefix: agy
    base-url: http://10.21.4.101:8123/v1
    api-key-entries:
      - api-key: provider-secret
  - name: Other
    prefix: other
    base-url: https://other.example/v1
    api-key-entries:
      - api-key: other-secret
`)))
	settings := currentPluginSettings()
	diagnostics := scanProviderDiagnostics()
	if len(diagnostics.ActivePrefixes) != 1 || diagnostics.ActivePrefixes[0] != "agy" {
		t.Fatalf("active prefixes = %#v, want [agy]", diagnostics.ActivePrefixes)
	}

	raw := []byte(`{"ToFormat":"openai","Model":"gemini-3.5-flash-low","RequestedModel":"agy/gemini-3.5-flash-low","Headers":{"Authorization":["Bearer client-key"],"User-Agent":["codex-tui/0.128.0"]}}`)
	response, errHandle := handleInterceptAfter(raw)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	text := string(response)
	if !strings.Contains(text, "X-AGY-Principal") {
		t.Fatalf("model-prefix request received no identity headers: %s", text)
	}
	if strings.Contains(text, "provider-secret") || strings.Contains(text, "client-key") {
		t.Fatalf("response leaked a credential: %s", text)
	}

	other := []byte(`{"ToFormat":"openai","Model":"kimi-k2","RequestedModel":"other/kimi-k2","Headers":{"Authorization":["Bearer client-key"]}}`)
	otherResponse, errOther := handleInterceptAfter(other)
	if errOther != nil {
		t.Fatal(errOther)
	}
	if strings.Contains(string(otherResponse), "X-AGY-Principal") {
		t.Fatalf("unrelated provider was intercepted: %s", otherResponse)
	}
	if matched, by := settings.shouldInterceptCandidate(providerCandidate{
		ToFormat: "antigravity", Native: true,
	}); matched || len(by) != 0 {
		t.Fatal("include_native_antigravity=false must not match native requests")
	}
}

// Interceptor-only traffic must carry the same canonical signature contract
// as executor traffic, so agy2api can refine the principal without trusting
// unsigned headers.
func TestInterceptAfterSignsCanonicalIdentity(t *testing.T) {
	previousSettings := currentPluginSettings()
	defer func() {
		pluginSettingsMu.Lock()
		pluginSettings = previousSettings
		pluginSettingsMu.Unlock()
		refreshMatchedRecords(nil)
	}()
	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")
	t.Setenv("AGY_PLUGIN_SECRET", "intercept-signing-secret-0123456789")

	applyPluginConfiguration(loadPluginConfiguration([]byte(`
plugins:
  configs:
    agy-identity-bridge:
      enabled: true
      auto_discover: true
openai-compatibility:
  - name: Antigravity
    prefix: agy
    base-url: http://10.21.4.101:8123/v1
    api-key-entries:
      - api-key: provider-secret
`)))
	diagnostics := scanProviderDiagnostics()
	if diagnostics.MatchedRecordCount != 1 {
		t.Fatalf("matched records = %d, want 1", diagnostics.MatchedRecordCount)
	}

	raw := []byte(`{"ToFormat":"openai","RequestedModel":"agy/gemini-3.5-flash-low","Headers":{"Authorization":["Bearer client-key"],"User-Agent":["codex-tui/0.128.0"]}}`)
	response, errHandle := handleInterceptAfter(raw)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			Headers map[string][]string `json:"Headers"`
		} `json:"result"`
	}
	if errUnmarshal := json.Unmarshal(response, &decoded); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	headers := decoded.Result.Headers
	principal := ""
	timestamp := ""
	signature := ""
	for key, values := range headers {
		switch strings.ToLower(key) {
		case "x-agy-principal":
			principal = values[0]
		case "x-agy-timestamp":
			timestamp = values[0]
		case "x-agy-signature":
			signature = values[0]
		}
	}
	if principal == "" || timestamp == "" || signature == "" {
		t.Fatalf("interceptor response missing signed identity headers: %s", response)
	}
	message := strings.Join([]string{
		"principal=" + principal,
		"timestamp=" + timestamp,
		"client_app=" + headers["X-AGY-Client-App"][0],
		"client_instance=" + "",
		"capability_profile=" + "",
		"connector_id=" + "",
		"method=POST",
		// The wire path, not the allowlisted endpoint: base_url contributes /v1 and
		// agy2api verifies against request.url.path.
		"path=/v1/chat/completions",
	}, "\n")
	mac := hmac.New(sha256.New, []byte("intercept-signing-secret-0123456789"))
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		t.Fatalf("signature does not match canonical payload: %s", response)
	}
	if strings.Contains(string(response), "provider-secret") || strings.Contains(string(response), "client-key") {
		t.Fatal("response leaked a credential")
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
	diagnostics := providerDiagnostics{
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
		}, {
			Name:        "antigravity",
			Label:       "operator.personal@gmail.com",
			ProviderKey: "antigravity",
			AuthIndex:   "auth-index-secret",
			Source:      "runtime-auth",
			Native:      true,
			Active:      true,
			Matched:     true,
			MatchedBy:   []string{"native-antigravity"},
		}},
		MatchName:  "private-selector",
		ConfigPath: "/private/config.yaml",
	}
	page := publicStatusPage(diagnostics)
	if !strings.Contains(page, "Open editor") || !strings.Contains(page, "Management access") {
		t.Fatalf("public status page is missing summary/provider data: %s", page)
	}
	for _, privateValue := range []string{
		"private-selector", "/private/config.yaml", "private.example",
		"operator.personal@gmail.com", "auth-index-secret",
	} {
		if strings.Contains(page, privateValue) {
			t.Fatalf("public status page leaked %q", privateValue)
		}
	}

	// CPA serves plugin resource routes without management authentication, so
	// account identifiers must never survive into the public projection.
	public := publicProviderDiagnostics(diagnostics)
	if len(public.Providers) != 2 {
		t.Fatalf("public providers = %d, want 2", len(public.Providers))
	}
	for _, provider := range public.Providers {
		if provider.Label != "" || provider.AuthIndex != "" || provider.URL != "" {
			t.Fatalf("public provider kept private identity fields: %+v", provider)
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
	if strings.Contains(text, `"menu":"AGY Provider View"`) ||
		strings.Contains(text, `"menu":"AGY Usage View"`) {
		t.Fatalf("management registration still exposes legacy dashboard menus: %s", text)
	}

	fields := make(map[string]bool)
	for _, field := range registration.Metadata.ConfigFields {
		fields[field.Name] = true
	}
	if !fields["match_provider"] || !fields["match_name"] || !fields["match_url"] || !fields["match_api_key"] {
		t.Fatalf("provider selector fields missing: %#v", fields)
	}
}
