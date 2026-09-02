package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderEditorHTMLHasManagementKeyGateAndProviderControls(t *testing.T) {
	loadMirror(t)
	diagnostics := scanProviderDiagnostics()
	page := providerResourcePage(diagnostics)
	for _, expected := range []string{
		"CPA management key",
		"Load secure config",
		"Disable original provider",
		"Identity bridge",
		"Allow explicit client identity headers",
		"API key entries",
		"Request headers",
		"Custom models",
		"Fetch from endpoint",
		"Test all keys",
		"Select a model to test",
		"Select models from endpoint",
		"notice-bar",
		"AGY_PLUGIN_SECRET",
		"drawer-close",
		"Save",
		"/v0/management/plugins/agy-identity-bridge",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("provider editor page missing %q", expected)
		}
	}
	for _, private := range []string{"provider-secret", "http://10.21.4.101:8123/v1", "Z:\\missing"} {
		if strings.Contains(page, private) {
			t.Fatalf("public provider editor leaked %q", private)
		}
	}
}

func TestUnifiedDashboardContainsUsageFiltersAndDrawerAnalytics(t *testing.T) {
	page := providerEditorHTML(providerEditorData{
		Version: "test",
		Diagnostics: providerDiagnostics{
			ReplacementMode:     "active",
			ExecutorProvider:    "ln.Antigravity",
			ExecutorAuthEnsured: true,
		},
		Usage: usagePageData{
			Filters: usageFilter{Period: "current_month", Bucket: "hour", Source: "all"},
			Summary: usageSummary{
				Requests:         12,
				TotalTokens:      1200,
				PromptTokens:     800,
				CompletionTokens: 400,
				CachedTokens:     200,
				CacheHits:        3,
				ModelCount:       2,
				SourceCount:      1,
			},
			TopModels:  []usageGroup{{Label: "gemini-3.7-flash-high", Requests: 8, TotalTokens: 900}},
			TopSources: []usageGroup{{Label: "codex", Requests: 12, TotalTokens: 1200}},
			Recent:     []usageViewRecord{{Model: "gemini-3.7-flash-high", ClientApp: "codex", TotalTokens: 120}},
			Buckets:    []usageBucket{{Label: "Sep 02 10:00", Requests: 12, TotalTokens: 1200}},
		},
	})
	for _, expected := range []string{
		"Single dashboard for the mirrored provider and its runtime telemetry",
		"Usage analytics",
		"Model usage share",
		"Traffic by client",
		"Recent usage",
		"Activity buckets",
		"drawer-tab",
		"data-pane=\"usage-pane\"",
		`name="period"`,
		`name="bucket"`,
		`name="source"`,
		"gemini-3.7-flash-high",
		"12",
		"1200",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("unified dashboard missing %q", expected)
		}
	}
	if strings.Count(page, `name="period"`) != 2 ||
		strings.Count(page, `name="bucket"`) != 2 ||
		strings.Count(page, `name="source"`) != 2 {
		t.Fatalf("dashboard should expose filters in main content and drawer")
	}
}

func TestPatchProviderConfigPreservesSecretsWhenWriteOnlyFieldsAreEmpty(t *testing.T) {
	settings := decodePluginSettings([]byte(mirrorConfigYAML))
	payload := providerEditorPayload{
		OriginalName:     "Antigravity",
		OriginalPrefix:   "agy",
		OriginalBaseURL:  "http://10.21.4.101:8123/v1",
		Name:             "Antigravity",
		Prefix:           "agy",
		BaseURL:          "http://10.21.4.101:8123/v1",
		Priority:         7,
		DisableCooling:   true,
		ExecutorEnabled:  true,
		ExecutorProvider: defaultExecutorProvider,
		HMACSecretSource: "env",
		ModelIDs:         []string{"gemini-pro", "gemini-image", "no-alias-model"},
	}
	updated, _, errPatch := patchProviderConfig([]byte(mirrorConfigYAML), payload, settings)
	if errPatch != nil {
		t.Fatal(errPatch)
	}
	text := string(updated)
	if !strings.Contains(text, "provider-secret") {
		t.Fatalf("provider API key was not preserved: %s", text)
	}
	if strings.Contains(text, "agy2api_identity_secret:") {
		t.Fatalf("empty write-only identity secret should not be written: %s", text)
	}
}

func TestPatchProviderConfigUpdatesProviderAndPluginFields(t *testing.T) {
	settings := decodePluginSettings([]byte(mirrorConfigYAML))
	payload := providerEditorPayload{
		OriginalName:          "Antigravity",
		OriginalPrefix:        "agy",
		OriginalBaseURL:       "http://10.21.4.101:8123/v1",
		Name:                  "Antigravity",
		Prefix:                "agy",
		BaseURL:               "http://10.21.4.101:8123/v1",
		Priority:              8,
		Disabled:              true,
		DisableCooling:        false,
		APIKeys:               []string{"new-provider-key"},
		Headers:               []editorHeaderPair{{Key: "X-Test", Value: "ok"}},
		ModelIDs:              []string{"gemini-pro", "new-model"},
		ExecutorEnabled:       true,
		ExecutorProvider:      defaultExecutorProvider,
		ModelNamespace:        "",
		Agy2apiIdentitySecret: "identity-secret",
		HMACSecretSource:      "config",
	}
	updated, changed, errPatch := patchProviderConfig([]byte(mirrorConfigYAML), payload, settings)
	if errPatch != nil {
		t.Fatal(errPatch)
	}
	root, errParse := parseYAMLMap(updated)
	if errParse != nil {
		t.Fatal(errParse)
	}
	providers := openAICompatEntries(root)
	if len(providers) == 0 {
		t.Fatal("providers missing after patch")
	}
	first := providers[0]
	if disabled, _ := boolValue(first, "disabled"); !disabled {
		t.Fatalf("disabled was not saved: %+v", first)
	}
	if priority, _ := intValue(first, "priority"); priority != 8 {
		t.Fatalf("priority = %d, want 8", priority)
	}
	if cooling, _ := boolValue(first, "disable-cooling"); cooling {
		t.Fatalf("disable-cooling should be false")
	}
	if got := compatAPIKeys(first); len(got) != 1 || got[0] != "new-provider-key" {
		t.Fatalf("api keys = %+v", got)
	}
	if got := compatHeaders(first)["X-Test"]; got != "ok" {
		t.Fatalf("headers = %+v", compatHeaders(first))
	}
	models := compatModels(first)
	if len(models) != 2 || models[0].Alias != "gemini-pro" || models[1].Name != "new-model" {
		t.Fatalf("models = %+v", models)
	}
	pluginConfig, found := findPluginConfig(root)
	if !found {
		t.Fatal("plugin config missing after patch")
	}
	if got, _ := stringValue(pluginConfig, "agy2api_identity_secret"); got != "identity-secret" {
		t.Fatalf("identity secret not written")
	}
	if got, _ := stringValue(pluginConfig, "hmac_secret_source"); got != "config" {
		t.Fatalf("hmac source = %q", got)
	}
	rawChanged, _ := json.Marshal(changed)
	for _, field := range []string{"disabled", "api-key-entries", "agy2api_identity_secret"} {
		if !strings.Contains(string(rawChanged), field) {
			t.Fatalf("changed fields missing %q: %s", field, rawChanged)
		}
	}
}

func TestPatchProviderConfigPreservesExistingApiKeysWhenBlankRowsStayBlank(t *testing.T) {
	settings := decodePluginSettings([]byte(mirrorConfigYAML))
	payload := providerEditorPayload{
		OriginalName:    "Antigravity",
		OriginalPrefix:  "agy",
		OriginalBaseURL: "http://10.21.4.101:8123/v1",
		Name:            "Antigravity",
		Prefix:          "agy",
		BaseURL:         "http://10.21.4.101:8123/v1",
		APIKeyRows: []providerEditorAPIKeyRow{
			{Existing: true, Value: ""},
			{Existing: false, Value: "new-provider-key"},
		},
	}
	updated, _, errPatch := patchProviderConfig([]byte(mirrorConfigYAML), payload, settings)
	if errPatch != nil {
		t.Fatal(errPatch)
	}
	root, errParse := parseYAMLMap(updated)
	if errParse != nil {
		t.Fatal(errParse)
	}
	providers := openAICompatEntries(root)
	if len(providers) == 0 {
		t.Fatal("providers missing after patch")
	}
	keys := compatAPIKeys(providers[0])
	if len(keys) != 2 || keys[0] != "provider-secret" || keys[1] != "new-provider-key" {
		t.Fatalf("api keys = %+v", keys)
	}
}

func TestParseOpenAIModelsSortsAndDeduplicatesIDs(t *testing.T) {
	models := parseOpenAIModels([]byte(`{"data":[{"id":"b"},{"id":"a"},{"id":"a"},{"id":""}]}`))
	if strings.Join(models, ",") != "a,b" {
		t.Fatalf("models = %+v", models)
	}
}

func TestEditorTestModelStripsProviderPrefixBeforeUpstream(t *testing.T) {
	settings := decodePluginSettings([]byte(mirrorConfigYAML))
	spec := providerSpec{
		Name:   "Antigravity",
		Prefix: "agy",
		Models: []modelSpec{{Name: "gemini-3.7-flash-high"}},
	}
	payload := providerEditorPayload{TestModel: "agy/gemini-3.7-flash-high"}
	model := editorTestModel(payload, spec)
	if got := stripModelPrefix(model, settingsModelPrefix(settings, spec)); got != "gemini-3.7-flash-high" {
		t.Fatalf("test model sent upstream as %q", got)
	}
}

func TestEditorProviderAPIKeysKeepsConfiguredKeysAndAddsNewKeys(t *testing.T) {
	current := providerSpec{APIKeys: []string{"configured-key"}}
	payload := providerEditorPayload{
		APIKeyRows: []providerEditorAPIKeyRow{
			{Existing: true},
			{Value: "new-key"},
		},
	}
	keys := editorProviderAPIKeys(payload, current)
	if len(keys) != 2 || keys[0] != "configured-key" || keys[1] != "new-key" {
		t.Fatalf("resolved API keys = %+v", keys)
	}
}
