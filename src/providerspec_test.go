package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const mirrorConfigYAML = `
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
    priority: 7
    disable-cooling: true
    headers:
      X-Custom: keep-me
    api-key-entries:
      - api-key: provider-secret
    models:
      - name: gemini-3.1-pro
        alias: gemini-pro
      - name: gemini-image
        alias: gemini-image
        image: true
        input-modalities: [Text, IMAGE, text]
        output-modalities: [Image]
      - name: no-alias-model
  - name: Other
    prefix: other
    base-url: https://other.example/v1
    models:
      - name: hidden
  - name: DisabledAGY2API
    base-url: https://agy2api-offline.example/v1
    disabled: true
`

func loadMirror(t *testing.T) PluginSettings {
	t.Helper()
	previous := currentConfigSnapshot()
	t.Cleanup(func() {
		applyPluginConfiguration(previous)
		storeProviderSpec(providerSpec{}, false)
	})
	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")
	snapshot := loadPluginConfiguration([]byte(mirrorConfigYAML))
	applyPluginConfiguration(snapshot)
	storeProviderSpec(providerSpec{}, false)
	return snapshot.Settings
}

func TestExtractProviderSpecMirrorsMatchingProvider(t *testing.T) {
	loadMirror(t)
	root, errParse := parseYAMLMap([]byte(mirrorConfigYAML))
	if errParse != nil {
		t.Fatal(errParse)
	}
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("expected the Antigravity provider to be mirrored")
	}
	if spec.Name != "Antigravity" || spec.Prefix != "agy" {
		t.Fatalf("identity = %+v", spec)
	}
	if spec.BaseURL != "http://10.21.4.101:8123/v1" || spec.upstreamBaseURL() != "http://10.21.4.101:8123/v1" {
		t.Fatalf("base url = %q", spec.BaseURL)
	}
	if spec.Priority != 7 || !spec.DisableCooling {
		t.Fatalf("priority/cooling = %+v", spec)
	}
	if spec.Headers["X-Custom"] != "keep-me" {
		t.Fatalf("headers = %+v", spec.Headers)
	}
	if spec.primaryAPIKey() != "provider-secret" {
		t.Fatalf("api key = %q", spec.primaryAPIKey())
	}
	if len(spec.Models) != 3 {
		t.Fatalf("models = %+v", spec.Models)
	}
}

func TestExtractProviderSpecSkipsDisabledAndUnrelated(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, _ := extractProviderSpec(root, currentPluginSettings())
	if spec.Name == "Other" || spec.Name == "DisabledAGY2API" {
		t.Fatalf("mirrored the wrong provider: %+v", spec.Name)
	}

	strict := currentPluginSettings()
	strict.MatchName = "Other"
	strict.AutoDiscover = false
	other, found := extractProviderSpec(root, strict)
	if !found || other.Name != "Other" {
		t.Fatalf("explicit selector did not mirror Other: %+v %v", other, found)
	}
}

// The mapping must match CLIProxyAPI's buildOpenAICompatibilityConfigModels so
// clients keep seeing the same model list they had before.
func TestModelInfosMatchCPAMapping(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, _ := extractProviderSpec(root, currentPluginSettings())
	infos := spec.modelInfos("")

	byID := map[string]modelInfo{}
	for _, info := range infos {
		byID[info.ID] = info
	}
	if len(infos) != 3 {
		t.Fatalf("model count = %d, want 3: %+v", len(infos), infos)
	}

	chat := byID["gemini-pro"]
	if chat.Type != "openai-compatibility" {
		t.Fatalf("chat type = %q", chat.Type)
	}
	if chat.Thinking == nil || len(chat.Thinking.Levels) != 3 {
		t.Fatalf("chat thinking default = %+v", chat.Thinking)
	}
	if chat.OwnedBy != "Antigravity" || chat.Object != "model" || chat.DisplayName != "gemini-pro" {
		t.Fatalf("chat metadata = %+v", chat)
	}

	image := byID["gemini-image"]
	if image.Type != "openai-image" {
		t.Fatalf("image type = %q", image.Type)
	}
	if image.Thinking != nil {
		t.Fatalf("image model must not get default thinking: %+v", image.Thinking)
	}
	// Lowercased and de-duplicated, exactly like normalizeCompatConfigModalities.
	if len(image.SupportedInputModalities) != 2 ||
		image.SupportedInputModalities[0] != "text" || image.SupportedInputModalities[1] != "image" {
		t.Fatalf("input modalities = %+v", image.SupportedInputModalities)
	}

	if _, ok := byID["no-alias-model"]; !ok {
		t.Fatalf("model without alias should publish by name: %+v", infos)
	}
}

func TestModelNamespaceKeepsCollisionControl(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, _ := extractProviderSpec(root, currentPluginSettings())
	namespaced := spec.modelInfos("spike.")
	if len(namespaced) == 0 {
		t.Fatal("no models")
	}
	for _, info := range namespaced {
		if len(info.ID) < 6 || info.ID[:6] != "spike." {
			t.Fatalf("namespace not applied: %+v", info)
		}
		if info.DisplayName != info.ID {
			t.Fatalf("display name drifted from id: %+v", info)
		}
	}
}

func TestModelRegisterResponseUsesCPAGoStyleKeys(t *testing.T) {
	loadMirror(t)
	// Namespace the models so the collision guard allows serving.
	settings := currentPluginSettings()
	settings.ExecutorEnabled = true
	settings.ModelNamespace = "spike."
	withSettings(t, settings)
	if _, found := resolveProviderSpec(); !found {
		t.Fatal("provider spec was not cached")
	}
	raw := handleModelRegister()

	// Decode the way the host does: untagged Go fields.
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			Provider string `json:"Provider"`
			Models   []struct {
				ID       string `json:"ID"`
				Type     string `json:"Type"`
				OwnedBy  string `json:"OwnedBy"`
				Thinking *struct {
					Levels []string `json:"Levels"`
				} `json:"Thinking"`
			} `json:"Models"`
		} `json:"result"`
	}
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !decoded.OK || decoded.Result.Provider != defaultExecutorProvider {
		t.Fatalf("envelope/provider = %s", raw)
	}
	if len(decoded.Result.Models) != 3 {
		t.Fatalf("host decoded %d models, want 3: %s", len(decoded.Result.Models), raw)
	}
	for _, model := range decoded.Result.Models {
		if model.ID == "" || model.Type == "" || model.OwnedBy != "Antigravity" {
			t.Fatalf("model lost fields through the wire: %+v", model)
		}
	}
}

func TestExecutorCapabilitiesAreOptIn(t *testing.T) {
	loadMirror(t)
	off := registrationCapabilities()
	if off.ModelRegistrar || off.ModelProvider {
		t.Fatalf("model capabilities declared while executor is off: %+v", off)
	}
	if !off.RequestInterceptor || !off.ManagementAPI {
		t.Fatalf("existing capabilities were dropped: %+v", off)
	}
}

// The mirrored provider in the fixture is still enabled, so the plugin must
// withhold its models until the operator either namespaces them or disables the
// original provider. Publishing duplicate model IDs would let the host load
// balance across both paths.
func TestExecutorWithholdsModelsWhileMirroredProviderIsLive(t *testing.T) {
	loadMirror(t)
	settings := currentPluginSettings()
	settings.ExecutorEnabled = true
	settings.ModelNamespace = ""
	withSettings(t, settings)

	if _, found := resolveProviderSpec(); !found {
		t.Fatal("fixture provider was not mirrored")
	}
	caps := registrationCapabilities()
	if caps.ModelRegistrar || caps.ModelProvider {
		t.Fatalf("models published while the mirrored provider is still live: %+v", caps)
	}
	if got := currentModelResponse(); len(got.Models) != 0 {
		t.Fatalf("model list should be empty, got %+v", got.Models)
	}

	diagnostics := scanProviderDiagnostics()
	if diagnostics.ModelsServed {
		t.Fatal("models_served should be false under collision risk")
	}
	var warned bool
	for _, warning := range diagnostics.Warnings {
		if strings.Contains(warning, "models are withheld") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("missing collision warning: %+v", diagnostics.Warnings)
	}

	// A test namespace removes the collision, so serving becomes allowed.
	namespaceSettings := currentPluginSettings()
	namespaceSettings.ModelNamespace = "spike."
	withSettings(t, namespaceSettings)
	storeProviderSpec(providerSpec{}, false)
	if _, found := resolveProviderSpec(); !found {
		t.Fatal("provider spec was not re-mirrored")
	}
	named := registrationCapabilities()
	if !named.ModelRegistrar || !named.ModelProvider {
		t.Fatalf("namespaced executor should declare model capabilities: %+v", named)
	}
	served := currentModelResponse()
	if len(served.Models) != 3 {
		t.Fatalf("namespaced model count = %d, want 3", len(served.Models))
	}
	for _, model := range served.Models {
		if !strings.HasPrefix(model.ID, "spike./") && !strings.HasPrefix(model.ID, "spike.") {
			t.Fatalf("namespace missing from %q", model.ID)
		}
	}
}

func withSettings(t *testing.T, settings PluginSettings) {
	t.Helper()
	previous := currentPluginSettings()
	pluginSettingsMu.Lock()
	pluginSettings = normalizeSettings(settings)
	pluginSettingsMu.Unlock()
	t.Cleanup(func() {
		pluginSettingsMu.Lock()
		pluginSettings = previous
		pluginSettingsMu.Unlock()
	})
}

func TestExecutorProviderKeyIsNormalised(t *testing.T) {
	if got := normalizeProviderKey(" AGY Bridge/Prod "); got != "AGY-Bridge-Prod" {
		t.Fatalf("normalizeProviderKey = %q", got)
	}
	settings := normalizeSettings(PluginSettings{})
	if settings.ExecutorProvider != defaultExecutorProvider {
		t.Fatalf("default provider key = %q", settings.ExecutorProvider)
	}
}

func TestDiagnosticsReportsMirroredProvider(t *testing.T) {
	loadMirror(t)
	diagnostics := scanProviderDiagnostics()
	if diagnostics.MirroredProvider != "Antigravity" {
		t.Fatalf("mirrored provider = %q", diagnostics.MirroredProvider)
	}
	if diagnostics.MirroredModelCount != 3 {
		t.Fatalf("mirrored models = %d, want 3", diagnostics.MirroredModelCount)
	}
	if !diagnostics.MirroredHasAPIKey {
		t.Fatal("mirrored api key presence not reported")
	}
	if diagnostics.ExecutorEnabled {
		t.Fatal("executor must stay off by default")
	}
	if diagnostics.ExecutorProvider != defaultExecutorProvider {
		t.Fatalf("executor provider = %q", diagnostics.ExecutorProvider)
	}

	// The mirrored base URL is internal and must not reach the public page.
	public := publicProviderDiagnostics(diagnostics)
	if public.MirroredBaseURL != "" {
		t.Fatalf("public diagnostics leaked base url: %q", public.MirroredBaseURL)
	}
	page := publicStatusPage(diagnostics)
	for _, expected := range []string{"Mirrored provider", "Antigravity", "3 models", "off, routing unchanged"} {
		if !strings.Contains(page, expected) {
			t.Fatalf("public page missing %q: %s", expected, page)
		}
	}
}
