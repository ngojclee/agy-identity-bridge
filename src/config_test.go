package main

import "testing"

func TestDecodePluginSettingsSupportsCPAConfigShapes(t *testing.T) {
	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "full root",
			raw: `
plugins:
  enabled: true
  configs:
    agy-identity-bridge:
      auto_discover: false
      include_native_antigravity: false
      match_mode: all
      match_name: Antigravity
      match_url: http://agy.internal/v1
      match_api_key: provider-key
      match_providers:
        - "*agy*"
`,
		},
		{
			name: "direct plugin subtree",
			raw: `
auto_discover: false
match_name: Custom AGY
`,
		},
		{
			name: "legacy plugin subtree",
			raw: `
plugins:
  agy-identity-bridge:
    match_name: Legacy Antigravity
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := decodePluginSettings([]byte(tt.raw))
			if tt.name == "full root" {
				if settings.AutoDiscover || settings.IncludeNativeAntigravity {
					t.Fatalf("explicit false values were lost: %+v", settings)
				}
				if settings.MatchMode != "all" || settings.MatchName != "Antigravity" {
					t.Fatalf("full root settings = %+v", settings)
				}
				if len(settings.MatchProviders) != 1 || settings.MatchProviders[0] != "*agy*" {
					t.Fatalf("match providers = %#v", settings.MatchProviders)
				}
				return
			}
			if settings.MatchName == "" {
				t.Fatalf("settings did not decode: %+v", settings)
			}
			if tt.name == "direct plugin subtree" && settings.AutoDiscover {
				t.Fatalf("explicit auto_discover=false was lost: %+v", settings)
			}
			if tt.name == "legacy plugin subtree" && !settings.AutoDiscover {
				t.Fatalf("legacy config should retain the automatic default: %+v", settings)
			}
		})
	}
}

func TestDecodePluginSettingsDefaultsToAutomaticAntigravityDiscovery(t *testing.T) {
	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")
	settings := decodePluginSettings([]byte(`plugins: {}`))
	if !settings.AutoDiscover {
		t.Fatal("auto_discover default = false, want true")
	}
	if !settings.IncludeNativeAntigravity {
		t.Fatal("include_native_antigravity default = false, want true")
	}
	if settings.MatchMode != "any" {
		t.Fatalf("match_mode = %q, want any", settings.MatchMode)
	}
}

func TestDecodePluginSettingsMergesSingleProviderAlias(t *testing.T) {
	t.Setenv("CPA_CONFIG_PATH", "Z:\\missing\\cpa-config.yaml")
	settings := decodePluginSettings([]byte(`
match_provider: Antigravity
match_providers:
  - "*agy2api*"
`))
	if len(settings.MatchProviders) != 2 {
		t.Fatalf("match providers = %#v, want two selectors", settings.MatchProviders)
	}
	if settings.configuredSelectorCount() != 2 {
		t.Fatalf("configured selector count = %d, want 2", settings.configuredSelectorCount())
	}
}
