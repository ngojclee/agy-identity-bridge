package main

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PluginSettings holds the agy-identity-bridge config block from CPA's config.yaml.
// Operator sets match_name, match_url, and optionally match_api_key under
// plugins.configs.agy-identity-bridge.
type PluginSettings struct {
	MatchName    string `yaml:"match_name" json:"match_name"`
	MatchURL     string `yaml:"match_url" json:"match_url"`
	MatchAPIKey  string `yaml:"match_api_key" json:"match_api_key"`
	MatchProvider string `yaml:"match_provider" json:"match_provider"`
}

var pluginSettings PluginSettings

func decodePluginSettings(configYAML []byte) PluginSettings {
	out := PluginSettings{}
	if len(configYAML) == 0 {
		return out
	}
	var root struct {
		Plugins *struct {
			Configs map[string]PluginSettings `yaml:"configs"`
		} `yaml:"plugins"`
	}
	if errYAML := yaml.Unmarshal(configYAML, &root); errYAML != nil {
		return out
	}
	if root.Plugins != nil {
		if cfg, ok := root.Plugins.Configs["agy-identity-bridge"]; ok {
			out = cfg
		}
	}
	if out.MatchName == "" && out.MatchURL == "" && out.MatchAPIKey == "" {
		if cfg, ok := decodeConfigFile(); ok {
			out = cfg
		}
	}
	return out
}

func decodeConfigFile() (PluginSettings, bool) {
	cfgPath := filepath.Join("/CLIProxyAPI", "config.yaml")
	if _, errStat := os.Stat(cfgPath); errStat != nil {
		return PluginSettings{}, false
	}
	raw, errRead := os.ReadFile(cfgPath)
	if errRead != nil {
		return PluginSettings{}, false
	}
	var root struct {
		Plugins *struct {
			Configs map[string]PluginSettings `yaml:"configs"`
		} `yaml:"plugins"`
	}
	if errYAML := yaml.Unmarshal(raw, &root); errYAML != nil {
		return PluginSettings{}, false
	}
	if root.Plugins != nil {
		if cfg, ok := root.Plugins.Configs["agy-identity-bridge"]; ok {
			return cfg, true
		}
	}
	return PluginSettings{}, false
}

func (s PluginSettings) hmacSecret() string {
	if s.MatchAPIKey != "" {
		return s.MatchAPIKey
	}
	return os.Getenv("AGY_PLUGIN_SECRET")
}

func (s PluginSettings) shouldIntercept(providerName, providerURL string) bool {
	nameMatch := s.MatchName != "" && strings.Contains(
		strings.ToLower(providerName), strings.ToLower(s.MatchName))
	urlMatch := s.MatchURL != "" && strings.Contains(
		strings.ToLower(providerURL), strings.ToLower(s.MatchURL))

	if s.MatchName != "" && s.MatchURL == "" {
		return nameMatch
	}
	if s.MatchName == "" && s.MatchURL != "" {
		return urlMatch
	}
	return nameMatch || urlMatch
}
