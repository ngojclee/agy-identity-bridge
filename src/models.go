package main

import (
	"encoding/json"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

// modelRegistrationResponse mirrors pluginapi.ModelRegistrationResponse. The
// host decodes untagged Go fields, so the tags below use Go field names on
// purpose.
type modelRegistrationResponse struct {
	Provider string      `json:"Provider"`
	Models   []modelInfo `json:"Models"`
}

// resolveProviderSpec returns the mirrored provider, refreshing the cache from
// the currently loaded CPA config when needed.
func resolveProviderSpec() (providerSpec, bool) {
	if spec, found := cachedProviderSpec(); found {
		return spec, true
	}
	snapshot := currentConfigSnapshot()
	if len(snapshot.ConfigYAML) == 0 {
		return providerSpec{}, false
	}
	root, errParse := parseYAMLMap(snapshot.ConfigYAML)
	if errParse != nil {
		return providerSpec{}, false
	}
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if found {
		storeProviderSpec(spec, true)
	}
	return spec, found
}

func currentModelResponse() modelRegistrationResponse {
	settings := currentPluginSettings()
	spec, found := resolveProviderSpec()
	if !found || !canServeModels(settings, spec) {
		return modelRegistrationResponse{Provider: settings.ExecutorProvider, Models: []modelInfo{}}
	}
	// CPA asks for models after registering this plugin. Retrying here makes
	// the plugin-owned auth record self-heal when a lifecycle-time callback
	// was too early for the host auth manager.
	if errAuth := ensureAuthRecord(spec, settings); errAuth != nil {
		hostLog("warn", "auth record creation failed during model registration", map[string]any{
			"error": errAuth.Error(),
		})
		recordDashboardEvent("error", "Plugin executor auth record could not be created during model registration")
	}
	return modelRegistrationResponse{
		Provider: settings.ExecutorProvider,
		Models:   spec.modelInfos(settings.ModelNamespace),
	}
}

func handleModelRegister() []byte {
	return okEnvelope(currentModelResponse())
}

func handleModelStatic() []byte {
	return okEnvelope(currentModelResponse())
}

// handleModelForAuth answers per-credential discovery. The mirrored provider
// owns one upstream base URL, so the answer matches the static list.
func handleModelForAuth(request []byte) ([]byte, error) {
	var payload map[string]any
	if len(request) > 0 {
		if errUnmarshal := json.Unmarshal(request, &payload); errUnmarshal != nil {
			return errorEnvelope("parse_error", errUnmarshal.Error()), nil
		}
	}
	return okEnvelope(currentModelResponse()), nil
}

func modelMethodHandled(method string) bool {
	switch method {
	case pluginabi.MethodModelRegister, pluginabi.MethodModelStatic, pluginabi.MethodModelForAuth:
		return true
	default:
		return false
	}
}
