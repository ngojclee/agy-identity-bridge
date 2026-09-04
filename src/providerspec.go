package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// providerSpec mirrors one openai-compatibility provider exactly as
// CLIProxyAPI configures it, so the plugin can stand in for that provider
// without inventing any value the operator did not write.
type providerSpec struct {
	Name           string
	Prefix         string
	BaseURL        string
	APIKeys        []string
	Headers        map[string]string
	Priority       int
	SourcePriority int
	DisableCooling bool
	Models         []modelSpec
	// Enabled reports whether the mirrored provider is still live in CPA
	// config. The executor must not publish the same model IDs while it is.
	Enabled bool
}

type modelSpec struct {
	Name             string
	Alias            string
	Image            bool
	InputModalities  []string
	OutputModalities []string
	Thinking         *thinkingSpec
}

type thinkingSpec struct {
	Min            int      `json:"Min"`
	Max            int      `json:"Max"`
	ZeroAllowed    bool     `json:"ZeroAllowed"`
	DynamicAllowed bool     `json:"DynamicAllowed"`
	Levels         []string `json:"Levels"`
}

// modelInfo mirrors pluginapi.ModelInfo field names. The host decodes this
// with untagged Go fields, so snake_case tags would silently drop every value.
type modelInfo struct {
	ID                        string        `json:"ID"`
	Object                    string        `json:"Object"`
	Created                   int64         `json:"Created"`
	OwnedBy                   string        `json:"OwnedBy"`
	Type                      string        `json:"Type"`
	DisplayName               string        `json:"DisplayName"`
	SupportedInputModalities  []string      `json:"SupportedInputModalities"`
	SupportedOutputModalities []string      `json:"SupportedOutputModalities"`
	Thinking                  *thinkingSpec `json:"Thinking"`
	UserDefined               bool          `json:"UserDefined"`
}

var providerSpecCache struct {
	sync.RWMutex
	spec    providerSpec
	found   bool
	refresh time.Time
}

func storeProviderSpec(spec providerSpec, found bool) {
	providerSpecCache.Lock()
	providerSpecCache.spec = spec
	providerSpecCache.found = found
	providerSpecCache.refresh = time.Now().UTC()
	providerSpecCache.Unlock()
}

func cachedProviderSpec() (providerSpec, bool) {
	providerSpecCache.RLock()
	defer providerSpecCache.RUnlock()
	return providerSpecCache.spec, providerSpecCache.found
}

// openAICompatEntries returns the raw provider maps so both discovery and the
// executor can read the same records without parsing twice.
func openAICompatEntries(root map[string]any) []map[string]any {
	if root == nil {
		return nil
	}
	raw, ok := mapValue(root, "openai-compatibility", "openai_compatibility")
	if !ok {
		return nil
	}
	entries := make([]map[string]any, 0)
	for _, item := range asSlice(raw) {
		if providerMap := asMap(item); providerMap != nil {
			entries = append(entries, providerMap)
		}
	}
	return entries
}

func compatAPIKeys(providerMap map[string]any) []string {
	apiKeys := make([]string, 0)
	rawKeys, exists := mapValue(providerMap, "api-key-entries", "api_key_entries")
	if !exists {
		return apiKeys
	}
	for _, rawKey := range asSlice(rawKeys) {
		keyMap := asMap(rawKey)
		if keyMap == nil {
			continue
		}
		if key, ok := stringValue(keyMap, "api-key", "api_key", "key"); ok && key != "" {
			apiKeys = append(apiKeys, key)
		}
	}
	return uniqueStrings(apiKeys)
}

func compatHeaders(providerMap map[string]any) map[string]string {
	raw, ok := mapValue(providerMap, "headers")
	if !ok {
		return nil
	}
	headerMap := asMap(raw)
	if headerMap == nil {
		return nil
	}
	out := make(map[string]string, len(headerMap))
	for key, value := range headerMap {
		if text, ok := value.(string); ok {
			if strings.TrimSpace(key) == "" || text == "" {
				continue
			}
			out[strings.TrimSpace(key)] = strings.TrimSpace(text)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func compatModels(providerMap map[string]any) []modelSpec {
	raw, ok := mapValue(providerMap, "models")
	if !ok {
		return nil
	}
	out := make([]modelSpec, 0)
	for _, item := range asSlice(raw) {
		modelMap := asMap(item)
		if modelMap == nil {
			continue
		}
		spec := modelSpec{}
		spec.Name, _ = stringValue(modelMap, "name")
		spec.Alias, _ = stringValue(modelMap, "alias")
		spec.Image, _ = boolValue(modelMap, "image")
		spec.InputModalities, _ = stringSliceValue(modelMap, "input-modalities", "input_modalities")
		spec.OutputModalities, _ = stringSliceValue(modelMap, "output-modalities", "output_modalities")
		if rawThinking, exists := mapValue(modelMap, "thinking"); exists {
			if thinkingMap := asMap(rawThinking); thinkingMap != nil {
				thinking := &thinkingSpec{}
				thinking.Min, _ = intValue(thinkingMap, "min")
				thinking.Max, _ = intValue(thinkingMap, "max")
				thinking.ZeroAllowed, _ = boolValue(thinkingMap, "zero-allowed", "zero_allowed")
				thinking.DynamicAllowed, _ = boolValue(thinkingMap, "dynamic-allowed", "dynamic_allowed")
				thinking.Levels, _ = stringSliceValue(thinkingMap, "levels")
				spec.Thinking = thinking
			}
		}
		if spec.Name == "" && spec.Alias == "" {
			continue
		}
		out = append(out, spec)
	}
	return out
}

// extractProviderSpec picks the configured provider the plugin owns, preferring
// a live one and falling back to a disabled match so the operator can mirror a
// provider they have already switched off.
func extractProviderSpec(root map[string]any, settings PluginSettings) (providerSpec, bool) {
	// The plugin serves models from the upstream /models endpoint it fetched
	// itself. A provider block that has no models (or has been removed) must
	// not zero out the published list, so the cached IDs are merged in below.
	var fallback providerSpec
	haveFallback := false
	for _, providerMap := range openAICompatEntries(root) {
		disabled, _ := boolValue(providerMap, "disabled")
		name, _ := stringValue(providerMap, "name")
		baseURL, _ := stringValue(providerMap, "base-url", "base_url", "url")
		prefix, _ := stringValue(providerMap, "prefix")
		apiKeys := compatAPIKeys(providerMap)
		item := discoveredProvider{
			Name:        name,
			ProviderKey: name,
			URL:         baseURL,
			Prefix:      prefix,
			Source:      "openai-compatibility",
			Active:      !disabled,
			Disabled:    disabled,
			APIKeys:     apiKeys,
		}
		if matched, _ := matchDiscoveredProvider(settings, item); !matched {
			continue
		}
		priority, _ := intValue(providerMap, "priority")
		// The plugin provider is a replacement, not a peer: give it enough
		// headroom to win against the original if a future CPA version starts
		// honoring priority during model collision resolution. The original's
		// priority is preserved as an offset so relative ordering of multiple
		// mirrors stays meaningful.
		mirroredPriority := maxInt(priority+100, 10)
		cooling, _ := boolValue(providerMap, "disable-cooling", "disable_cooling")
		spec := providerSpec{
			Name:           name,
			Prefix:         prefix,
			BaseURL:        baseURL,
			APIKeys:        apiKeys,
			Headers:        compatHeaders(providerMap),
			Priority:       mirroredPriority,
			SourcePriority: priority,
			DisableCooling: cooling,
			Models:         compatModels(providerMap),
			Enabled:        !disabled,
		}
		if !disabled {
			return spec, true
		}
		if !haveFallback {
			fallback = spec
			haveFallback = true
		}
	}
	if haveFallback {
		if len(fallback.Models) == 0 {
			fallback.Models = cachedModelSpecs(fallback.BaseURL)
		}
		return fallback, true
	}
	cached := cachedProviderSpecFromCache()
	return cached, cached.BaseURL != ""
}

// cachedModelSpecs converts cached model IDs into editable model specs so the
// provider editor and executor keep serving the same list.
func cachedModelSpecs(baseURL string) []modelSpec {
	catalog := loadModelCatalog()
	if len(catalog) == 0 {
		return nil
	}
	return catalog
}

// cachedProviderSpecFromCache restores a serviceable spec purely from the
// persisted model cache plus the current plugin settings. It is used when the
// original provider block has been removed from CPA config entirely.
func cachedProviderSpecFromCache() providerSpec {
	settings := currentPluginSettings()
	ids := loadModelCache()
	if len(ids) == 0 {
		return providerSpec{}
	}
	return providerSpec{
		Name:     settings.ExecutorProvider,
		Prefix:   settings.ModelNamespace,
		Models:   cachedModelSpecs(""),
		Enabled:  false,
		Priority: 110,
	}
}

// canServeModels is the collision guard. Publishing the mirrored provider's own
// model IDs while that provider is still enabled would leave two providers
// serving the same model, and CLIProxyAPI would load balance across them, so
// some requests would silently bypass the bridge. Until the operator either
// disables the mirrored provider or asks for a test namespace, the plugin keeps
// its models out of the registry.
func canServeModels(settings PluginSettings, spec providerSpec) bool {
	if !settings.ExecutorEnabled {
		return false
	}
	return strings.TrimSpace(settings.ModelNamespace) != "" || !spec.Enabled
}

// modelInfos reproduces CLIProxyAPI's own model metadata mapping: alias wins
// over name and image models switch type. Thinking metadata is passed through
// exactly as declared by the provider or endpoint catalog; the bridge must not
// invent effort levels for an otherwise unannotated model.
func (s providerSpec) modelInfos(namespace string) []modelInfo {
	created := time.Now().Unix()
	out := make([]modelInfo, 0, len(s.Models))
	for _, model := range s.Models {
		modelID := model.Alias
		if modelID == "" {
			modelID = model.Name
		}
		modelID = strings.TrimSpace(modelID)
		if modelID == "" {
			continue
		}
		modelType := "openai-compatibility"
		if model.Image {
			modelType = "openai-image"
		}
		out = append(out, modelInfo{
			ID:                        modelID,
			Object:                    "model",
			Created:                   created,
			OwnedBy:                   s.Name,
			Type:                      modelType,
			DisplayName:               modelID,
			SupportedInputModalities:  normalizeModalities(model.InputModalities),
			SupportedOutputModalities: normalizeModalities(model.OutputModalities),
			Thinking:                  effectiveThinking(model.Thinking),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func effectiveThinking(spec *thinkingSpec) *thinkingSpec {
	if spec == nil {
		return nil
	}
	out := *spec
	out.Levels = normalizeThinkingLevels(spec.Levels)
	if spec.ZeroAllowed && !containsThinkingLevel(out.Levels, "none") {
		out.Levels = append([]string{"none"}, out.Levels...)
	}
	return &out
}

func containsThinkingLevel(levels []string, want string) bool {
	for _, level := range levels {
		if strings.EqualFold(strings.TrimSpace(level), want) {
			return true
		}
	}
	return false
}

// defaultThinkingLevelsForModel is intentionally narrow. These are the
// family aliases owned by the agy2api contract; concrete suffixed model IDs
// and unknown models must keep their source metadata unchanged.
func defaultThinkingLevelsForModel(model string) []string {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "gemini-3.1-pro":
		return []string{"none", "low", "high"}
	case "gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.8-flash":
		return []string{"none", "low", "medium", "high"}
	case "gemini-image":
		return []string{"none", "low", "high"}
	default:
		return nil
	}
}

// modelInfosForRegistration returns bare model IDs for CPA's plugin host.
// CPA reconciles these IDs through the plugin-owned auth record and applies
// that record's prefix itself. Returning prefixed IDs here would produce
// duplicate public IDs such as agy/agy/model.
func (s providerSpec) modelInfosForRegistration(namespace string) []modelInfo {
	return s.modelInfos(namespace)
}

// modelNamespace selects the prefix written to the plugin-owned auth record.
// An explicit test namespace wins; otherwise the original provider prefix is
// preserved.
func modelNamespace(namespace, providerPrefix string) string {
	namespace = strings.TrimSpace(namespace)
	if namespace != "" {
		return strings.TrimSuffix(namespace, "/")
	}
	return strings.TrimSuffix(strings.TrimSpace(providerPrefix), "/")
}

func normalizeModalities(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		modality := strings.ToLower(strings.TrimSpace(item))
		if modality == "" {
			continue
		}
		if _, exists := seen[modality]; exists {
			continue
		}
		seen[modality] = struct{}{}
		out = append(out, modality)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// upstreamBaseURL keeps the provider URL exactly as configured.
func (s providerSpec) upstreamBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
}

// primaryAPIKey is the credential the executor presents upstream. CPA would
// rotate across entries; the mirror keeps the configured order and uses the
// first key, which matches a single-key provider such as the agy2api one.
func (s providerSpec) primaryAPIKey() string {
	if len(s.APIKeys) == 0 {
		return ""
	}
	return strings.TrimSpace(s.APIKeys[0])
}
