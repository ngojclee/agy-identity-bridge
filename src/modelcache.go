package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// modelCacheFile stores model IDs fetched directly from the upstream /models
// endpoint. The cache lets the plugin serve models even when the original
// provider entry is removed from CPA config, and keeps the list fresh without
// re-discovering it from a disabled or deleted provider block.
const modelCacheFileName = "agy-identity-bridge-models.json"

type modelCache struct {
	FetchedAt time.Time     `json:"fetched_at"`
	BaseURL   string        `json:"base_url"`
	Models    []string      `json:"models"`
	Catalog   []cachedModel `json:"catalog,omitempty"`
}

type cachedModel struct {
	ID               string   `json:"id"`
	Image            bool     `json:"image,omitempty"`
	ThinkingLevels   []string `json:"thinking_levels,omitempty"`
	InputModalities  []string `json:"input_modalities,omitempty"`
	OutputModalities []string `json:"output_modalities,omitempty"`
}

func modelCachePath() string {
	return filepath.Join(filepath.Dir(usageDataPath()), modelCacheFileName)
}

func loadModelCache() []string {
	raw, errRead := os.ReadFile(modelCachePath())
	if errRead != nil {
		return nil
	}
	var cache modelCache
	if errUnmarshal := json.Unmarshal(raw, &cache); errUnmarshal != nil {
		return nil
	}
	out := make([]string, 0, len(cache.Models))
	for _, id := range cache.Models {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func loadModelCatalog() []modelSpec {
	raw, errRead := os.ReadFile(modelCachePath())
	if errRead != nil {
		return nil
	}
	var cache modelCache
	if errUnmarshal := json.Unmarshal(raw, &cache); errUnmarshal != nil {
		return nil
	}
	if len(cache.Catalog) == 0 {
		return cachedModelSpecsFromIDs(cache.Models)
	}
	out := make([]modelSpec, 0, len(cache.Catalog))
	for _, item := range cache.Catalog {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		levels := normalizeThinkingLevels(item.ThinkingLevels)
		var thinking *thinkingSpec
		if len(levels) > 0 {
			thinking = &thinkingSpec{Levels: levels}
		}
		out = append(out, modelSpec{
			Name:             id,
			Image:            item.Image,
			Thinking:         thinking,
			InputModalities:  append([]string(nil), item.InputModalities...),
			OutputModalities: append([]string(nil), item.OutputModalities...),
		})
	}
	return out
}

func cachedModelSpecsFromIDs(ids []string) []modelSpec {
	out := make([]modelSpec, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		levels := defaultThinkingLevelsForModel(id)
		var thinking *thinkingSpec
		if len(levels) > 0 {
			thinking = &thinkingSpec{Levels: levels}
		}
		out = append(out, modelSpec{
			Name:     id,
			Image:    strings.Contains(strings.ToLower(id), "image"),
			Thinking: thinking,
		})
	}
	return out
}

func saveModelCache(baseURL string, models []string) {
	if len(models) == 0 {
		return
	}
	saveModelCatalog(baseURL, cachedModelSpecsFromIDs(models))
}

func saveModelCatalog(baseURL string, models []modelSpec) {
	if len(models) == 0 {
		return
	}
	ids := make([]string, 0, len(models))
	catalog := make([]cachedModel, 0, len(models))
	for _, model := range models {
		id := strings.TrimSpace(model.Name)
		if id == "" {
			id = strings.TrimSpace(model.Alias)
		}
		if id == "" {
			continue
		}
		ids = append(ids, id)
		var levels []string
		if model.Thinking != nil {
			levels = normalizeThinkingLevels(model.Thinking.Levels)
		} else {
			levels = defaultThinkingLevelsForModel(id)
		}
		catalog = append(catalog, cachedModel{
			ID:               id,
			Image:            model.Image,
			ThinkingLevels:   levels,
			InputModalities:  normalizeModalities(model.InputModalities),
			OutputModalities: normalizeModalities(model.OutputModalities),
		})
	}
	if len(ids) == 0 {
		return
	}
	cache := modelCache{
		FetchedAt: time.Now().UTC(),
		BaseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		Models:    uniqueStrings(ids),
		Catalog:   catalog,
	}
	raw, errMarshal := json.Marshal(cache)
	if errMarshal != nil {
		return
	}
	path := modelCachePath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, raw, 0o600)
}

func normalizeThinkingLevels(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, level := range raw {
		level = strings.ToLower(strings.TrimSpace(level))
		if level == "" {
			continue
		}
		if _, exists := seen[level]; exists {
			continue
		}
		seen[level] = struct{}{}
		out = append(out, level)
	}
	return out
}
