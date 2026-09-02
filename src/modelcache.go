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
	FetchedAt time.Time `json:"fetched_at"`
	BaseURL   string    `json:"base_url"`
	Models    []string  `json:"models"`
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

func saveModelCache(baseURL string, models []string) {
	if len(models) == 0 {
		return
	}
	cache := modelCache{
		FetchedAt: time.Now().UTC(),
		BaseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		Models:    append([]string(nil), models...),
	}
	raw, errMarshal := json.Marshal(cache)
	if errMarshal != nil {
		return
	}
	path := modelCachePath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, raw, 0o600)
}
