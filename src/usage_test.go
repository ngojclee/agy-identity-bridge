package main

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUsageTelemetryRecordsPromptCompletionAndCacheHits(t *testing.T) {
	resetUsageState()
	t.Cleanup(resetUsageState)

	recordUsageFromExecutorResponse([]byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20,"prompt_tokens_details":{"cached_tokens":4},"cache_hit":true}}`),
		nil, "Antigravity", "agy/gemini-3.7-flash-high", "codex", "principal-abc", "execute")

	data := usageDashboardData(providerDiagnostics{}, normalizeUsageFilter(url.Values{}))
	if data.Summary.Requests != 1 {
		t.Fatalf("requests = %d, want 1", data.Summary.Requests)
	}
	if data.Summary.PromptTokens != 12 || data.Summary.CompletionTokens != 8 || data.Summary.TotalTokens != 20 {
		t.Fatalf("summary tokens = %+v", data.Summary)
	}
	if data.Summary.CachedTokens != 4 || data.Summary.CacheHits != 1 {
		t.Fatalf("cache stats = %+v", data.Summary)
	}
	if data.Summary.ModelCount != 1 || data.Summary.SourceCount != 1 || data.Summary.PrincipalCount != 1 {
		t.Fatalf("summary cardinality = %+v", data.Summary)
	}
}

func TestUsageTelemetryParsesStreamUsageText(t *testing.T) {
	resetUsageState()
	t.Cleanup(resetUsageState)

	streamPayload := []byte("data: {\"choices\":[],\"usage\":{\"input_tokens\":5,\"output_tokens\":7,\"total_tokens\":12,\"cached_tokens\":2}}\n")
	recordUsageFromExecutorResponse(streamPayload, nil, "Antigravity", "agy/gemini-3.7-flash-high", "hermes", "principal-def", "stream")

	data := usageDashboardData(providerDiagnostics{}, normalizeUsageFilter(url.Values{}))
	if data.Summary.InputTokens != 5 || data.Summary.OutputTokens != 7 || data.Summary.TotalTokens != 12 {
		t.Fatalf("stream usage summary = %+v", data.Summary)
	}
	if data.Summary.CachedTokens != 2 {
		t.Fatalf("stream cached tokens = %+v", data.Summary)
	}
}

func TestUsageDashboardHTMLIncludesFiltersAndOverview(t *testing.T) {
	resetUsageState()
	t.Cleanup(resetUsageState)

	usageState.Lock()
	usageState.records = []usageRecord{
		{
			At:         time.Now().UTC(),
			Provider:   "Antigravity",
			Model:      "agy/gemini-3.7-flash-high",
			ClientApp:  "codex",
			Principal:  strings.Repeat("a", 64),
			Mode:       "execute",
			TotalTokens: 20,
		},
	}
	usageState.Unlock()

	page := usageDashboardHTML(usageDashboardData(providerDiagnostics{
		MirroredProvider:        "Antigravity",
		ReplacementMode:         "active",
		ExecutorProvider:        "ln.Antigravity",
		ProviderOriginalEnabled: false,
	}, normalizeUsageFilter(url.Values{})))
	for _, expected := range []string{
		"AGY Usage View",
		"Current month",
		"By hour",
		"All sources",
		"Usage overview",
		"Top models",
		"Top sources",
		"Recent usage",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("usage dashboard missing %q", expected)
		}
	}
}

