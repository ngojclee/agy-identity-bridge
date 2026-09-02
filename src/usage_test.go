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

func TestCanonicalUsageProviderNameCollapsesDuplicatePresentation(t *testing.T) {
	for input, want := range map[string]string{
		"ln.Antigravity-ln.Antigravity": "ln.Antigravity",
		"ln.Antigravity executor":       "ln.Antigravity",
		"ln.Antigravity":                "ln.Antigravity",
	} {
		if got := canonicalUsageProviderName(input); got != want {
			t.Fatalf("canonicalUsageProviderName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestUsageDashboardHTMLIncludesFiltersAndOverview(t *testing.T) {
	resetUsageState()
	t.Cleanup(resetUsageState)

	usageState.Lock()
	usageState.records = []usageRecord{
		{
			At:          time.Now().UTC(),
			Provider:    "Antigravity",
			Model:       "agy/gemini-3.7-flash-high",
			ClientApp:   "codex",
			Principal:   strings.Repeat("a", 64),
			Mode:        "execute",
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
		"Last 5 hours",
		"Last 7 days",
		"Last 30 days",
		"Current month",
		"By minute",
		"By hour",
		"By week",
		"By month",
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

func TestUsageFilterPeriodsAndBuckets(t *testing.T) {
	now := time.Now().UTC()
	records := []usageRecord{
		{At: now.Add(-2 * time.Hour), ClientApp: "hermes", TotalTokens: 20},
		{At: now.Add(-8 * 24 * time.Hour), ClientApp: "hermes", TotalTokens: 20},
		{At: now.Add(-31 * 24 * time.Hour), ClientApp: "hermes", TotalTokens: 20},
	}
	for _, test := range []struct {
		period string
		want   int
	}{
		{"last_5_hours", 1},
		{"last_7_days", 1},
		{"last_30_days", 2},
	} {
		filter := normalizeUsageFilter(url.Values{"period": {test.period}, "bucket": {"day"}})
		count := 0
		for _, record := range records {
			if recordMatchesUsageFilter(record, filter) {
				count++
			}
		}
		if count != test.want {
			t.Fatalf("%s matched %d records, want %d", test.period, count, test.want)
		}
	}

	for _, bucket := range []string{"minute", "hour", "day", "week", "month"} {
		label, order := usageBucketLabel(now, bucket)
		if label == "" || order.IsZero() {
			t.Fatalf("bucket %s returned empty label/order", bucket)
		}
	}
}
