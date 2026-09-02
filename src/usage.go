package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type usageRecord struct {
	At               time.Time
	Provider         string
	Model            string
	ClientApp        string
	Principal        string
	Mode             string
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64
	InputTokens      int64
	OutputTokens     int64
	CachedTokens     int64
	CacheHit         bool
}

type usageTotals struct {
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64
	InputTokens      int64
	OutputTokens     int64
	CachedTokens     int64
	CacheHit         bool
}

var usageState struct {
	sync.RWMutex
	records []usageRecord
}

const maxUsageRecords = 2048

func recordUsageObservation(obs usageRecord) {
	if obs.At.IsZero() {
		obs.At = time.Now().UTC()
	}
	if obs.PromptTokens == 0 && obs.CompletionTokens == 0 && obs.TotalTokens == 0 &&
		obs.InputTokens == 0 && obs.OutputTokens == 0 && obs.CachedTokens == 0 && !obs.CacheHit {
		return
	}
	usageState.Lock()
	usageState.records = append(usageState.records, obs)
	if excess := len(usageState.records) - maxUsageRecords; excess > 0 {
		usageState.records = append([]usageRecord(nil), usageState.records[excess:]...)
	}
	usageState.Unlock()
}

func recentUsageRecords() []usageRecord {
	usageState.RLock()
	defer usageState.RUnlock()
	out := make([]usageRecord, len(usageState.records))
	copy(out, usageState.records)
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out
}

func resetUsageState() {
	usageState.Lock()
	usageState.records = nil
	usageState.Unlock()
}

func parseUsageObservation(body []byte, headers map[string][]string) (usageTotals, bool) {
	if totals, ok := parseUsageTotalsFromPayload(body); ok {
		return totals, true
	}
	if totals, ok := parseUsageTotalsFromHeaders(headers); ok {
		return totals, true
	}
	return usageTotals{}, false
}

func parseUsageTotalsFromPayload(raw []byte) (usageTotals, bool) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return usageTotals{}, false
	}
	if totals, ok := parseUsageTotalsFromJSON(raw); ok {
		return totals, true
	}
	if totals, ok := parseUsageTotalsFromStreamText(raw); ok {
		return totals, true
	}
	return usageTotals{}, false
}

func parseUsageTotalsFromJSON(raw []byte) (usageTotals, bool) {
	var decoded any
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		return usageTotals{}, false
	}
	return usageTotalsFromValue(decoded)
}

func parseUsageTotalsFromStreamText(raw []byte) (usageTotals, bool) {
	lines := strings.Split(string(raw), "\n")
	var combined usageTotals
	var found bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[DONE]" {
			continue
		}
		line = strings.TrimPrefix(line, "data:")
		line = strings.TrimSpace(line)
		if line == "" || line == "[DONE]" {
			continue
		}
		if totals, ok := parseUsageTotalsFromJSON([]byte(line)); ok {
			combined = mergeUsageTotals(combined, totals)
			found = true
		}
	}
	if found {
		return combined, true
	}
	return usageTotals{}, false
}

func usageTotalsFromValue(value any) (usageTotals, bool) {
	raw := asMap(value)
	if raw == nil {
		if slice := asSlice(value); slice != nil {
			var combined usageTotals
			var found bool
			for _, item := range slice {
				totals, ok := usageTotalsFromValue(item)
				if !ok {
					continue
				}
				combined = mergeUsageTotals(combined, totals)
				found = true
			}
			if found {
				return combined, true
			}
		}
		return usageTotals{}, false
	}

	if totals, ok := usageTotalsFromUsageObject(raw); ok {
		return totals, true
	}
	for _, key := range []string{"usage", "result", "data", "response", "body", "payload"} {
		if nested, ok := mapValue(raw, key); ok {
			if totals, found := usageTotalsFromValue(nested); found {
				return totals, true
			}
		}
	}
	return usageTotals{}, false
}

func usageTotalsFromUsageObject(raw map[string]any) (usageTotals, bool) {
	if raw == nil {
		return usageTotals{}, false
	}
	var totals usageTotals
	totals.PromptTokens = int64FromAny(raw["prompt_tokens"])
	totals.CompletionTokens = int64FromAny(raw["completion_tokens"])
	totals.TotalTokens = int64FromAny(raw["total_tokens"])
	totals.InputTokens = int64FromAny(raw["input_tokens"])
	totals.OutputTokens = int64FromAny(raw["output_tokens"])
	totals.CachedTokens = int64FromAny(raw["cached_tokens"])
	totals.CacheHit = boolFromAny(raw["cache_hit"])

	if promptDetails := asMap(raw["prompt_tokens_details"]); promptDetails != nil {
		if cached := int64FromAny(promptDetails["cached_tokens"]); cached > totals.CachedTokens {
			totals.CachedTokens = cached
		}
		if boolFromAny(promptDetails["cache_hit"]) {
			totals.CacheHit = true
		}
	}
	if completionDetails := asMap(raw["completion_tokens_details"]); completionDetails != nil {
		if cached := int64FromAny(completionDetails["cached_tokens"]); cached > totals.CachedTokens {
			totals.CachedTokens = cached
		}
		if boolFromAny(completionDetails["cache_hit"]) {
			totals.CacheHit = true
		}
	}
	if totals.InputTokens == 0 {
		totals.InputTokens = totals.PromptTokens
	}
	if totals.OutputTokens == 0 {
		totals.OutputTokens = totals.CompletionTokens
	}
	if totals.TotalTokens == 0 && (totals.PromptTokens > 0 || totals.CompletionTokens > 0) {
		totals.TotalTokens = totals.PromptTokens + totals.CompletionTokens
	}
	if totals.TotalTokens == 0 && (totals.InputTokens > 0 || totals.OutputTokens > 0) {
		totals.TotalTokens = totals.InputTokens + totals.OutputTokens
	}
	if totals.PromptTokens == 0 && totals.CompletionTokens == 0 && totals.TotalTokens == 0 &&
		totals.InputTokens == 0 && totals.OutputTokens == 0 && totals.CachedTokens == 0 && !totals.CacheHit {
		return usageTotals{}, false
	}
	return totals, true
}

func parseUsageTotalsFromHeaders(headers map[string][]string) (usageTotals, bool) {
	if len(headers) == 0 {
		return usageTotals{}, false
	}
	var totals usageTotals
	for key, values := range headers {
		value := firstHeaderValue(map[string][]string{key: values}, key)
		if value == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "x-usage-prompt-tokens":
			totals.PromptTokens = int64FromString(value)
		case "x-usage-completion-tokens":
			totals.CompletionTokens = int64FromString(value)
		case "x-usage-total-tokens":
			totals.TotalTokens = int64FromString(value)
		case "x-usage-input-tokens":
			totals.InputTokens = int64FromString(value)
		case "x-usage-output-tokens":
			totals.OutputTokens = int64FromString(value)
		case "x-usage-cached-tokens":
			totals.CachedTokens = int64FromString(value)
		case "x-usage-cache-hit", "x-cache-hit":
			totals.CacheHit = boolFromString(value)
		}
	}
	if totals.InputTokens == 0 {
		totals.InputTokens = totals.PromptTokens
	}
	if totals.OutputTokens == 0 {
		totals.OutputTokens = totals.CompletionTokens
	}
	if totals.TotalTokens == 0 && (totals.PromptTokens > 0 || totals.CompletionTokens > 0) {
		totals.TotalTokens = totals.PromptTokens + totals.CompletionTokens
	}
	if totals.TotalTokens == 0 && (totals.InputTokens > 0 || totals.OutputTokens > 0) {
		totals.TotalTokens = totals.InputTokens + totals.OutputTokens
	}
	if totals.PromptTokens == 0 && totals.CompletionTokens == 0 && totals.TotalTokens == 0 &&
		totals.InputTokens == 0 && totals.OutputTokens == 0 && totals.CachedTokens == 0 && !totals.CacheHit {
		return usageTotals{}, false
	}
	return totals, true
}

func mergeUsageTotals(left, right usageTotals) usageTotals {
	merged := left
	merged.PromptTokens += right.PromptTokens
	merged.CompletionTokens += right.CompletionTokens
	merged.TotalTokens += right.TotalTokens
	merged.InputTokens += right.InputTokens
	merged.OutputTokens += right.OutputTokens
	merged.CachedTokens += right.CachedTokens
	merged.CacheHit = merged.CacheHit || right.CacheHit
	return merged
}

func int64FromAny(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return int64(typed)
	case uint8:
		return int64(typed)
	case uint16:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		return int64(typed)
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed
		}
		if parsed, err := typed.Float64(); err == nil {
			return int64(parsed)
		}
	case string:
		return int64FromString(typed)
	}
	return 0
}

func int64FromString(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

func boolFromAny(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return boolFromString(typed)
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	}
	return false
}

func boolFromString(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1", "hit", "cache_hit":
		return true
	default:
		return false
	}
}

type usageFilter struct {
	Period string
	Bucket string
	Source string
}

func normalizeUsageFilter(values url.Values) usageFilter {
	filter := usageFilter{
		Period: strings.ToLower(strings.TrimSpace(values.Get("period"))),
		Bucket: strings.ToLower(strings.TrimSpace(values.Get("bucket"))),
		Source: strings.TrimSpace(values.Get("source")),
	}
	switch filter.Period {
	case "", "current_month", "month":
		filter.Period = "current_month"
	case "all", "all_time":
		filter.Period = "all_time"
	default:
		filter.Period = "current_month"
	}
	switch filter.Bucket {
	case "", "hour":
		filter.Bucket = "hour"
	case "day":
		filter.Bucket = "day"
	default:
		filter.Bucket = "hour"
	}
	if filter.Source == "" {
		filter.Source = "all"
	}
	return filter
}

type usagePageData struct {
	Version         string              `json:"version"`
	Filters         usageFilter         `json:"filters"`
	Summary         usageSummary        `json:"summary"`
	Buckets         []usageBucket       `json:"buckets"`
	TopModels       []usageGroup        `json:"top_models"`
	TopSources      []usageGroup        `json:"top_sources"`
	Recent          []usageViewRecord   `json:"recent"`
	AvailableSource []string            `json:"available_sources"`
	Diagnostics     providerDiagnostics `json:"diagnostics"`
}

type usageSummary struct {
	Requests         int64 `json:"requests"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CachedTokens     int64 `json:"cached_tokens"`
	CacheHits        int64 `json:"cache_hits"`
	PrincipalCount   int   `json:"principal_count"`
	ModelCount       int   `json:"model_count"`
	SourceCount      int   `json:"source_count"`
}

type usageBucket struct {
	Label            string `json:"label"`
	Requests         int64  `json:"requests"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	TotalTokens      int64  `json:"total_tokens"`
	CachedTokens     int64  `json:"cached_tokens"`
	CacheHits        int64  `json:"cache_hits"`
}

type usageGroup struct {
	Label            string `json:"label"`
	Requests         int64  `json:"requests"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	TotalTokens      int64  `json:"total_tokens"`
	CachedTokens     int64  `json:"cached_tokens"`
	CacheHits        int64  `json:"cache_hits"`
}

type usageViewRecord struct {
	At               string `json:"at"`
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	ClientApp        string `json:"client_app"`
	Principal        string `json:"principal"`
	Mode             string `json:"mode"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	TotalTokens      int64  `json:"total_tokens"`
	CachedTokens     int64  `json:"cached_tokens"`
	CacheHit         bool   `json:"cache_hit"`
}

func usageDashboardData(diag providerDiagnostics, filter usageFilter) usagePageData {
	records := recentUsageRecords()
	filtered := make([]usageRecord, 0, len(records))
	for _, record := range records {
		if !recordMatchesUsageFilter(record, filter) {
			continue
		}
		filtered = append(filtered, record)
	}

	sources := observedUsageSources(filtered)
	summary := summarizeUsageRecords(filtered)
	buckets := groupUsageBuckets(filtered, filter.Bucket)
	topModels := groupUsageGroups(filtered, func(record usageRecord) string {
		return firstNonEmpty(record.Model, "unknown")
	})
	topSources := groupUsageGroups(filtered, func(record usageRecord) string {
		return firstNonEmpty(record.ClientApp, "unknown")
	})
	recent := make([]usageViewRecord, 0, minInt(len(filtered), 24))
	for i := 0; i < len(filtered) && i < 24; i++ {
		record := filtered[i]
		recent = append(recent, usageViewRecord{
			At:               record.At.UTC().Format("2006-01-02 15:04:05 MST"),
			Provider:         record.Provider,
			Model:            record.Model,
			ClientApp:        record.ClientApp,
			Principal:        maskPrincipal(record.Principal),
			Mode:             record.Mode,
			PromptTokens:     record.PromptTokens,
			CompletionTokens: record.CompletionTokens,
			TotalTokens:      record.TotalTokens,
			CachedTokens:     record.CachedTokens,
			CacheHit:         record.CacheHit,
		})
	}
	return usagePageData{
		Version:         pluginVersion,
		Filters:         filter,
		Summary:         summary,
		Buckets:         buckets,
		TopModels:       topModels,
		TopSources:      topSources,
		Recent:          recent,
		AvailableSource: sources,
		Diagnostics:     diag,
	}
}

func recordMatchesUsageFilter(record usageRecord, filter usageFilter) bool {
	if filter.Period == "current_month" {
		now := time.Now().UTC()
		recordAt := record.At.UTC()
		if recordAt.Year() != now.Year() || recordAt.Month() != now.Month() {
			return false
		}
	}
	if filter.Source != "" && filter.Source != "all" {
		if !strings.EqualFold(record.ClientApp, filter.Source) {
			return false
		}
	}
	return true
}

func summarizeUsageRecords(records []usageRecord) usageSummary {
	var out usageSummary
	principals := make(map[string]struct{})
	models := make(map[string]struct{})
	sources := make(map[string]struct{})
	for _, record := range records {
		out.Requests++
		out.PromptTokens += record.PromptTokens
		out.CompletionTokens += record.CompletionTokens
		out.TotalTokens += record.TotalTokens
		out.InputTokens += record.InputTokens
		out.OutputTokens += record.OutputTokens
		out.CachedTokens += record.CachedTokens
		if record.CacheHit {
			out.CacheHits++
		}
		if strings.TrimSpace(record.Principal) != "" {
			principals[record.Principal] = struct{}{}
		}
		if strings.TrimSpace(record.Model) != "" {
			models[record.Model] = struct{}{}
		}
		if strings.TrimSpace(record.ClientApp) != "" {
			sources[record.ClientApp] = struct{}{}
		}
	}
	out.PrincipalCount = len(principals)
	out.ModelCount = len(models)
	out.SourceCount = len(sources)
	return out
}

func groupUsageBuckets(records []usageRecord, bucket string) []usageBucket {
	type bucketTotals struct {
		usageBucket
		order time.Time
	}
	grouped := make(map[string]*bucketTotals)
	for _, record := range records {
		label, order := usageBucketLabel(record.At, bucket)
		item, ok := grouped[label]
		if !ok {
			item = &bucketTotals{usageBucket: usageBucket{Label: label}, order: order}
			grouped[label] = item
		}
		item.Requests++
		item.PromptTokens += record.PromptTokens
		item.CompletionTokens += record.CompletionTokens
		item.TotalTokens += record.TotalTokens
		item.CachedTokens += record.CachedTokens
		if record.CacheHit {
			item.CacheHits++
		}
	}
	out := make([]bucketTotals, 0, len(grouped))
	for _, item := range grouped {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].order.Before(out[j].order)
	})
	result := make([]usageBucket, 0, len(out))
	for _, item := range out {
		result = append(result, item.usageBucket)
	}
	return result
}

func groupUsageGroups(records []usageRecord, labelFn func(usageRecord) string) []usageGroup {
	type groupTotals struct {
		usageGroup
		order int64
	}
	grouped := make(map[string]*groupTotals)
	for _, record := range records {
		label := strings.TrimSpace(labelFn(record))
		if label == "" {
			label = "unknown"
		}
		item, ok := grouped[label]
		if !ok {
			item = &groupTotals{usageGroup: usageGroup{Label: label}}
			grouped[label] = item
		}
		item.Requests++
		item.PromptTokens += record.PromptTokens
		item.CompletionTokens += record.CompletionTokens
		item.TotalTokens += record.TotalTokens
		item.CachedTokens += record.CachedTokens
		if record.CacheHit {
			item.CacheHits++
		}
		item.order = item.TotalTokens
	}
	out := make([]groupTotals, 0, len(grouped))
	for _, item := range grouped {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalTokens == out[j].TotalTokens {
			if out[i].Requests == out[j].Requests {
				return out[i].Label < out[j].Label
			}
			return out[i].Requests > out[j].Requests
		}
		return out[i].TotalTokens > out[j].TotalTokens
	})
	result := make([]usageGroup, 0, len(out))
	for _, item := range out {
		result = append(result, item.usageGroup)
	}
	return result
}

func usageBucketLabel(at time.Time, bucket string) (string, time.Time) {
	at = at.UTC()
	switch bucket {
	case "day":
		base := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		return base.Format("2006-01-02"), base
	default:
		base := time.Date(at.Year(), at.Month(), at.Day(), at.Hour(), 0, 0, 0, time.UTC)
		return base.Format("Jan 02 15:00"), base
	}
}

func observedUsageSources(records []usageRecord) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	for _, record := range records {
		source := strings.TrimSpace(record.ClientApp)
		if source == "" {
			source = "unknown"
		}
		if _, exists := seen[source]; exists {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

func maskPrincipal(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if len(value) <= 12 {
		return value
	}
	return value[:6] + "..." + value[len(value)-6:]
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func recordUsageFromExecutorResponse(body []byte, headers map[string][]string, provider, model, clientApp, principal, mode string) {
	totals, ok := parseUsageObservation(body, headers)
	if !ok {
		return
	}
	recordUsageObservation(usageRecord{
		At:               time.Now().UTC(),
		Provider:         canonicalUsageProviderName(provider),
		Model:            model,
		ClientApp:        clientApp,
		Principal:        principal,
		Mode:             mode,
		PromptTokens:     totals.PromptTokens,
		CompletionTokens: totals.CompletionTokens,
		TotalTokens:      totals.TotalTokens,
		InputTokens:      totals.InputTokens,
		OutputTokens:     totals.OutputTokens,
		CachedTokens:     totals.CachedTokens,
		CacheHit:         totals.CacheHit,
	})
}

// canonicalUsageProviderName collapses presentation-only duplication without
// changing the executor key used by CPA. This protects the plugin dashboard
// from records emitted by older plugin builds or external consumers that join
// the provider and label with a hyphen.
func canonicalUsageProviderName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, " executor")
	value = normalizeExecutorProviderKey(value)
	return value
}

func usageShareMetric(group usageGroup, summary usageSummary) (float64, string) {
	denominator := summary.TotalTokens
	value := group.TotalTokens
	label := formatUsageNumber(group.TotalTokens) + " tokens"
	if denominator <= 0 {
		denominator = summary.Requests
		value = group.Requests
		label = formatUsageNumber(group.Requests) + " requests"
	}
	if denominator <= 0 {
		return 0, label
	}
	return float64(value) * 100 / float64(denominator), label
}

func usagePercent(value, total int64) string {
	if total <= 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(value)*100/float64(total))
}

func usageFilterLabel(filter usageFilter) string {
	period := "Current month"
	if filter.Period == "all_time" {
		period = "All time"
	}
	bucket := "By hour"
	if filter.Bucket == "day" {
		bucket = "By day"
	}
	source := "All sources"
	if filter.Source != "" && filter.Source != "all" {
		source = filter.Source
	}
	return period + " / " + bucket + " / " + source
}

func renderUsageFilterForm(data usagePageData, action, prefix string) string {
	return fmt.Sprintf(`<form class="usage-filters" method="get" action="%s">
<label><span>Period</span><select id="%s-period" name="period">
<option value="current_month"%s>Current month</option><option value="all_time"%s>All time</option>
</select></label>
<label><span>Bucket</span><select id="%s-bucket" name="bucket">
<option value="hour"%s>By hour</option><option value="day"%s>By day</option>
</select></label>
<label><span>Source</span><select id="%s-source" name="source">%s</select></label>
<button class="btn" type="submit">Apply</button>
</form>`,
		html.EscapeString(action),
		html.EscapeString(prefix),
		usageSelected(data.Filters.Period, "current_month"),
		usageSelected(data.Filters.Period, "all_time"),
		html.EscapeString(prefix),
		usageSelected(data.Filters.Bucket, "hour"),
		usageSelected(data.Filters.Bucket, "day"),
		html.EscapeString(prefix),
		renderSourceOptions(data.Filters.Source, data.AvailableSource),
	)
}

func renderUsageShareRows(groups []usageGroup, summary usageSummary, limit int) string {
	if len(groups) == 0 {
		return `<div class="usage-empty">No usage records match the current filter.</div>`
	}
	if limit > 0 && len(groups) > limit {
		groups = groups[:limit]
	}
	var builder strings.Builder
	for _, group := range groups {
		percentage, metric := usageShareMetric(group, summary)
		builder.WriteString(fmt.Sprintf(
			`<div class="share-row"><div class="share-row-head"><strong>%s</strong><span>%s</span></div><div class="share-bar"><span style="width:%.1f%%"></span></div><div class="share-meta"><span>%s calls</span><span>%s</span></div></div>`,
			html.EscapeString(group.Label),
			html.EscapeString(fmt.Sprintf("%.1f%%", percentage)),
			percentage,
			formatUsageNumber(group.Requests),
			html.EscapeString(metric),
		))
	}
	return builder.String()
}

func renderUsageBucketRows(buckets []usageBucket, limit int) string {
	if len(buckets) == 0 {
		return `<div class="usage-empty">No usage records match the current filter.</div>`
	}
	if limit > 0 && len(buckets) > limit {
		buckets = buckets[len(buckets)-limit:]
	}
	var builder strings.Builder
	for _, bucket := range buckets {
		builder.WriteString(fmt.Sprintf(
			`<div class="bucket-row"><span>%s</span><strong>%s</strong><small>%s tokens / %d hits</small></div>`,
			html.EscapeString(bucket.Label),
			formatUsageNumber(bucket.Requests),
			formatUsageNumber(bucket.TotalTokens),
			bucket.CacheHits,
		))
	}
	return builder.String()
}

func renderUsageRecentRows(records []usageViewRecord, limit int) string {
	if len(records) == 0 {
		return `<div class="usage-empty">No usage records match the current filter.</div>`
	}
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	var builder strings.Builder
	for _, record := range records {
		cache := ""
		if record.CacheHit {
			cache = `<span class="usage-tag">cache hit</span>`
		}
		builder.WriteString(fmt.Sprintf(
			`<div class="recent-row"><div><strong>%s</strong><small>%s · %s · %s</small></div><div class="recent-value"><strong>%s</strong><small>%s %s</small></div></div>`,
			html.EscapeString(firstNonEmpty(record.Model, "unknown")),
			html.EscapeString(firstNonEmpty(record.ClientApp, "unknown")),
			html.EscapeString(record.Mode),
			html.EscapeString(record.At),
			formatUsageNumber(record.TotalTokens),
			formatUsageNumber(record.PromptTokens),
			cache,
		))
	}
	return builder.String()
}

func renderUsageMainHTML(data usagePageData, action string) string {
	cacheRate := usagePercent(data.Summary.CacheHits, data.Summary.Requests)
	return fmt.Sprintf(`<section class="card usage-overview">
<div class="card-head"><div><div class="section-title">Usage analytics</div><div class="muted">Passive usage returned by agy2api · %s</div></div><span class="pill">%s</span></div>
%s
<div class="usage-metrics">
<div class="usage-metric"><span>Requests</span><strong>%d</strong></div>
<div class="usage-metric"><span>Total tokens</span><strong>%s</strong></div>
<div class="usage-metric"><span>Prompt / output</span><strong>%s / %s</strong></div>
<div class="usage-metric"><span>Cached tokens</span><strong>%s</strong></div>
<div class="usage-metric"><span>Cache hit rate</span><strong>%s</strong></div>
<div class="usage-metric"><span>Models / apps</span><strong>%d / %d</strong></div>
</div>
</section>
<div class="usage-analysis-grid">
<section class="card usage-panel"><div class="card-head"><div><div class="section-title">Model usage share</div><div class="muted">Share is token-based when usage totals exist, otherwise request-based.</div></div><span class="mini-pill">%d models</span></div><div class="share-list">%s</div></section>
<section class="card usage-panel"><div class="card-head"><div><div class="section-title">Traffic by client</div><div class="muted">Which CPA-facing app is using the bridge.</div></div><span class="mini-pill">%d sources</span></div><div class="share-list">%s</div></section>
<section class="card usage-panel"><div class="card-head"><div><div class="section-title">Recent usage</div><div class="muted">Latest observations retained by the plugin.</div></div><span class="mini-pill">last %d</span></div><div class="recent-list">%s</div></section>
<section class="card usage-panel"><div class="card-head"><div><div class="section-title">Activity buckets</div><div class="muted">Request volume across the selected period.</div></div><span class="mini-pill">%s</span></div><div class="bucket-list">%s</div></section>
</div>`,
		html.EscapeString(usageFilterLabel(data.Filters)),
		html.EscapeString(firstNonEmpty(data.Diagnostics.ReplacementMode, "unknown")),
		renderUsageFilterForm(data, action, "main"),
		data.Summary.Requests,
		formatUsageNumber(data.Summary.TotalTokens),
		formatUsageNumber(data.Summary.PromptTokens),
		formatUsageNumber(data.Summary.CompletionTokens),
		formatUsageNumber(data.Summary.CachedTokens),
		cacheRate,
		data.Summary.ModelCount,
		data.Summary.SourceCount,
		data.Summary.ModelCount,
		renderUsageShareRows(data.TopModels, data.Summary, 8),
		data.Summary.SourceCount,
		renderUsageShareRows(data.TopSources, data.Summary, 6),
		minInt(len(data.Recent), 6),
		renderUsageRecentRows(data.Recent, 6),
		html.EscapeString(firstNonEmpty(data.Filters.Bucket, "hour")),
		renderUsageBucketRows(data.Buckets, 6),
	)
}

func renderUsageDrawerHTML(data usagePageData, action string) string {
	cacheRate := usagePercent(data.Summary.CacheHits, data.Summary.Requests)
	return fmt.Sprintf(`<div class="drawer-usage-summary"><div class="section-title">Usage snapshot</div><div class="muted">%s</div><div class="drawer-usage-metrics"><span><strong>%d</strong> requests</span><span><strong>%s</strong> tokens</span><span><strong>%s</strong> cache rate</span></div></div>
%s
<details class="accordion" open><summary>Model usage share <span class="mini-pill">%d</span></summary><div class="accordion-body"><div class="share-list">%s</div></div></details>
<details class="accordion"><summary>Traffic by client <span class="mini-pill">%d</span></summary><div class="accordion-body"><div class="share-list">%s</div></div></details>
<details class="accordion"><summary>Recent usage <span class="mini-pill">%d</span></summary><div class="accordion-body"><div class="recent-list">%s</div></div></details>
<details class="accordion"><summary>Activity buckets <span class="mini-pill">%d</span></summary><div class="accordion-body"><div class="bucket-list">%s</div></div></details>`,
		html.EscapeString(usageFilterLabel(data.Filters)),
		data.Summary.Requests,
		formatUsageNumber(data.Summary.TotalTokens),
		cacheRate,
		renderUsageFilterForm(data, action, "drawer"),
		data.Summary.ModelCount,
		renderUsageShareRows(data.TopModels, data.Summary, 12),
		data.Summary.SourceCount,
		renderUsageShareRows(data.TopSources, data.Summary, 12),
		minInt(len(data.Recent), 12),
		renderUsageRecentRows(data.Recent, 12),
		len(data.Buckets),
		renderUsageBucketRows(data.Buckets, 12),
	)
}

func usageRoutePage(diag providerDiagnostics, query url.Values) string {
	data := usageDashboardData(diag, normalizeUsageFilter(query))
	return usageDashboardHTML(data)
}

func usageRouteJSON(diag providerDiagnostics, query url.Values) []byte {
	data := usageDashboardData(diag, normalizeUsageFilter(query))
	return managementJSONResponse(http.StatusOK, data)
}

func usageDashboardHTML(data usagePageData) string {
	statusLabel := data.Diagnostics.ReplacementMode
	if statusLabel == "" {
		statusLabel = "unknown"
	}
	periodLabel := "Current month"
	if data.Filters.Period == "all_time" {
		periodLabel = "All time"
	}
	bucketLabel := "By hour"
	if data.Filters.Bucket == "day" {
		bucketLabel = "By day"
	}
	sourceLabel := "All sources"
	if data.Filters.Source != "" && data.Filters.Source != "all" {
		sourceLabel = data.Filters.Source
	}
	overview := fmt.Sprintf(`<section class="panel"><div class="panel-title">Usage overview</div><div class="metrics">
<div class="metric"><span>Requests</span><strong>%d</strong></div>
<div class="metric"><span>Total tokens</span><strong>%s</strong></div>
<div class="metric"><span>Prompt tokens</span><strong>%s</strong></div>
<div class="metric"><span>Completion tokens</span><strong>%s</strong></div>
<div class="metric"><span>Cached tokens</span><strong>%s</strong></div>
<div class="metric"><span>Cache hits</span><strong>%d</strong></div>
<div class="metric"><span>Models</span><strong>%d</strong></div>
<div class="metric"><span>Sources</span><strong>%d</strong></div>
</div></section>`,
		data.Summary.Requests,
		formatUsageNumber(data.Summary.TotalTokens),
		formatUsageNumber(data.Summary.PromptTokens),
		formatUsageNumber(data.Summary.CompletionTokens),
		formatUsageNumber(data.Summary.CachedTokens),
		data.Summary.CacheHits,
		data.Summary.ModelCount,
		data.Summary.SourceCount,
	)
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AGY Usage View</title>
<style>
:root{--bg:#faf9f5;--panel:#fffdf9;--surface:#f1eee8;--inset:#f6f3ec;--ink:#2c2925;--ink-2:#6d6760;--ink-3:#a29c95;--line:#e3e0da;--line-2:#d4d0c8;--accent:#2563eb;--success:#0f766e;--warn:#a16207;--radius:8px;--shadow:0 1px 2px #00000014}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;font-size:14px;line-height:1.45}
a{color:inherit;text-decoration:none}
.shell{min-height:100vh;display:grid;grid-template-columns:minmax(0,1fr) 360px}
.content{padding:20px 18px 28px}
.drawer{background:var(--panel);border-left:1px solid var(--line);box-shadow:-8px 0 22px #0000000f;padding:0;min-height:100vh}
.drawer-head{padding:16px;border-bottom:1px solid var(--line);display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.drawer-title{font-size:15px;font-weight:750}
.drawer-body{padding:14px 16px 20px}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.title h1{font-size:22px;line-height:1.15;margin:0 0 4px;font-weight:750}
.muted{color:var(--ink-2);font-size:12.5px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.btn{border:1px solid var(--line-2);background:#fff;color:var(--ink);border-radius:6px;height:34px;padding:0 11px;font-weight:650;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn:hover{filter:brightness(.985)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px;margin-bottom:10px}
.panel-title{font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.04em;color:var(--ink-3);margin-bottom:10px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.metric{background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:10px}
.metric span{display:block;color:var(--ink-3);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.metric strong{display:block;margin-top:3px;font-weight:750;word-break:break-word}
.table{width:100%%;border-collapse:collapse}
.table th,.table td{padding:9px 7px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}
.table th{font-size:11px;color:var(--ink-3);text-transform:uppercase;letter-spacing:.04em}
.table tr:last-child td{border-bottom:0}
.pill{display:inline-flex;align-items:center;border:1px solid var(--line-2);background:var(--surface);padding:4px 9px;border-radius:999px;font-size:12px;font-weight:700;color:var(--ink-2)}
.summary-row{display:flex;gap:8px;flex-wrap:wrap}
.field{margin-bottom:12px}.field label{display:block;font-size:12px;font-weight:650;color:var(--ink-2);margin-bottom:5px}
.field select{width:100%%;border:1px solid var(--line-2);background:#fff;border-radius:6px;color:var(--ink);padding:8px 9px}
.filters{display:grid;grid-template-columns:1fr;gap:10px}
.record{border:1px solid var(--line);border-radius:8px;background:var(--inset);padding:10px;margin-bottom:8px}
.record-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;margin-bottom:6px}
.record-main{font-weight:700}
.record-meta{color:var(--ink-2);font-size:12px}
.status{display:inline-flex;align-items:center;border-radius:999px;border:1px solid var(--line-2);background:var(--surface);padding:4px 9px;font-size:12px;font-weight:700}
.status.ok{background:#dcfce7;color:#166534;border-color:#86efac}
.status.warn{background:#fef3c7;color:#92400e;border-color:#fcd34d}
.empty{padding:14px;border:1px dashed var(--line-2);border-radius:8px;color:var(--ink-2);background:#fff}
.group{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.group strong{font-size:13px}
.group span{color:var(--ink-2);font-size:12px}
@media(max-width:960px){.shell{grid-template-columns:1fr}.drawer{border-left:0;border-top:1px solid var(--line);min-height:auto}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.content{padding:16px}.drawer-body{padding:14px}}
</style>
</head>
<body>
<div class="shell">
<main class="content">
<div class="top">
<div class="title"><h1>AGY Usage View</h1><div class="muted">Passive usage telemetry from agy2api responses. No request routing changes, no secret exposure.</div></div>
<div class="actions">
<a class="btn" href="/v0/resource/plugins/%s/status">Back to status</a>
<a class="btn" href="/v0/resource/plugins/%s/provider">Provider view</a>
<button class="btn" onclick="location.reload()">Refresh</button>
</div>
</div>
<div class="summary-row"><span class="pill">%s</span><span class="pill">%s</span><span class="pill">%s</span></div>
%s
<section class="panel"><div class="panel-title">Time buckets</div>%s</section>
<section class="panel"><div class="panel-title">Top models</div>%s</section>
<section class="panel"><div class="panel-title">Top sources</div>%s</section>
<section class="panel"><div class="panel-title">Recent usage</div>%s</section>
</main>
<aside class="drawer">
<div class="drawer-head"><div><div class="drawer-title">Usage filters</div><div class="muted">Current month, bucket, and source are all query-string driven.</div></div><span class="status %s">%s</span></div>
<div class="drawer-body">
<form class="panel" method="get" action="/v0/resource/plugins/%s/usage">
<div class="field"><label for="period">Period</label><select id="period" name="period" onchange="this.form.submit()">
<option value="current_month"%s>Current month</option>
<option value="all_time"%s>All time</option>
</select></div>
<div class="field"><label for="bucket">Bucket</label><select id="bucket" name="bucket" onchange="this.form.submit()">
<option value="hour"%s>By hour</option>
<option value="day"%s>By day</option>
</select></div>
<div class="field"><label for="source">Source</label><select id="source" name="source" onchange="this.form.submit()">%s</select></div>
<div class="actions"><button class="btn primary" type="submit">Apply</button><a class="btn" href="/v0/resource/plugins/%s/usage">Reset</a></div>
</form>
<div class="panel">
<div class="panel-title">Plugin context</div>
<div class="record"><div class="record-main">%s</div><div class="record-meta">Replacement mode: %s</div></div>
<div class="record"><div class="record-main">%s</div><div class="record-meta">Original provider</div></div>
<div class="record"><div class="record-main">%s</div><div class="record-meta">Executor provider</div></div>
</div>
<div class="panel">
<div class="panel-title">Notes</div>
<div class="record-meta">Token counts are recorded only when agy2api returns usage metadata or usage headers. Streamed responses are scanned passively after completion.</div>
</div>
</div>
</aside>
</div>
</body>
</html>`,
		pluginID,
		pluginID,
		periodLabel,
		bucketLabel,
		sourceLabel,
		overview,
		renderUsageBucketsTable(data.Buckets),
		renderUsageGroupsTable(data.TopModels),
		renderUsageGroupsTable(data.TopSources),
		renderUsageRecentTable(data.Recent),
		statusPillClass(statusLabel),
		html.EscapeString(statusLabel),
		pluginID,
		usageSelected(data.Filters.Period, "current_month"),
		usageSelected(data.Filters.Period, "all_time"),
		usageSelected(data.Filters.Bucket, "hour"),
		usageSelected(data.Filters.Bucket, "day"),
		renderSourceOptions(data.Filters.Source, data.AvailableSource),
		pluginID,
		html.EscapeString(firstNonEmpty(data.Diagnostics.MirroredProvider, "No mirrored provider")),
		html.EscapeString(firstNonEmpty(data.Diagnostics.ReplacementMode, "unknown")),
		html.EscapeString(firstNonEmpty(data.Diagnostics.ExecutorProvider, defaultExecutorProvider)),
		html.EscapeString(firstNonEmpty(data.Diagnostics.MirroredProvider, "No mirrored provider")),
	)
}

func usageSelected(current, value string) string {
	if strings.EqualFold(strings.TrimSpace(current), value) {
		return ` selected`
	}
	return ""
}

func statusPillClass(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "active":
		return "ok"
	case "withheld":
		return "warn"
	default:
		return ""
	}
}

func renderSourceOptions(current string, sources []string) string {
	var b strings.Builder
	current = strings.TrimSpace(current)
	if current == "" {
		current = "all"
	}
	b.WriteString(fmt.Sprintf(`<option value="all"%s>All sources</option>`, usageSelected(current, "all")))
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		b.WriteString(fmt.Sprintf(`<option value="%s"%s>%s</option>`, html.EscapeString(source), usageSelected(current, source), html.EscapeString(source)))
	}
	return b.String()
}

func renderUsageBucketsTable(buckets []usageBucket) string {
	if len(buckets) == 0 {
		return `<div class="empty">No usage records match the current filter.</div>`
	}
	var b strings.Builder
	b.WriteString(`<table class="table"><thead><tr><th>Bucket</th><th>Requests</th><th>Total tokens</th><th>Cached</th><th>Cache hits</th></tr></thead><tbody>`)
	for _, bucket := range buckets {
		b.WriteString(fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>`,
			html.EscapeString(bucket.Label),
			formatUsageNumber(bucket.Requests),
			formatUsageNumber(bucket.TotalTokens),
			formatUsageNumber(bucket.CachedTokens),
			bucket.CacheHits,
		))
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func renderUsageGroupsTable(groups []usageGroup) string {
	if len(groups) == 0 {
		return `<div class="empty">No usage records match the current filter.</div>`
	}
	var b strings.Builder
	b.WriteString(`<table class="table"><thead><tr><th>Name</th><th>Requests</th><th>Total tokens</th><th>Cache hits</th></tr></thead><tbody>`)
	for _, group := range groups {
		b.WriteString(fmt.Sprintf(
			`<tr><td><div class="group"><strong>%s</strong><span>%s prompt / %s completion</span></div></td><td>%s</td><td>%s</td><td>%d</td></tr>`,
			html.EscapeString(group.Label),
			formatUsageNumber(group.PromptTokens),
			formatUsageNumber(group.CompletionTokens),
			formatUsageNumber(group.Requests),
			formatUsageNumber(group.TotalTokens),
			group.CacheHits,
		))
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func renderUsageRecentTable(records []usageViewRecord) string {
	if len(records) == 0 {
		return `<div class="empty">No usage records match the current filter.</div>`
	}
	var b strings.Builder
	for _, record := range records {
		b.WriteString(fmt.Sprintf(
			`<div class="record"><div class="record-top"><div><div class="record-main">%s</div><div class="record-meta">%s · %s · %s</div></div><span class="status %s">%s</span></div><div class="record-meta">Tokens %s total, %s prompt, %s completion, cached %s</div></div>`,
			html.EscapeString(record.Model),
			html.EscapeString(record.At),
			html.EscapeString(firstNonEmpty(record.ClientApp, "unknown")),
			html.EscapeString(firstNonEmpty(record.Provider, "unknown")),
			recordStatusClass(record),
			usageRecordStatus(record),
			formatUsageNumber(record.TotalTokens),
			formatUsageNumber(record.PromptTokens),
			formatUsageNumber(record.CompletionTokens),
			formatUsageNumber(record.CachedTokens),
		))
	}
	return b.String()
}

func recordStatusClass(record usageViewRecord) string {
	if record.CacheHit {
		return "ok"
	}
	return ""
}

func usageRecordStatus(record usageViewRecord) string {
	if record.CacheHit {
		return "cache hit"
	}
	return "usage"
}

func formatUsageNumber(value any) string {
	switch typed := value.(type) {
	case int:
		return formatUsageNumberInt64(int64(typed))
	case int64:
		return formatUsageNumberInt64(typed)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func formatUsageNumberInt64(value int64) string {
	if value < 1000 {
		return strconv.FormatInt(value, 10)
	}
	return fmt.Sprintf("%d", value)
}
