package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const managementBasePath = "/plugins/" + pluginID

func handleManagementRegister() []byte {
	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: managementBasePath + "/status"},
			{Method: http.MethodGet, Path: managementBasePath + "/provider"},
			{Method: http.MethodGet, Path: managementBasePath + "/provider/config"},
			{Method: http.MethodPost, Path: managementBasePath + "/provider/save"},
			{Method: http.MethodPost, Path: managementBasePath + "/provider/test"},
			{Method: http.MethodPost, Path: managementBasePath + "/provider/fetch-models"},
			{Method: http.MethodGet, Path: managementBasePath + "/settings"},
			{Method: http.MethodPost, Path: managementBasePath + "/rescan"},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				Path:        "/status",
				Menu:        "AGY Identity Bridge",
				Description: "Redacted provider matching diagnostics for AGY Identity Bridge.",
			},
			{
				Path:        "/data",
				Description: "Redacted JSON provider matching diagnostics.",
			},
			{
				Path:        "/provider",
				Menu:        "AGY Provider View",
				Description: "Provider-shaped dashboard for the mirrored AGY provider.",
			},
		},
	})
}

func handleManagement(raw []byte) ([]byte, error) {
	var request pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return managementJSONResponse(http.StatusBadRequest, map[string]string{
			"error": "invalid management request",
		}), nil
	}
	path, isResource := normalizeManagementPath(request.Path)

	if isResource {
		switch {
		case request.Method == http.MethodGet && (path == "/" || path == "/status"):
			return managementHTMLResponse(http.StatusOK, publicStatusPage(scanProviderDiagnostics())), nil
		case request.Method == http.MethodGet && path == "/provider":
			return managementHTMLResponse(http.StatusOK, providerResourcePage(scanProviderDiagnostics())), nil
		case request.Method == http.MethodGet && path == "/data":
			return managementJSONResponse(http.StatusOK, publicProviderDiagnostics(scanProviderDiagnostics())), nil
		default:
			return managementJSONResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
		}
	}

	switch {
	case request.Method == http.MethodGet && (path == "/" || path == "/status"):
		return managementJSONResponse(http.StatusOK, scanProviderDiagnostics()), nil
	case request.Method == http.MethodGet && path == "/provider":
		return managementHTMLResponse(http.StatusOK, providerDetailPage(scanProviderDiagnostics())), nil
	case request.Method == http.MethodGet && path == "/provider/config":
		return managementJSONResponse(http.StatusOK, currentProviderEditorData(scanProviderDiagnostics(), true)), nil
	case request.Method == http.MethodPost && path == "/provider/save":
		return handleProviderEditorSave(request)
	case request.Method == http.MethodPost && path == "/provider/test":
		return handleProviderTest(request)
	case request.Method == http.MethodPost && path == "/provider/fetch-models":
		return handleProviderFetchModels(request)
	case request.Method == http.MethodGet && path == "/settings":
		return managementJSONResponse(http.StatusOK, managementSettings()), nil
	case request.Method == http.MethodPost && path == "/rescan":
		return managementJSONResponse(http.StatusOK, scanProviderDiagnostics()), nil
	default:
		return managementJSONResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
	}
}

func normalizeManagementPath(path string) (string, bool) {
	isResource := false
	if index := strings.Index(path, "/v0/resource/plugins/"+pluginID); index >= 0 {
		path = path[index+len("/v0/resource/plugins/"+pluginID):]
		isResource = true
	} else if index := strings.Index(path, "/v0/management/plugins/"+pluginID); index >= 0 {
		path = path[index+len("/v0/management/plugins/"+pluginID):]
	} else if strings.HasPrefix(path, managementBasePath) {
		path = strings.TrimPrefix(path, managementBasePath)
	}
	if path == "" {
		path = "/"
	}
	return path, isResource
}

func managementSettings() map[string]any {
	snapshot := currentConfigSnapshot()
	settings := normalizeSettings(snapshot.Settings)
	return map[string]any{
		"version":                                pluginVersion,
		"enabled":                                settings.Enabled,
		"priority":                               settings.Priority,
		"auto_discover":                          settings.AutoDiscover,
		"include_native_antigravity":             settings.IncludeNativeAntigravity,
		"allow_explicit_client_identity_headers": settings.AllowExplicitClientIdentityHeaders,
		"principal_fallback_mode":                settings.PrincipalFallbackMode,
		"debug_logging":                          settings.DebugLogging,
		"match_mode":                             settings.MatchMode,
		"match_name":                             settings.MatchName,
		"match_url":                              redactURL(settings.MatchURL),
		"match_api_key_configured":               settings.MatchAPIKey != "",
		"match_provider":                         settings.MatchProvider,
		"match_providers":                        settings.MatchProviders,
		"match_model":                            settings.MatchModel,
		"match_models":                           settings.MatchModels,
		"configured_selector_count":              settings.configuredSelectorCount(),
		"hmac_secret_configured":                 settings.hmacSecret() != "",
		"hmac_secret_source":                     settings.hmacSecretSource(),
		"agy2api_identity_secret_configured":     settings.Agy2apiIdentitySecret != "",
		"config_path_found":                      snapshot.ConfigPathFound,
		"plugin_config_found":                    snapshot.PluginConfigFound,
		"executor_enabled":                       settings.ExecutorEnabled,
		"executor_provider":                      settings.ExecutorProvider,
		"executor_auth_ensured":                  executorAuthRecordEnsured(),
		"model_namespace":                        settings.ModelNamespace,
	}
}

func managementJSONResponse(status int, value any) []byte {
	body, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"response serialization failed"}`)
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	})
}

func managementHTMLResponse(status int, body string) []byte {
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       []byte(body),
	})
}

func publicStatusPage(diagnostics providerDiagnostics) string {
	return dashboardHTML(publicProviderDiagnostics(diagnostics), false)
}

func providerDetailPage(diagnostics providerDiagnostics) string {
	spec, found := resolveProviderSpec()
	if !found {
		return dashboardHTML(diagnostics, true)
	}
	settings := currentPluginSettings()
	return providerEditorHTML(currentProviderEditorDataFromSpec(diagnostics, spec, settings, true))
}

func providerResourcePage(diagnostics providerDiagnostics) string {
	spec, found := resolveProviderSpec()
	if !found {
		return dashboardHTML(publicProviderDiagnostics(diagnostics), false)
	}
	settings := currentPluginSettings()
	return providerEditorHTML(currentProviderEditorDataFromSpec(publicProviderDiagnostics(diagnostics), spec, settings, false))
}

func dashboardHTML(diagnostics providerDiagnostics, detail bool) string {
	raw, errMarshal := json.MarshalIndent(diagnostics, "", "  ")
	if errMarshal != nil {
		raw = []byte(`{"error":"status serialization failed"}`)
	}

	state, stateTone := dashboardRouteState(diagnostics)
	mirrored := "Not matched"
	if diagnostics.MirroredProvider != "" {
		mirrored = diagnostics.MirroredProvider
	}
	executor := "Off"
	if diagnostics.ExecutorEnabled {
		executor = diagnostics.ExecutorProvider
	}
	prefix := strings.Join(diagnostics.ActivePrefixes, ", ")
	if prefix == "" {
		prefix = "none"
	}
	originalProvider := "Not matched"
	if diagnostics.MirroredProvider != "" {
		if diagnostics.ProviderOriginalEnabled {
			originalProvider = "Enabled"
		} else {
			originalProvider = "Disabled"
		}
	}
	secret := dashboardCheck(diagnostics.HMACSecretConfigured,
		"HMAC secret configured",
		"No HMAC secret configured")
	authReady := dashboardCheck(diagnostics.ExecutorAuthEnsured,
		"ln.Antigravity auth ready",
		"ln.Antigravity auth not ready")
	modelState := dashboardCheck(diagnostics.ModelsServed,
		"Plugin models published",
		"Plugin models withheld")
	upstream := "No agy2api response yet"
	upstreamTone := "muted"
	if diagnostics.LastExecutorStatus != 0 {
		upstream = fmt.Sprintf("agy2api HTTP %d", diagnostics.LastExecutorStatus)
		upstreamTone = dashboardStatusTone(diagnostics.LastExecutorStatus)
	}

	checks := secret + authReady + modelState
	var events strings.Builder
	if len(diagnostics.RecentEvents) == 0 {
		events.WriteString(`<div class="empty">No runtime events since the plugin loaded.</div>`)
	} else {
		for _, event := range diagnostics.RecentEvents {
			events.WriteString(fmt.Sprintf(
				`<div class="event"><span class="dot tone-%s"></span><span class="time">%s</span><span class="message">%s</span></div>`,
				html.EscapeString(dashboardEventTone(event.Level)),
				html.EscapeString(event.At),
				html.EscapeString(event.Message),
			))
		}
	}

	var warningBlock strings.Builder
	if len(diagnostics.Warnings) == 0 {
		warningBlock.WriteString(`<div class="empty">No configuration warnings.</div>`)
	} else {
		for _, warning := range diagnostics.Warnings {
			warningBlock.WriteString(`<div class="warning-item">` + html.EscapeString(warning) + `</div>`)
		}
	}

	providerLink := "/v0/resource/plugins/" + pluginID + "/provider"
	backLink := "/v0/resource/plugins/" + pluginID + "/status"
	actionLabel := "Provider view"
	actionLink := providerLink
	if detail {
		actionLabel = "Back to summary"
		actionLink = backLink
	}
	actionButton := fmt.Sprintf(`<a class="button button-link" href="%s">%s</a>`, html.EscapeString(actionLink), html.EscapeString(actionLabel))
	modelMode := diagnostics.ReplacementMode
	if modelMode == "" {
		modelMode = "unknown"
	}
	priority := "n/a"
	if diagnostics.MirroredPriority != 0 {
		priority = fmt.Sprintf("%d", diagnostics.MirroredPriority)
	}
	cooling := boolToLabel(diagnostics.MirroredDisableCooling)
	baseURL := "redacted"
	if detail {
		if diagnostics.MirroredBaseURL != "" {
			baseURL = diagnostics.MirroredBaseURL
		} else {
			baseURL = "n/a"
		}
	}
	apiKey := "not configured"
	if diagnostics.MirroredHasAPIKey {
		apiKey = "configured"
	}
	primaryModels := dashboardModelChips(diagnostics.PublishedModelIDs, "No live models are currently being published.")
	modelCatalog := dashboardModelChips(diagnostics.MirroredModelIDs, "No mirrored models were discovered.")
	providerTone := "info"
	switch diagnostics.ReplacementMode {
	case "active":
		providerTone = "success"
	case "withheld":
		providerTone = "warning"
	}

	providerSnapshot := fmt.Sprintf(`<section class="section"><div class="section-head"><span>Provider snapshot</span><span class="pill tone-%s">%s</span></div><div class="kv">
<div><span>Mirrored provider</span><strong>%s</strong></div><div><span>Provider mode</span><strong>%s</strong></div><div><span>Original provider</span><strong>%s</strong></div><div><span>Model prefix</span><strong>%s</strong></div><div><span>Upstream base URL</span><strong>%s</strong></div><div><span>Priority</span><strong>%s</strong></div><div><span>Disable cooling</span><strong>%s</strong></div><div><span>API key</span><strong>%s</strong></div><div><span>Published models</span><strong>%d</strong></div><div><span>Executor provider</span><strong>%s</strong></div></div><div class="subhead">Live model IDs</div>%s<div class="subhead">Mirrored model catalog</div>%s</section>`,
		providerTone,
		html.EscapeString(modelMode),
		html.EscapeString(mirrored),
		html.EscapeString(modelMode),
		html.EscapeString(originalProvider),
		html.EscapeString(prefix),
		html.EscapeString(baseURL),
		html.EscapeString(priority),
		html.EscapeString(cooling),
		html.EscapeString(apiKey),
		dashboardPublishedModelCount(diagnostics),
		html.EscapeString(executor),
		primaryModels,
		modelCatalog,
	)

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AGY Identity Bridge</title>
<style>
:root{--bg:#faf9f5;--panel:#fffdf9;--surface:#f0eee8;--inset:#f6f4ee;--ink:#2d2a26;--ink-2:#6d6760;--ink-3:#a29c95;--line:#e3e1db;--line-2:#d5d2cb;--muted:#8b8680;--success:#10b981;--amber:#d97706;--error:#c65746;--success-bg:#d1fae5;--success-ink:#065f46;--amber-bg:#fef3c7;--amber-ink:#92400e;--error-bg:#c657461a;--error-ink:#8a3a30;--shadow:0 1px 2px #00000014;--radius:8px}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%%}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;font-size:14px;line-height:1.5}
main{max-width:920px;margin:0 auto;padding:20px 16px 34px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.between{justify-content:space-between}h1{font-size:20px;font-weight:650;letter-spacing:0;margin:0}p{margin:0}
.page-head{margin-bottom:16px}.subtitle{color:var(--ink-2);font-size:13px}.button{appearance:none;border:1px solid var(--line-2);background:var(--panel);color:var(--ink-2);font:inherit;font-size:12px;font-weight:600;padding:6px 10px;border-radius:6px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}.button:hover{border-color:var(--line-2);background:#fff;color:var(--ink)}.button-link{min-width:102px}
.pill{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:650;border:1px solid transparent}.tone-success{background:var(--success-bg);color:var(--success-ink);border-color:#6ee7b7}.tone-warning{background:var(--amber-bg);color:var(--amber-ink);border-color:#fcd34d}.tone-error{background:var(--error-bg);color:var(--error-ink);border-color:#c6574659}.tone-info{background:#e9e6df;color:#5d5751;border-color:#d5d2cb}.tone-muted{background:#f0eee8;color:var(--ink-2);border-color:#e3e1db}
.hero{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}.route{display:flex;align-items:center;gap:8px;flex-wrap:wrap;color:var(--ink-2);font-size:13px;font-weight:550}.route-node{color:var(--ink);font-weight:650}.route-state{margin-top:10px;display:flex;justify-content:space-between;align-items:center;gap:12px}.state-label{font-size:11px;font-weight:650;text-transform:uppercase;letter-spacing:.04em;color:var(--ink-3)}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:10px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:13px;box-shadow:var(--shadow)}.stat strong{display:block;font-size:22px;line-height:1.15;letter-spacing:-.01em}.stat span{display:block;margin-top:3px;color:var(--ink-2);font-size:12px}
.section{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px;box-shadow:var(--shadow);margin-top:10px}.section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px}.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--ink-3)}
.checks{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.check{display:flex;gap:8px;align-items:flex-start;background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:9px}.dot{width:7px;height:7px;border-radius:50%%;flex:0 0 auto;margin-top:6px}.ok{color:var(--success-ink)}.bad{color:var(--error-ink)}
.log{background:#22221f;color:#eceae5;border-radius:6px;padding:10px;max-height:235px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px;line-height:1.5}.event{display:flex;gap:9px;padding:3px 0}.time{color:#9a978f;white-space:nowrap}.message{white-space:pre-wrap;word-break:break-word}.log .tone-success{background:#10b981}.log .tone-error{background:#c65746}.log .tone-warning{background:#d97706}.log .tone-info,.log .tone-muted{background:#8b8680}
.subhead{margin-top:12px;margin-bottom:8px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--ink-3)}.chips{display:flex;flex-wrap:wrap;gap:8px}.chip{display:inline-flex;align-items:center;min-height:28px;padding:5px 9px;border-radius:999px;background:#ece9e2;border:1px solid var(--line-2);color:var(--ink);font-size:12px;font-weight:600}.model-empty{color:var(--ink-3);font-size:13px;background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:9px}
.warning-item{border:1px solid #c6574659;background:var(--error-bg);color:var(--error-ink);padding:9px;border-radius:6px}.warning-item+.warning-item{margin-top:7px}.empty{color:var(--ink-3);font-size:13px}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}.kv div{background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:9px}.kv span{display:block;font-size:11px;color:var(--ink-3);font-weight:650;text-transform:uppercase;letter-spacing:.04em}.kv strong{font-weight:650}
details{border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);margin-top:10px}summary{cursor:pointer;user-select:none;padding:13px 14px;color:var(--ink-2);font-size:13px;font-weight:550}details pre{margin:0 14px 14px;padding:12px;overflow:auto;border-radius:6px;background:#22221f;color:#eceae5;font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-word}
@media(max-width:760px){.grid,.checks{grid-template-columns:repeat(2,minmax(0,1fr))}.route{font-size:12.5px}.route-state{align-items:flex-start;flex-direction:column}.section-head{align-items:flex-start;flex-direction:column}}
@media(max-width:480px){.grid,.checks{grid-template-columns:1fr}.stat strong{font-size:20px}main{padding:16px 12px 28px}}
</style>
</head>
<body>
<main>
<div class="page-head"><div class="row between"><div><h1>AGY Identity Bridge</h1><div class="subtitle">Antigravity bridge diagnostics and runtime status</div></div><div class="row">%s<button class="button" onclick="location.reload()">Refresh</button></div></div></div>
<section class="hero">
<div class="route"><span class="route-node">%s</span><span>&rarr;</span><span class="route-node">%s</span><span>&rarr;</span><span class="route-node">agy2api</span></div>
<div class="route-state"><div><div class="state-label">Route state</div><p><strong>%s</strong></p></div><span class="pill tone-%s">%s</span></div>
</section>
<section class="grid">
<div class="stat"><strong>%d</strong><span>Intercepted requests</span></div>
<div class="stat"><strong>%d</strong><span>Published models</span></div>
<div class="stat"><strong>%d</strong><span>Runtime auths</span></div>
<div class="stat"><strong>%d</strong><span>Matched records</span></div>
</section>
<section class="section"><div class="section-head"><span>Live health</span><span class="pill tone-%s">%s</span></div><div class="checks">%s</div></section>
%s
<section class="section"><div class="section-head"><span>Runtime log</span><span class="pill tone-muted">Last 8</span></div><div class="log">%s</div></section>
<section class="section"><div class="section-head"><span>Configuration</span></div><div class="kv">
<div><span>Mirrored provider</span><strong>%s</strong></div><div><span>Original provider</span><strong>%s</strong></div><div><span>Executor</span><strong>%s</strong></div><div><span>Model prefix</span><strong>%s</strong></div><div><span>HMAC source</span><strong>%s</strong></div></div></section>
<section class="section"><div class="section-head"><span>Warnings</span></div>%s</section>
<details><summary>Redacted JSON</summary><pre>%s</pre></details>
</main>
</body>
</html>`,
		actionButton,
		html.EscapeString(mirrored),
		html.EscapeString(executor),
		html.EscapeString(state.label),
		stateTone,
		html.EscapeString(state.pill),
		diagnostics.InterceptCount,
		dashboardPublishedModelCount(diagnostics),
		diagnostics.RuntimeAuthCount,
		diagnostics.MatchedRecordCount,
		upstreamTone,
		html.EscapeString(upstream),
		checks,
		providerSnapshot,
		events.String(),
		html.EscapeString(mirrored),
		html.EscapeString(originalProvider),
		html.EscapeString(executor),
		html.EscapeString(prefix),
		html.EscapeString(diagnostics.HMACSecretSource),
		warningBlock.String(),
		html.EscapeString(string(raw)),
	)
}

type providerEditorData struct {
	Version     string              `json:"version"`
	Locked      bool                `json:"locked"`
	ConfigPath  string              `json:"config_path,omitempty"`
	Diagnostics providerDiagnostics `json:"diagnostics"`
	Provider    providerEditorView  `json:"provider"`
	Plugin      pluginEditorView    `json:"plugin"`
}

type providerEditorView struct {
	Name                 string                `json:"name"`
	Prefix               string                `json:"prefix"`
	BaseURL              string                `json:"base_url"`
	Priority             int                   `json:"priority"`
	Disabled             bool                  `json:"disabled"`
	DisableCooling       bool                  `json:"disable_cooling"`
	APIKeyConfigured     bool                  `json:"api_key_configured"`
	APIKeyCount          int                   `json:"api_key_count"`
	Headers              []editorHeaderPair    `json:"headers"`
	Models               []providerEditorModel `json:"models"`
	ModelIDs             []string              `json:"model_ids"`
	PublishedModelIDs    []string              `json:"published_model_ids"`
	OriginalName         string                `json:"original_name"`
	OriginalPrefix       string                `json:"original_prefix"`
	OriginalBaseURL      string                `json:"original_base_url"`
	OriginalModelCount   int                   `json:"original_model_count"`
	ReplacementMode      string                `json:"replacement_mode"`
	OriginalProviderLive bool                  `json:"original_provider_live"`
}

type pluginEditorView struct {
	Enabled                            bool   `json:"enabled"`
	AllowExplicitClientIdentityHeaders bool   `json:"allow_explicit_client_identity_headers"`
	PrincipalFallbackMode              string `json:"principal_fallback_mode"`
	DebugLogging                       bool   `json:"debug_logging"`
	ExecutorEnabled                    bool   `json:"executor_enabled"`
	ExecutorProvider                   string `json:"executor_provider"`
	ModelNamespace                     string `json:"model_namespace"`
	HMACSecretConfigured               bool   `json:"hmac_secret_configured"`
	HMACSecretSource                   string `json:"hmac_secret_source"`
	Agy2apiIdentitySecretConfigured    bool   `json:"agy2api_identity_secret_configured"`
}

type editorHeaderPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type providerEditorModel struct {
	Name             string   `json:"name"`
	Alias            string   `json:"alias,omitempty"`
	Image            bool     `json:"image,omitempty"`
	ThinkingDisabled bool     `json:"thinking_disabled,omitempty"`
	ThinkingLevels   []string `json:"thinking_levels,omitempty"`
	InputModalities  []string `json:"input_modalities,omitempty"`
	OutputModalities []string `json:"output_modalities,omitempty"`
}

type providerEditorPayload struct {
	OriginalName                       string                    `json:"original_name"`
	OriginalPrefix                     string                    `json:"original_prefix"`
	OriginalBaseURL                    string                    `json:"original_base_url"`
	Name                               string                    `json:"name"`
	Prefix                             string                    `json:"prefix"`
	BaseURL                            string                    `json:"base_url"`
	Priority                           int                       `json:"priority"`
	Disabled                           bool                      `json:"disabled"`
	DisableCooling                     bool                      `json:"disable_cooling"`
	APIKeys                            []string                  `json:"api_keys"`
	APIKeyRows                         []providerEditorAPIKeyRow `json:"api_key_rows"`
	Headers                            []editorHeaderPair        `json:"headers"`
	Models                             []providerEditorModel     `json:"models"`
	ModelIDs                           []string                  `json:"model_ids"`
	Enabled                            bool                      `json:"enabled"`
	AllowExplicitClientIdentityHeaders bool                      `json:"allow_explicit_client_identity_headers"`
	PrincipalFallbackMode              string                    `json:"principal_fallback_mode"`
	DebugLogging                       bool                      `json:"debug_logging"`
	ExecutorEnabled                    bool                      `json:"executor_enabled"`
	ExecutorProvider                   string                    `json:"executor_provider"`
	ModelNamespace                     string                    `json:"model_namespace"`
	HMACSecret                         string                    `json:"hmac_secret"`
	Agy2apiIdentitySecret              string                    `json:"agy2api_identity_secret"`
	HMACSecretSource                   string                    `json:"hmac_secret_source"`
}

type providerEditorAPIKeyRow struct {
	Existing bool   `json:"existing"`
	Value    string `json:"value"`
}

func currentProviderEditorData(diagnostics providerDiagnostics, exposeConfig bool) providerEditorData {
	spec, found := resolveProviderSpec()
	if !found {
		return providerEditorData{
			Version:     pluginVersion,
			Locked:      !exposeConfig,
			Diagnostics: diagnostics,
			Plugin:      pluginEditorViewFromSettings(currentPluginSettings()),
		}
	}
	return currentProviderEditorDataFromSpec(diagnostics, spec, currentPluginSettings(), exposeConfig)
}

func currentProviderEditorDataFromSpec(diagnostics providerDiagnostics, spec providerSpec, settings PluginSettings, exposeConfig bool) providerEditorData {
	configPath := ""
	if exposeConfig {
		configPath = currentConfigSnapshot().ConfigPath
	}
	view := providerEditorView{
		Name:                 spec.Name,
		Prefix:               spec.Prefix,
		BaseURL:              spec.BaseURL,
		Priority:             spec.SourcePriority,
		Disabled:             !spec.Enabled,
		DisableCooling:       spec.DisableCooling,
		APIKeyConfigured:     spec.primaryAPIKey() != "",
		APIKeyCount:          len(spec.APIKeys),
		Headers:              editorHeaders(spec.Headers, exposeConfig),
		Models:               editorModelsFromSpec(spec.Models),
		ModelIDs:             modelIDsFromInfos(spec.modelInfos(settings.ModelNamespace)),
		PublishedModelIDs:    diagnostics.PublishedModelIDs,
		OriginalName:         spec.Name,
		OriginalPrefix:       spec.Prefix,
		OriginalBaseURL:      spec.BaseURL,
		OriginalModelCount:   len(spec.Models),
		ReplacementMode:      diagnostics.ReplacementMode,
		OriginalProviderLive: spec.Enabled,
	}
	if !exposeConfig {
		view.BaseURL = diagnostics.MirroredBaseURL
		view.Headers = nil
		view.OriginalBaseURL = ""
	}
	return providerEditorData{
		Version:     pluginVersion,
		Locked:      !exposeConfig,
		ConfigPath:  configPath,
		Diagnostics: diagnostics,
		Provider:    view,
		Plugin:      pluginEditorViewFromSettings(settings),
	}
}

func pluginEditorViewFromSettings(settings PluginSettings) pluginEditorView {
	settings = normalizeSettings(settings)
	return pluginEditorView{
		Enabled:                            settings.Enabled,
		AllowExplicitClientIdentityHeaders: settings.AllowExplicitClientIdentityHeaders,
		PrincipalFallbackMode:              settings.PrincipalFallbackMode,
		DebugLogging:                       settings.DebugLogging,
		ExecutorEnabled:                    settings.ExecutorEnabled,
		ExecutorProvider:                   settings.ExecutorProvider,
		ModelNamespace:                     settings.ModelNamespace,
		HMACSecretConfigured:               settings.hmacSecret() != "",
		HMACSecretSource:                   settings.hmacSecretSource(),
		Agy2apiIdentitySecretConfigured:    settings.Agy2apiIdentitySecret != "",
	}
}

func editorHeaders(headers map[string]string, exposeConfig bool) []editorHeaderPair {
	if len(headers) == 0 || !exposeConfig {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sortStrings(keys)
	out := make([]editorHeaderPair, 0, len(keys))
	for _, key := range keys {
		out = append(out, editorHeaderPair{Key: key, Value: headers[key]})
	}
	return out
}

func providerEditorHTML(data providerEditorData) string {
	seed := jsonForScript(data)
	status := data.Diagnostics.ReplacementMode
	if status == "" {
		status = "unknown"
	}
	lockedMessage := ""
	if data.Locked {
		lockedMessage = `<div class="notice">Provider View is opened in public mode. Enter the CPA management key and click Load secure config to edit or run checks.</div>`
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AGY Provider View</title>
<style>
:root{--bg:#f7f5ef;--panel:#fffdfa;--surface:#f0ede5;--inset:#f8f6f1;--ink:#282521;--ink-2:#69635b;--ink-3:#9b948b;--line:#dfdacf;--line-2:#cfc8bb;--accent:#2563eb;--success:#0f766e;--success-bg:#ccfbf1;--warn:#9a5a00;--warn-bg:#fff0bf;--error:#b44232;--error-bg:#fbe3df;--radius:8px;--shadow:0 1px 2px #00000014}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;font-size:14px;line-height:1.45}button,input,textarea,select{font:inherit}
.shell{min-height:100vh;display:grid;grid-template-columns:minmax(280px,1fr) minmax(360px,520px)}.content{padding:22px}.drawer{background:var(--panel);border-left:1px solid var(--line);box-shadow:-8px 0 22px #0000000f;min-height:100vh}.drawer-head{height:58px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 16px}.drawer-title{font-size:15px;font-weight:700}.drawer-body{padding:14px 16px 24px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px}.title h1{font-size:20px;line-height:1.2;margin:0 0 4px;font-weight:700;letter-spacing:0}.muted{color:var(--ink-2);font-size:12.5px}.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px;margin-bottom:10px}.section-title{font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.04em;color:var(--ink-3);margin-bottom:10px}.metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.metric{background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:10px}.metric span{display:block;color:var(--ink-3);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}.metric strong{display:block;margin-top:3px;font-weight:700;word-break:break-word}.pill{display:inline-flex;align-items:center;border-radius:999px;border:1px solid var(--line-2);background:var(--surface);padding:4px 9px;font-size:12px;font-weight:700;color:var(--ink-2)}.pill.ok{background:var(--success-bg);border-color:#5eead4;color:var(--success)}.pill.warn{background:var(--warn-bg);border-color:#f6d365;color:var(--warn)}.pill.err{background:var(--error-bg);border-color:#f0a79d;color:var(--error)}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.btn{border:1px solid var(--line-2);background:#fff;color:var(--ink);border-radius:6px;height:34px;padding:0 11px;font-weight:650;font-size:13px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn:hover{filter:brightness(.985)}.btn:disabled{opacity:.5;cursor:not-allowed}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.field{margin-bottom:12px}.field label{display:block;font-size:12px;color:var(--ink-2);font-weight:650;margin-bottom:5px}.field input,.field textarea,.field select{width:100%%;border:1px solid var(--line-2);background:#fff;border-radius:6px;color:var(--ink);padding:8px 9px;outline:none}.field textarea{resize:vertical;min-height:74px;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px}.toggle{display:flex;align-items:center;gap:9px;background:var(--inset);border:1px solid var(--line);border-radius:6px;padding:9px;margin-bottom:8px}.toggle input{width:16px;height:16px}.toggle span{font-weight:650}.notice{background:var(--warn-bg);border:1px solid #f6d365;color:var(--warn);border-radius:6px;padding:10px;margin-bottom:10px}.result{display:none;white-space:pre-wrap;word-break:break-word;border-radius:6px;padding:10px;margin-top:10px;background:#22221f;color:#eceae5;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px;max-height:230px;overflow:auto}.chips{display:flex;gap:7px;flex-wrap:wrap}.chip{background:var(--surface);border:1px solid var(--line-2);border-radius:999px;padding:5px 9px;font-size:12px;font-weight:650}.log{max-height:220px;overflow:auto;background:#22221f;color:#eceae5;border-radius:6px;padding:10px;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px}.event{padding:3px 0}.danger{color:var(--error)}.hidden{display:none!important}
.accordion{border:1px solid var(--line);border-radius:8px;background:var(--panel);box-shadow:var(--shadow);margin-top:10px;overflow:hidden}.accordion summary{cursor:pointer;list-style:none;padding:12px 14px;font-weight:700;color:var(--ink);display:flex;align-items:center;justify-content:space-between;gap:10px}.accordion summary::-webkit-details-marker{display:none}.accordion-body{padding:0 14px 14px}.rowlist{display:flex;flex-direction:column;gap:8px;margin-top:10px}.rowcard{border:1px solid var(--line);border-radius:8px;background:var(--inset);padding:10px}.rowgrid{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) auto auto;gap:8px;align-items:end}.rowgrid.cols-3{grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) auto}.rowgrid .field{margin-bottom:0}.mini-pill{display:inline-flex;align-items:center;min-width:22px;justify-content:center;padding:2px 6px;border-radius:999px;background:var(--surface);border:1px solid var(--line-2);font-size:11px;font-weight:700;color:var(--ink-2)}.muted.small{font-size:12px;color:var(--ink-2)}.model-think{margin-top:10px;border-top:1px solid var(--line);padding-top:10px}.think-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.think-pill{display:flex;align-items:center;justify-content:space-between;gap:8px;border:1px solid var(--line);border-radius:6px;padding:8px 10px;background:#fff;font-size:12px}.think-pill input{width:16px;height:16px}
@media(max-width:900px){.shell{grid-template-columns:1fr}.drawer{border-left:0;border-top:1px solid var(--line);min-height:auto}.grid{grid-template-columns:1fr}.content{padding:16px}.drawer-body{padding:14px}}
</style>
</head>
<body>
<div class="shell">
<main class="content">
<div class="top"><div class="title"><h1>AGY Identity Bridge</h1><div class="muted">Editing the source provider mirrored into ln.Antigravity</div></div><div class="actions"><a class="btn" href="/v0/resource/plugins/%s/status">Back to summary</a><button class="btn" onclick="location.reload()">Refresh</button></div></div>
<section class="card"><div class="section-title">Route state</div><div class="metrics">
<div class="metric"><span>Replacement mode</span><strong id="metric-mode">%s</strong></div>
<div class="metric"><span>Published models</span><strong id="metric-published">%d</strong></div>
<div class="metric"><span>Original provider</span><strong id="metric-original">%s</strong></div>
<div class="metric"><span>Executor auth</span><strong id="metric-auth">%s</strong></div>
</div></section>
<section class="card"><div class="section-title">Live model IDs</div><div id="live-models" class="chips"></div></section>
<section class="card"><div class="section-title">Runtime log</div><div id="runtime-log" class="log"></div></section>
</main>
<aside class="drawer">
<div class="drawer-head"><div><div class="drawer-title">ln.Antigravity</div><div class="muted">Mirrored provider editor</div></div><span id="mode-pill" class="pill">%s</span></div>
<div class="drawer-body">
%s
<div class="card"><div class="section-title">Management access</div><div class="field"><label for="mkey">CPA management key</label><input id="mkey" type="password" autocomplete="current-password" placeholder="Required for Load, Save, Test, Fetch"></div><div class="actions"><button class="btn" id="load-secure">Load secure config</button><button class="btn" id="clear-key">Clear</button></div></div>
<form id="editor-form" class="card">
<div class="section-title">Source provider</div>
<input type="hidden" id="original_name"><input type="hidden" id="original_prefix"><input type="hidden" id="original_base_url">
<div class="grid"><div class="field"><label for="name">Name</label><input id="name"></div><div class="field"><label for="prefix">Prefix</label><input id="prefix" placeholder="agy"></div></div>
<div class="field"><label for="base_url">Base URL</label><input id="base_url" placeholder="http://host:port/v1"></div>
<div class="grid"><div class="field"><label for="priority">Priority</label><input id="priority" type="number"></div><div class="field"><label for="hmac_source">HMAC source</label><select id="hmac_source"><option value="env">env</option><option value="config">config</option><option value="provider_api_key">provider_api_key</option><option value="none">none</option></select></div></div>
<label class="toggle"><input id="disabled" type="checkbox"><span>Disable original provider</span></label>
<label class="toggle"><input id="disable_cooling" type="checkbox"><span>Disable cooling</span></label>

<details class="accordion" open>
<summary>API key entries <span id="api-key-count" class="mini-pill"></span></summary>
<div class="accordion-body">
<div class="actions"><button class="btn" type="button" id="add-key">+ Add key entry</button><button class="btn" type="button" id="test-provider">Test all</button></div>
<div id="api-key-rows" class="rowlist"></div>
</div>
</details>

<details class="accordion" open>
<summary>Request headers <span id="header-count" class="mini-pill"></span></summary>
<div class="accordion-body">
<div id="header-rows" class="rowlist"></div>
<div class="actions"><button class="btn" type="button" id="add-header">+ Add header</button></div>
</div>
</details>

<details class="accordion" open>
<summary>Custom models <span id="model-count" class="mini-pill"></span></summary>
<div class="accordion-body">
<div class="actions"><button class="btn" type="button" id="fetch-models">Fetch from endpoint</button><button class="btn" type="button" id="add-model">+ Add model</button></div>
<div id="model-rows" class="rowlist"></div>
</div>
</details>

<details class="accordion" open>
<summary>Identity bridge</summary>
<div class="accordion-body">
<label class="toggle"><input id="enabled" type="checkbox"><span>Enable plugin</span></label>
<label class="toggle"><input id="allow_explicit_client_identity_headers" type="checkbox"><span>Allow explicit client identity headers</span></label>
<div class="grid"><div class="field"><label for="principal_fallback_mode">Fallback mode</label><select id="principal_fallback_mode"><option value="client_key_hash">client_key_hash</option><option value="user_agent_plus_session">user_agent_plus_session</option><option value="disabled">disabled</option></select></div><div class="field"><label for="debug_logging">Debug logging</label><select id="debug_logging"><option value="false">off</option><option value="true">on</option></select></div></div>
<div class="field"><label for="hmac_secret">HMAC secret</label><input id="hmac_secret" type="password" placeholder="Write-only. Leave empty to keep current secret."></div>
<div class="field"><label for="agy_secret">agy2api identity secret</label><input id="agy_secret" type="password" placeholder="Write-only. Leave empty to keep current secret."></div>
<div class="grid"><div class="field"><label for="executor_enabled">Executor enabled</label><select id="executor_enabled"><option value="false">off</option><option value="true">on</option></select></div><div class="field"><label for="executor_provider">Executor provider</label><input id="executor_provider" placeholder="ln.Antigravity"></div></div>
<div class="field"><label for="model_namespace">Model namespace override</label><input id="model_namespace" placeholder="Leave empty to keep provider prefix"></div>
</div>
</details>

<div class="actions"><button class="btn primary" type="submit" id="save-provider">Save</button></div>
<div id="result" class="result"></div>
</form>
</div>
</aside>
</div>
<script id="seed" type="application/json">%s</script>
<script>
let state = JSON.parse(document.getElementById('seed').textContent);
const MGT = '/v0/management/plugins/%s';
const ids = ['original_name','original_prefix','original_base_url','name','prefix','base_url','priority','disabled','disable_cooling','enabled','allow_explicit_client_identity_headers','principal_fallback_mode','debug_logging','api-key-rows','header-rows','model-rows','executor_enabled','executor_provider','model_namespace','agy_secret','hmac_secret','hmac_source'];
function el(id){return document.getElementById(id)}
function managementKey(){return el('mkey').value.trim() || sessionStorage.getItem('agyBridgeManagementKey') || ''}
function mgmtHeaders(json){const key=managementKey(); const h={}; if(json) h['Content-Type']='application/json'; if(key){h['X-Management-Key']=key; h['Authorization']='Bearer '+key} return h}
function show(value){const out=el('result'); out.style.display='block'; out.textContent=typeof value==='string'?value:JSON.stringify(value,null,2)}
function esc(value){return String(value ?? '').replace(/[&<>"']/g, ch=>{switch(ch){case '&': return '&amp;'; case '<': return '&lt;'; case '>': return '&gt;'; case '"': return '&quot;'; default: return '&#39;';}})}
function setLocked(node, locked){ if(!node) return; if('disabled' in node){ node.disabled = locked; } node.querySelectorAll('input,select,textarea,button').forEach(child=>{ child.disabled = locked; }); }
function render(data){state=data; const p=data.provider||{}; const pl=data.plugin||{}; el('original_name').value=p.original_name||p.name||''; el('original_prefix').value=p.original_prefix||p.prefix||''; el('original_base_url').value=p.original_base_url||p.base_url||''; el('name').value=p.name||''; el('prefix').value=p.prefix||''; el('base_url').value=p.base_url||''; el('priority').value=p.priority||0; el('disabled').checked=!!p.disabled; el('disable_cooling').checked=!!p.disable_cooling; el('enabled').checked=pl.enabled !== false; el('allow_explicit_client_identity_headers').checked=pl.allow_explicit_client_identity_headers !== false; el('principal_fallback_mode').value=pl.principal_fallback_mode||'client_key_hash'; el('debug_logging').value=pl.debug_logging ? 'true' : 'false'; el('api-key-count').textContent=(p.api_key_count||0).toString(); el('header-count').textContent=(p.headers||[]).length.toString(); el('model-count').textContent=(p.models||[]).length.toString(); renderKeyRows(p.api_key_count||0); renderHeaderRows(p.headers||[]); renderModelRows(p.models||[]); el('executor_enabled').value=pl.executor_enabled ? 'true' : 'false'; el('executor_provider').value=pl.executor_provider||'ln.Antigravity'; el('model_namespace').value=pl.model_namespace||''; el('hmac_secret').value=''; el('hmac_secret').placeholder=pl.hmac_secret_configured?'Write-only. Secret configured; leave empty to keep it.':'Write-only. Paste shared HMAC secret.'; el('agy_secret').value=''; el('agy_secret').placeholder=pl.agy2api_identity_secret_configured?'Write-only. Secret configured; leave empty to keep it.':'Write-only. Paste shared agy2api secret.'; el('hmac_source').value=pl.hmac_secret_source||'env'; el('metric-mode').textContent=p.replacement_mode||'unknown'; el('metric-published').textContent=(p.published_model_ids||[]).length; el('metric-original').textContent=p.original_provider_live?'enabled':'disabled'; el('metric-auth').textContent=(data.diagnostics&&data.diagnostics.executor_auth_ensured)?'ready':'not ready'; const pill=el('mode-pill'); pill.textContent=p.replacement_mode||'unknown'; pill.className='pill '+(p.replacement_mode==='active'?'ok':p.replacement_mode==='withheld'?'warn':''); renderChips('live-models',p.published_model_ids||[],'No plugin-published models right now.'); renderLog(data.diagnostics&&data.diagnostics.recent_events||[]); for(const id of ids){ setLocked(el(id), !!data.locked); } ['fetch-models','test-provider','save-provider','add-key','add-header','add-model'].forEach(id=>{const node=el(id); if(node) node.disabled=!!data.locked}); }
function renderChips(id,values,empty){const box=el(id); box.innerHTML=''; if(!values.length){box.innerHTML='<span class="muted">'+empty+'</span>'; return} values.forEach(v=>{const s=document.createElement('span'); s.className='chip'; s.textContent=v; box.appendChild(s)})}
function renderLog(events){const box=el('runtime-log'); if(!events.length){box.textContent='No runtime events since the plugin loaded.'; return} box.innerHTML=''; events.forEach(ev=>{const d=document.createElement('div'); d.className='event'; d.textContent=(ev.at||'')+'  '+(ev.level||'info').toUpperCase()+'  '+(ev.message||''); box.appendChild(d)})}
function rowHtml(type, row, index){
	if(type==='key'){
		return '<div class="rowcard key-row" data-row="key" data-existing="'+((row && row.existing) ? 'true' : 'false')+'"><div class="rowgrid cols-3"><div class="field"><label>Key #'+(index+1)+'</label><input class="api-key-value" type="password" autocomplete="new-password" placeholder="'+((row && row.existing) ? 'Write-only. Leave empty to keep this key.' : 'Write-only. Enter a new key.')+'"></div><div class="muted small">Configured keys stay hidden.</div><div class="actions"><button class="btn row-remove" type="button">×</button></div></div></div>';
	}
	if(type==='header'){
		return '<div class="rowcard header-row" data-row="header"><div class="rowgrid cols-3"><div class="field"><label>Header</label><input class="header-key" placeholder="X-Custom-Header"></div><div class="field"><label>Value</label><input class="header-value" placeholder="value"></div><div class="actions"><button class="btn row-remove" type="button">×</button></div></div></div>';
	}
	const levels=['none','minimal','low','medium','high','xhigh','max','auto'];
	const think = row && row.thinking_levels && row.thinking_levels.length ? row.thinking_levels : [];
	const noneChecked = row && row.thinking_disabled || think.length === 0;
	let thinkHtml = '<div class="think-grid">';
	for(const level of levels){
		const checked = level === 'none' ? noneChecked : think.includes(level);
		thinkHtml += '<label class="think-pill"><span>'+(level==='none'?'Disable thinking':level.charAt(0).toUpperCase()+level.slice(1))+'</span><input type="checkbox" class="model-think-level" data-level="'+level+'"'+(checked?' checked':'')+'></label>';
	}
	thinkHtml += '</div>';
	return '<div class="rowcard model-row" data-row="model"><div class="rowgrid cols-3"><div class="field"><label>Model</label><input class="model-name" placeholder="gemini-3.7-flash-high" value="'+esc(row && row.name)+'"></div><div class="field"><label>Alias</label><input class="model-alias" placeholder="alias (optional)" value="'+esc(row && row.alias)+'"></div><div class="actions"><button class="btn row-remove" type="button">×</button></div></div><label class="toggle"><input class="model-image" type="checkbox"'+((row&&row.image)?' checked':'')+'><span>Allow image endpoints</span></label><div class="model-think">'+thinkHtml+'</div></div>';
}
function renderRows(containerId, type, rows, fallbackCount){
	const box = el(containerId);
	box.innerHTML = '';
	const items = rows && rows.length ? rows : [];
	if(type==='key' && items.length === 0 && fallbackCount > 0){
		for(let i=0;i<fallbackCount;i++){ items.push({existing:true}); }
	}
	if(items.length === 0){
		box.innerHTML = '';
		if(type === 'header' || type === 'model'){
			box.innerHTML = '<div class="muted small">No entries yet.</div>';
		}
	}
	items.forEach((row, index) => {
		const wrap = document.createElement('div');
		wrap.innerHTML = rowHtml(type, row || {}, index);
		const node = wrap.firstElementChild;
		const remove = node.querySelector('.row-remove');
		if(remove){ remove.onclick = ()=>{ node.remove(); updateCounts(); }; }
		if(type==='model'){
			node.querySelectorAll('.model-think-level').forEach(cb=>{
				cb.onchange = ()=>{ if(cb.dataset.level === 'none' && cb.checked){ node.querySelectorAll('.model-think-level').forEach(other=>{ if(other !== cb && other.dataset.level !== 'none'){ other.checked = false; } }); } else if(cb.dataset.level !== 'none' && cb.checked){ const none = node.querySelector('.model-think-level[data-level="none"]'); if(none) none.checked = false; } updateCounts(); };
			});
		}
		box.appendChild(node);
	});
}
function renderKeyRows(count){ renderRows('api-key-rows','key',Array.from({length:count>0?count:1},()=>({existing:true})),0); updateCounts(); }
function renderHeaderRows(rows){ renderRows('header-rows','header',rows,0); updateCounts(); }
function renderModelRows(rows){ renderRows('model-rows','model',rows,0); updateCounts(); }
function updateCounts(){ el('api-key-count').textContent = el('api-key-rows').querySelectorAll('.rowcard').length.toString(); el('header-count').textContent = el('header-rows').querySelectorAll('.rowcard').length.toString(); el('model-count').textContent = el('model-rows').querySelectorAll('.rowcard').length.toString(); }
function collectKeyRows(){ return Array.from(el('api-key-rows').querySelectorAll('.rowcard')).map(node=>({existing:node.dataset.existing==='true',value:node.querySelector('.api-key-value').value.trim()})); }
function collectHeaders(){ return Array.from(el('header-rows').querySelectorAll('.rowcard')).map(node=>({key:node.querySelector('.header-key').value.trim(),value:node.querySelector('.header-value').value.trim()})).filter(item=>item.key && item.value); }
function collectModels(){ return Array.from(el('model-rows').querySelectorAll('.rowcard')).map(node=>{ const levels = Array.from(node.querySelectorAll('.model-think-level')).filter(cb=>cb.checked).map(cb=>cb.dataset.level).filter(level=>level !== 'none'); const none = node.querySelector('.model-think-level[data-level="none"]'); return {name:node.querySelector('.model-name').value.trim(),alias:node.querySelector('.model-alias').value.trim(),image:node.querySelector('.model-image').checked,thinking_disabled:!!(none && none.checked),thinking_levels:levels}; }).filter(item=>item.name || item.alias); }
function payload(){const keyRows=collectKeyRows(); return {original_name:el('original_name').value,original_prefix:el('original_prefix').value,original_base_url:el('original_base_url').value,name:el('name').value.trim(),prefix:el('prefix').value.trim(),base_url:el('base_url').value.trim(),priority:Number(el('priority').value||0),disabled:el('disabled').checked,disable_cooling:el('disable_cooling').checked,api_keys:keyRows.filter(row=>!row.existing).map(row=>row.value).filter(Boolean),api_key_rows:keyRows,headers:collectHeaders(),models:collectModels(),enabled:el('enabled').checked,allow_explicit_client_identity_headers:el('allow_explicit_client_identity_headers').checked,principal_fallback_mode:el('principal_fallback_mode').value,debug_logging:el('debug_logging').value==='true',executor_enabled:el('executor_enabled').value==='true',executor_provider:el('executor_provider').value.trim(),model_namespace:el('model_namespace').value.trim(),hmac_secret:el('hmac_secret').value,agy2api_identity_secret:el('agy_secret').value,hmac_secret_source:el('hmac_source').value}}
async function call(path,body){const res=await fetch(MGT+path,{method:body?'POST':'GET',headers:mgmtHeaders(!!body),body:body?JSON.stringify(body):undefined}); const text=await res.text(); let data; try{data=JSON.parse(text)}catch{data=text} if(!res.ok) throw new Error(typeof data==='string'?data:JSON.stringify(data)); return data}
el('load-secure').onclick=async()=>{try{if(el('mkey').value.trim()) sessionStorage.setItem('agyBridgeManagementKey',el('mkey').value.trim()); const data=await call('/provider/config'); render(data); show('Secure config loaded.')}catch(e){show('Could not load secure config: '+e.message)}}
el('clear-key').onclick=()=>{sessionStorage.removeItem('agyBridgeManagementKey'); el('mkey').value=''; show('Management key cleared from this browser session.')}
el('add-key').onclick=()=>{if(state.locked){show('Load secure config first.'); return} const box=el('api-key-rows'); const wrap=document.createElement('div'); wrap.innerHTML=rowHtml('key',{existing:false},box.children.length); const node=wrap.firstElementChild; node.querySelector('.row-remove').onclick=()=>{node.remove(); updateCounts();}; box.appendChild(node); updateCounts(); node.querySelector('.api-key-value').focus();}
el('add-header').onclick=()=>{if(state.locked){show('Load secure config first.'); return} const box=el('header-rows'); const wrap=document.createElement('div'); wrap.innerHTML=rowHtml('header',{},box.children.length); const node=wrap.firstElementChild; node.querySelector('.row-remove').onclick=()=>{node.remove(); updateCounts();}; box.appendChild(node); updateCounts(); node.querySelector('.header-key').focus();}
el('add-model').onclick=()=>{if(state.locked){show('Load secure config first.'); return} const box=el('model-rows'); const wrap=document.createElement('div'); wrap.innerHTML=rowHtml('model',{name:'',alias:'',thinking_levels:['low','medium','high']},box.children.length); const node=wrap.firstElementChild; node.querySelector('.row-remove').onclick=()=>{node.remove(); updateCounts();}; node.querySelectorAll('.model-think-level').forEach(cb=>{cb.onchange=()=>{ if(cb.dataset.level === 'none' && cb.checked){ node.querySelectorAll('.model-think-level').forEach(other=>{ if(other !== cb && other.dataset.level !== 'none'){ other.checked = false; } }); } else if(cb.dataset.level !== 'none' && cb.checked){ const none = node.querySelector('.model-think-level[data-level="none"]'); if(none) none.checked = false; } updateCounts(); }; }); box.appendChild(node); updateCounts(); node.querySelector('.model-name').focus();}
el('fetch-models').onclick=async()=>{if(state.locked){show('Load secure config first.'); return} try{const data=await call('/provider/fetch-models',payload()); if(data.models){ renderModelRows((data.models||[]).map(id=>({name:id,thinking_levels:['low','medium','high']}))); } show(data)}catch(e){show('Fetch failed: '+e.message)}}
el('test-provider').onclick=async()=>{if(state.locked){show('Load secure config first.'); return} try{show(await call('/provider/test',payload()))}catch(e){show('Test failed: '+e.message)}}
el('editor-form').onsubmit=async(ev)=>{ev.preventDefault(); if(state.locked){show('Load secure config first.'); return} try{const data=await call('/provider/save',payload()); show(data); if(data.editor) render(data.editor)}catch(e){show('Save failed: '+e.message)}}
render(state);
</script>
</body>
</html>`,
		pluginID,
		html.EscapeString(status),
		len(data.Provider.PublishedModelIDs),
		boolToEnabled(data.Provider.OriginalProviderLive),
		boolToReady(data.Diagnostics.ExecutorAuthEnsured),
		html.EscapeString(status),
		lockedMessage,
		seed,
		pluginID,
	)
}

func handleProviderEditorSave(request pluginapi.ManagementRequest) ([]byte, error) {
	payload, errParse := parseProviderEditorPayload(request.Body)
	if errParse != nil {
		return managementJSONResponse(http.StatusBadRequest, map[string]string{"error": errParse.Error()}), nil
	}
	snapshot := currentConfigSnapshot()
	if !snapshot.ConfigPathFound || strings.TrimSpace(snapshot.ConfigPath) == "" {
		return managementJSONResponse(http.StatusConflict, map[string]string{"error": "mounted CPA config path was not found"}), nil
	}
	updated, changed, errPatch := patchProviderConfig(snapshot.ConfigYAML, payload, currentPluginSettings())
	if errPatch != nil {
		return managementJSONResponse(http.StatusBadRequest, map[string]string{"error": errPatch.Error()}), nil
	}
	mode := os.FileMode(0600)
	if info, errStat := os.Stat(snapshot.ConfigPath); errStat == nil {
		mode = info.Mode().Perm()
	}
	if errWrite := os.WriteFile(snapshot.ConfigPath, updated, mode); errWrite != nil {
		return managementJSONResponse(http.StatusInternalServerError, map[string]string{"error": "write CPA config: " + errWrite.Error()}), nil
	}
	applyPluginConfiguration(loadPluginConfiguration(updated))
	storeProviderSpec(providerSpec{}, false)
	resetExecutorAuthRecordState()
	if spec, found := resolveProviderSpec(); found {
		_ = ensureAuthRecord(spec, currentPluginSettings())
	}
	recordDashboardEvent("success", "Provider editor saved CPA config")
	diagnostics := scanProviderDiagnostics()
	return managementJSONResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"changed": changed,
		"editor":  currentProviderEditorData(diagnostics, true),
	}), nil
}

func handleProviderTest(request pluginapi.ManagementRequest) ([]byte, error) {
	payload, _ := parseProviderEditorPayload(request.Body)
	spec := providerSpecFromEditorPayload(payload)
	if spec.BaseURL == "" || spec.primaryAPIKey() == "" {
		if current, found := resolveProviderSpec(); found {
			if spec.BaseURL == "" {
				spec.BaseURL = current.BaseURL
			}
			if spec.primaryAPIKey() == "" {
				spec.APIKeys = current.APIKeys
			}
			if len(spec.Headers) == 0 {
				spec.Headers = current.Headers
			}
		}
	}
	status, models, errProbe := probeProviderModels(spec)
	if errProbe != nil {
		return managementJSONResponse(http.StatusBadGateway, map[string]any{"ok": false, "error": errProbe.Error()}), nil
	}
	return managementJSONResponse(http.StatusOK, map[string]any{
		"ok":          status >= 200 && status < 300,
		"http_status": status,
		"model_count": len(models),
		"models":      models,
	}), nil
}

func handleProviderFetchModels(request pluginapi.ManagementRequest) ([]byte, error) {
	payload, _ := parseProviderEditorPayload(request.Body)
	spec := providerSpecFromEditorPayload(payload)
	if spec.BaseURL == "" || spec.primaryAPIKey() == "" {
		if current, found := resolveProviderSpec(); found {
			if spec.BaseURL == "" {
				spec.BaseURL = current.BaseURL
			}
			if spec.primaryAPIKey() == "" {
				spec.APIKeys = current.APIKeys
			}
			if len(spec.Headers) == 0 {
				spec.Headers = current.Headers
			}
		}
	}
	status, models, errProbe := probeProviderModels(spec)
	if errProbe != nil {
		return managementJSONResponse(http.StatusBadGateway, map[string]any{"ok": false, "error": errProbe.Error()}), nil
	}
	return managementJSONResponse(http.StatusOK, map[string]any{
		"ok":          status >= 200 && status < 300,
		"http_status": status,
		"model_count": len(models),
		"models":      models,
	}), nil
}

func parseProviderEditorPayload(raw []byte) (providerEditorPayload, error) {
	var payload providerEditorPayload
	if len(raw) == 0 {
		return payload, nil
	}
	if errUnmarshal := json.Unmarshal(raw, &payload); errUnmarshal != nil {
		return payload, fmt.Errorf("invalid provider editor payload")
	}
	payload.Name = strings.TrimSpace(payload.Name)
	payload.Prefix = strings.Trim(strings.TrimSpace(payload.Prefix), "/")
	payload.BaseURL = strings.TrimRight(strings.TrimSpace(payload.BaseURL), "/")
	payload.OriginalName = strings.TrimSpace(payload.OriginalName)
	payload.OriginalPrefix = strings.Trim(strings.TrimSpace(payload.OriginalPrefix), "/")
	payload.OriginalBaseURL = strings.TrimRight(strings.TrimSpace(payload.OriginalBaseURL), "/")
	payload.ExecutorProvider = normalizeProviderKey(payload.ExecutorProvider)
	payload.ModelNamespace = strings.Trim(strings.TrimSpace(payload.ModelNamespace), "/")
	payload.HMACSecret = strings.TrimSpace(payload.HMACSecret)
	payload.Agy2apiIdentitySecret = strings.TrimSpace(payload.Agy2apiIdentitySecret)
	payload.HMACSecretSource = strings.ToLower(strings.TrimSpace(payload.HMACSecretSource))
	payload.APIKeys = uniqueStrings(payload.APIKeys)
	for i := range payload.APIKeyRows {
		payload.APIKeyRows[i].Value = strings.TrimSpace(payload.APIKeyRows[i].Value)
	}
	payload.ModelIDs = uniqueStrings(payload.ModelIDs)
	if len(payload.Models) == 0 && len(payload.ModelIDs) > 0 {
		payload.Models = editorModelsFromIDs(payload.ModelIDs)
	}
	for i := range payload.Models {
		payload.Models[i].Name = strings.TrimSpace(payload.Models[i].Name)
		payload.Models[i].Alias = strings.TrimSpace(payload.Models[i].Alias)
		payload.Models[i].ThinkingLevels = uniqueStrings(payload.Models[i].ThinkingLevels)
		payload.Models[i].InputModalities = uniqueStrings(payload.Models[i].InputModalities)
		payload.Models[i].OutputModalities = uniqueStrings(payload.Models[i].OutputModalities)
	}
	headers := make([]editorHeaderPair, 0, len(payload.Headers))
	for _, header := range payload.Headers {
		header.Key = strings.TrimSpace(header.Key)
		header.Value = strings.TrimSpace(header.Value)
		if header.Key != "" && header.Value != "" {
			headers = append(headers, header)
		}
	}
	payload.Headers = headers
	return payload, nil
}

func providerSpecFromEditorPayload(payload providerEditorPayload) providerSpec {
	headers := make(map[string]string, len(payload.Headers))
	for _, header := range payload.Headers {
		headers[header.Key] = header.Value
	}
	return providerSpec{
		Name:           payload.Name,
		Prefix:         payload.Prefix,
		BaseURL:        payload.BaseURL,
		APIKeys:        payload.APIKeys,
		Headers:        headers,
		Priority:       payload.Priority,
		DisableCooling: payload.DisableCooling,
		Enabled:        !payload.Disabled,
	}
}

func probeProviderModels(spec providerSpec) (int, []string, error) {
	if spec.upstreamBaseURL() == "" {
		return 0, nil, fmt.Errorf("base URL is required")
	}
	if spec.primaryAPIKey() == "" {
		return 0, nil, fmt.Errorf("API key is required or must already exist in provider config")
	}
	headers := map[string][]string{
		"Authorization": {"Bearer " + spec.primaryAPIKey()},
		"Accept":        {"application/json"},
		"User-Agent":    {"agy-identity-bridge-dashboard"},
	}
	for key, value := range spec.Headers {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			headers[key] = []string{value}
		}
	}
	request := hostHTTPRequest{
		Method:  "GET",
		URL:     spec.upstreamBaseURL() + "/models",
		Headers: headers,
	}
	raw, errCall := hostCall(pluginabi.MethodHostHTTPDo, request.marshal())
	if errCall != nil {
		return 0, nil, errCall
	}
	var response hostHTTPResponse
	if errDecode := json.Unmarshal(raw, &response); errDecode != nil {
		return 0, nil, fmt.Errorf("decode host HTTP response: %w", errDecode)
	}
	models := parseOpenAIModels(unb64(response.Body))
	return response.StatusCode, models, nil
}

func parseOpenAIModels(raw []byte) []string {
	var decoded struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		return nil
	}
	models := make([]string, 0, len(decoded.Data))
	for _, item := range decoded.Data {
		if id := strings.TrimSpace(item.ID); id != "" {
			models = append(models, id)
		}
	}
	sortStrings(models)
	return uniqueStrings(models)
}

func patchProviderConfig(raw []byte, payload providerEditorPayload, settings PluginSettings) ([]byte, []string, error) {
	root, errParse := parseYAMLMap(raw)
	if errParse != nil {
		return nil, nil, fmt.Errorf("parse CPA config: %w", errParse)
	}
	if root == nil {
		return nil, nil, fmt.Errorf("CPA config is empty")
	}
	entries := openAICompatEntries(root)
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("openai-compatibility providers were not found")
	}
	index := findEditableProviderIndex(entries, payload)
	if index < 0 {
		return nil, nil, fmt.Errorf("mirrored provider was not found in config")
	}
	provider := entries[index]
	changed := make([]string, 0, 12)
	setString(provider, "name", payload.Name, &changed)
	setString(provider, "prefix", payload.Prefix, &changed)
	setString(provider, "base-url", payload.BaseURL, &changed)
	setInt(provider, "priority", payload.Priority, &changed)
	setBool(provider, "disabled", payload.Disabled, &changed)
	setBool(provider, "disable-cooling", payload.DisableCooling, &changed)
	if len(payload.Headers) == 0 {
		deleteNormalized(provider, "headers", &changed)
	} else {
		headers := make(map[string]any, len(payload.Headers))
		for _, header := range payload.Headers {
			headers[header.Key] = header.Value
		}
		setAny(provider, "headers", headers, &changed)
	}
	if len(payload.APIKeyRows) > 0 {
		apiEntries := make([]any, 0, len(payload.APIKeyRows))
		currentKeys := compatAPIKeys(provider)
		for index, row := range payload.APIKeyRows {
			value := strings.TrimSpace(row.Value)
			if value == "" && row.Existing {
				if index < len(currentKeys) {
					value = currentKeys[index]
				}
			}
			if value == "" {
				continue
			}
			apiEntries = append(apiEntries, map[string]any{"api-key": value})
		}
		if len(apiEntries) > 0 {
			setAny(provider, "api-key-entries", apiEntries, &changed)
		}
	} else if len(payload.APIKeys) > 0 {
		apiEntries := make([]any, 0, len(payload.APIKeys))
		for _, key := range payload.APIKeys {
			apiEntries = append(apiEntries, map[string]any{"api-key": key})
		}
		setAny(provider, "api-key-entries", apiEntries, &changed)
	}
	if len(payload.Models) > 0 {
		setAny(provider, "models", modelsForEditorPayload(payload.Models, compatModels(provider)), &changed)
	} else if len(payload.ModelIDs) > 0 {
		setAny(provider, "models", modelsForEditorPayload(editorModelsFromIDs(payload.ModelIDs), compatModels(provider)), &changed)
	}
	if errUpdate := replaceOpenAICompatEntry(root, index, provider); errUpdate != nil {
		return nil, nil, errUpdate
	}
	pluginConfig := ensurePluginConfig(root)
	if payload.ExecutorProvider == "" {
		payload.ExecutorProvider = settings.ExecutorProvider
	}
	setBool(pluginConfig, "enabled", payload.Enabled, &changed)
	setBool(pluginConfig, "allow_explicit_client_identity_headers", payload.AllowExplicitClientIdentityHeaders, &changed)
	setString(pluginConfig, "principal_fallback_mode", payload.PrincipalFallbackMode, &changed)
	setBool(pluginConfig, "debug_logging", payload.DebugLogging, &changed)
	setBool(pluginConfig, "executor_enabled", payload.ExecutorEnabled, &changed)
	setString(pluginConfig, "executor_provider", payload.ExecutorProvider, &changed)
	setString(pluginConfig, "model_namespace", payload.ModelNamespace, &changed)
	if payload.HMACSecret != "" {
		setString(pluginConfig, "hmac_secret", payload.HMACSecret, &changed)
	}
	if payload.HMACSecretSource != "" {
		setString(pluginConfig, "hmac_secret_source", payload.HMACSecretSource, &changed)
	}
	if payload.Agy2apiIdentitySecret != "" {
		setString(pluginConfig, "agy2api_identity_secret", payload.Agy2apiIdentitySecret, &changed)
	}
	out, errMarshal := yaml.Marshal(root)
	if errMarshal != nil {
		return nil, nil, fmt.Errorf("marshal CPA config: %w", errMarshal)
	}
	return out, uniqueStrings(changed), nil
}

func findEditableProviderIndex(entries []map[string]any, payload providerEditorPayload) int {
	for index, provider := range entries {
		name, _ := stringValue(provider, "name")
		prefix, _ := stringValue(provider, "prefix")
		baseURL, _ := stringValue(provider, "base-url", "base_url", "url")
		if payload.OriginalName != "" && !strings.EqualFold(name, payload.OriginalName) {
			continue
		}
		if payload.OriginalPrefix != "" && !strings.EqualFold(prefix, payload.OriginalPrefix) {
			continue
		}
		if payload.OriginalBaseURL != "" && strings.TrimRight(baseURL, "/") != payload.OriginalBaseURL {
			continue
		}
		return index
	}
	for index, provider := range entries {
		name, _ := stringValue(provider, "name")
		baseURL, _ := stringValue(provider, "base-url", "base_url", "url")
		if payload.Name != "" && strings.EqualFold(name, payload.Name) {
			return index
		}
		if payload.BaseURL != "" && strings.TrimRight(baseURL, "/") == payload.BaseURL {
			return index
		}
	}
	return -1
}

func replaceOpenAICompatEntry(root map[string]any, index int, provider map[string]any) error {
	raw, ok := mapValue(root, "openai-compatibility", "openai_compatibility")
	if !ok {
		return fmt.Errorf("openai-compatibility providers were not found")
	}
	entries := asSlice(raw)
	if index < 0 || index >= len(entries) {
		return fmt.Errorf("provider index is out of range")
	}
	entries[index] = provider
	setAny(root, "openai-compatibility", entries, nil)
	return nil
}

func ensurePluginConfig(root map[string]any) map[string]any {
	plugins := ensureMap(root, "plugins")
	configs := ensureMap(plugins, "configs")
	return ensureMap(configs, pluginID)
}

func ensureMap(parent map[string]any, key string) map[string]any {
	if raw, ok := mapValue(parent, key); ok {
		if existing := asMap(raw); existing != nil {
			return existing
		}
	}
	child := map[string]any{}
	parent[key] = child
	return child
}

func editorModelsFromSpec(models []modelSpec) []providerEditorModel {
	if len(models) == 0 {
		return nil
	}
	out := make([]providerEditorModel, 0, len(models))
	for _, model := range models {
		out = append(out, providerEditorModel{
			Name:             model.Name,
			Alias:            model.Alias,
			Image:            model.Image,
			ThinkingLevels:   append([]string(nil), thinkingLevels(model.Thinking)...),
			InputModalities:  append([]string(nil), model.InputModalities...),
			OutputModalities: append([]string(nil), model.OutputModalities...),
			ThinkingDisabled: model.Thinking != nil && len(model.Thinking.Levels) == 0,
		})
	}
	return out
}

func editorModelsFromIDs(ids []string) []providerEditorModel {
	if len(ids) == 0 {
		return nil
	}
	out := make([]providerEditorModel, 0, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		out = append(out, providerEditorModel{Name: id})
	}
	return out
}

func thinkingLevels(spec *thinkingSpec) []string {
	if spec == nil {
		return nil
	}
	return append([]string(nil), spec.Levels...)
}

func modelsForEditorPayload(rows []providerEditorModel, existing []modelSpec) []any {
	byID := make(map[string]modelSpec, len(existing)*2)
	for _, model := range existing {
		if model.Name != "" {
			byID[strings.ToLower(model.Name)] = model
		}
		if model.Alias != "" {
			byID[strings.ToLower(model.Alias)] = model
		}
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		id := strings.TrimSpace(row.Name)
		if id == "" {
			id = strings.TrimSpace(row.Alias)
		}
		if id == "" {
			continue
		}
		model, found := byID[strings.ToLower(id)]
		if !found {
			item := map[string]any{"name": id}
			if row.Alias != "" {
				item["alias"] = row.Alias
			}
			if row.Image {
				item["image"] = true
			}
			if len(row.ThinkingLevels) > 0 || row.ThinkingDisabled {
				item["thinking"] = map[string]any{
					"levels": row.ThinkingLevels,
				}
			}
			if len(row.InputModalities) > 0 {
				item["input-modalities"] = row.InputModalities
			}
			if len(row.OutputModalities) > 0 {
				item["output-modalities"] = row.OutputModalities
			}
			out = append(out, item)
			continue
		}
		item := map[string]any{}
		if row.Name != "" {
			item["name"] = row.Name
		} else if model.Name != "" {
			item["name"] = model.Name
		}
		if row.Alias != "" {
			item["alias"] = row.Alias
		} else if model.Alias != "" {
			item["alias"] = model.Alias
		}
		if row.Image || model.Image {
			item["image"] = row.Image || model.Image
		}
		if len(row.InputModalities) > 0 {
			item["input-modalities"] = row.InputModalities
		} else if len(model.InputModalities) > 0 {
			item["input-modalities"] = model.InputModalities
		}
		if len(row.OutputModalities) > 0 {
			item["output-modalities"] = row.OutputModalities
		} else if len(model.OutputModalities) > 0 {
			item["output-modalities"] = model.OutputModalities
		}
		if len(row.ThinkingLevels) > 0 || row.ThinkingDisabled {
			item["thinking"] = map[string]any{
				"levels": row.ThinkingLevels,
			}
		} else if model.Thinking != nil {
			item["thinking"] = map[string]any{
				"min":             model.Thinking.Min,
				"max":             model.Thinking.Max,
				"zero-allowed":    model.Thinking.ZeroAllowed,
				"dynamic-allowed": model.Thinking.DynamicAllowed,
				"levels":          model.Thinking.Levels,
			}
		}
		out = append(out, item)
	}
	return out
}

func setString(target map[string]any, key, value string, changed *[]string) {
	setAny(target, key, strings.TrimSpace(value), changed)
}

func setInt(target map[string]any, key string, value int, changed *[]string) {
	setAny(target, key, value, changed)
}

func setBool(target map[string]any, key string, value bool, changed *[]string) {
	setAny(target, key, value, changed)
}

func setAny(target map[string]any, key string, value any, changed *[]string) {
	actual := existingKey(target, key)
	if actual == "" {
		actual = key
	}
	target[actual] = value
	if changed != nil {
		*changed = append(*changed, key)
	}
}

func deleteNormalized(target map[string]any, key string, changed *[]string) {
	actual := existingKey(target, key)
	if actual == "" {
		return
	}
	delete(target, actual)
	if changed != nil {
		*changed = append(*changed, key)
	}
}

func existingKey(target map[string]any, key string) string {
	want := normalizedMapKey(key)
	for existing := range target {
		if normalizedMapKey(existing) == want {
			return existing
		}
	}
	return ""
}

func boolToEnabled(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

func boolToReady(value bool) string {
	if value {
		return "ready"
	}
	return "not ready"
}

func jsonForScript(value any) string {
	raw, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		raw = []byte(`{"error":"serialization failed"}`)
	}
	return strings.ReplaceAll(string(raw), "</", "<\\/")
}

func sortStrings(values []string) {
	sort.SliceStable(values, func(i, j int) bool {
		return strings.ToLower(values[i]) < strings.ToLower(values[j])
	})
}

func dashboardModelChips(values []string, emptyText string) string {
	if len(values) == 0 {
		return `<div class="model-empty">` + html.EscapeString(emptyText) + `</div>`
	}
	var builder strings.Builder
	builder.WriteString(`<div class="chips">`)
	for _, value := range values {
		builder.WriteString(`<span class="chip">`)
		builder.WriteString(html.EscapeString(value))
		builder.WriteString(`</span>`)
	}
	builder.WriteString(`</div>`)
	return builder.String()
}

func boolToLabel(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

type dashboardStatus struct {
	label string
	pill  string
}

func dashboardRouteState(public providerDiagnostics) (dashboardStatus, string) {
	if !public.Enabled {
		return dashboardStatus{label: "Plugin disabled", pill: "Disabled"}, "muted"
	}
	if !public.ExecutorEnabled {
		return dashboardStatus{label: "Routing unchanged", pill: "Executor off"}, "info"
	}
	if !public.ExecutorAuthEnsured {
		return dashboardStatus{label: "Executor not ready", pill: "Auth missing"}, "error"
	}
	if public.LastExecutorStatus >= 400 {
		return dashboardStatus{label: "Executor degraded", pill: fmt.Sprintf("HTTP %d", public.LastExecutorStatus)}, "error"
	}
	if !public.ModelsServed {
		return dashboardStatus{label: "Models withheld", pill: "Withheld"}, "warning"
	}
	if public.ReplacementMode == "namespace" {
		return dashboardStatus{label: "Namespace test active", pill: "Namespace"}, "info"
	}
	if public.ReplacementMode == "active" {
		return dashboardStatus{label: "Plugin replacement live", pill: "Live"}, "success"
	}
	return dashboardStatus{label: "Serving mirrored models", pill: "Serving"}, "info"
}

func dashboardPublishedModelCount(public providerDiagnostics) int {
	if !public.ModelsServed {
		return 0
	}
	return public.MirroredModelCount
}

func dashboardCheck(ok bool, okText, badText string) string {
	if ok {
		return fmt.Sprintf(`<div class="check"><span class="dot tone-success"></span><span class="ok">%s</span></div>`, html.EscapeString(okText))
	}
	return fmt.Sprintf(`<div class="check"><span class="dot tone-error"></span><span class="bad">%s</span></div>`, html.EscapeString(badText))
}

func dashboardEventTone(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "success", "info":
		return "success"
	case "warning", "warn":
		return "warning"
	case "error":
		return "error"
	default:
		return "muted"
	}
}

func dashboardStatusTone(status int) string {
	if status >= 400 {
		return "error"
	}
	if status >= 300 {
		return "warning"
	}
	return "success"
}

func providerActivityLabel(provider providerStatus) string {
	if !provider.Active {
		return "matched, inactive"
	}
	return "matched, active"
}
