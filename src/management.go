package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const managementBasePath = "/plugins/" + pluginID

func handleManagementRegister() []byte {
	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: managementBasePath + "/status"},
			{Method: http.MethodGet, Path: managementBasePath + "/provider"},
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
		"version":                            pluginVersion,
		"enabled":                            settings.Enabled,
		"priority":                           settings.Priority,
		"auto_discover":                      settings.AutoDiscover,
		"include_native_antigravity":         settings.IncludeNativeAntigravity,
		"match_mode":                         settings.MatchMode,
		"match_name":                         settings.MatchName,
		"match_url":                          redactURL(settings.MatchURL),
		"match_api_key_configured":           settings.MatchAPIKey != "",
		"match_provider":                     settings.MatchProvider,
		"match_providers":                    settings.MatchProviders,
		"match_model":                        settings.MatchModel,
		"match_models":                       settings.MatchModels,
		"configured_selector_count":          settings.configuredSelectorCount(),
		"hmac_secret_configured":             settings.hmacSecret() != "",
		"hmac_secret_source":                 settings.hmacSecretSource(),
		"agy2api_identity_secret_configured": settings.Agy2apiIdentitySecret != "",
		"config_path_found":                  snapshot.ConfigPathFound,
		"plugin_config_found":                snapshot.PluginConfigFound,
		"executor_enabled":                   settings.ExecutorEnabled,
		"executor_provider":                  settings.ExecutorProvider,
		"executor_auth_ensured":              executorAuthRecordEnsured(),
		"model_namespace":                    settings.ModelNamespace,
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
	return dashboardHTML(diagnostics, true)
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

	providerLink := "/v0/management/plugins/" + pluginID + "/provider"
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
