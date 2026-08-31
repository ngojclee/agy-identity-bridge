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
		"version":                    pluginVersion,
		"enabled":                    settings.Enabled,
		"priority":                   settings.Priority,
		"auto_discover":              settings.AutoDiscover,
		"include_native_antigravity": settings.IncludeNativeAntigravity,
		"match_mode":                 settings.MatchMode,
		"match_name":                 settings.MatchName,
		"match_url":                  redactURL(settings.MatchURL),
		"match_api_key_configured":   settings.MatchAPIKey != "",
		"match_provider":             settings.MatchProvider,
		"match_providers":            settings.MatchProviders,
		"configured_selector_count":  settings.configuredSelectorCount(),
		"hmac_secret_configured":     settings.hmacSecret() != "",
		"hmac_secret_source":         settings.hmacSecretSource(),
		"config_path_found":          snapshot.ConfigPathFound,
		"plugin_config_found":        snapshot.PluginConfigFound,
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
	public := publicProviderDiagnostics(diagnostics)
	raw, errMarshal := json.MarshalIndent(public, "", "  ")
	if errMarshal != nil {
		raw = []byte(`{"error":"status serialization failed"}`)
	}
	rows := make([]string, 0, len(public.Providers))
	for _, provider := range public.Providers {
		rows = append(rows, fmt.Sprintf(
			"<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			html.EscapeString(provider.Name),
			html.EscapeString(provider.Source),
			html.EscapeString(provider.ProviderKey),
			html.EscapeString(strings.Join(provider.MatchedBy, ", ")),
			html.EscapeString(providerActivityLabel(provider)),
		))
	}
	if len(rows) == 0 {
		rows = append(rows, `<tr><td colspan="5">No matching provider records</td></tr>`)
	}
	warnings := make([]string, 0, len(public.Warnings))
	for _, warning := range public.Warnings {
		warnings = append(warnings, "<li>"+html.EscapeString(warning)+"</li>")
	}
	if len(warnings) == 0 {
		warnings = append(warnings, "<li>None</li>")
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AGY Identity Bridge</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 28px; color: #172033; background: #f7f8fa; }
    main { max-width: 860px; margin: 0 auto; }
    h1 { margin: 0 0 8px; font-size: 24px; }
    p { color: #536071; margin: 0 0 18px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 18px 0; }
    .metric { background: #fff; border: 1px solid #d9dee7; padding: 12px; border-radius: 6px; }
    .metric strong { display: block; font-size: 22px; color: #172033; }
    .metric span { color: #536071; font-size: 13px; }
    table { width: 100%%; border-collapse: collapse; background: #fff; border: 1px solid #d9dee7; }
    th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #e7eaf0; vertical-align: top; }
    th { color: #536071; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    ul { background: #fff; border: 1px solid #d9dee7; padding: 12px 12px 12px 30px; }
    details { margin-top: 18px; }
    pre { overflow: auto; background: #111827; color: #e5e7eb; padding: 16px; border-radius: 6px; line-height: 1.45; }
  </style>
</head>
<body>
  <main>
    <h1>AGY Identity Bridge</h1>
    <p>Redacted provider matching diagnostics. Use the authenticated Management API status endpoint for path-level details.</p>
    <section class="summary">
      <div class="metric"><strong>%d</strong><span>Scanned records</span></div>
      <div class="metric"><strong>%d</strong><span>Matched records</span></div>
      <div class="metric"><strong>%d</strong><span>Unique matched providers</span></div>
      <div class="metric"><strong>%d</strong><span>Intercepted requests</span></div>
    </section>
    <h2>Providers affected</h2>
    <table>
      <thead><tr><th>Name</th><th>Source</th><th>Provider key</th><th>Matched by</th><th>Activity</th></tr></thead>
      <tbody>%s</tbody>
    </table>
    <h2>Warnings</h2>
    <ul>%s</ul>
    <details>
      <summary>Redacted JSON</summary>
      <pre>%s</pre>
    </details>
  </main>
</body>
</html>`,
		public.ScannedRecordCount,
		public.MatchedRecordCount,
		public.MatchedProviderCount,
		public.InterceptCount,
		strings.Join(rows, ""),
		strings.Join(warnings, ""),
		html.EscapeString(string(raw)),
	)
}

func providerActivityLabel(provider providerStatus) string {
	if !provider.Active {
		return "matched, inactive"
	}
	return "matched, active"
}
