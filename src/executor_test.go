package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExecutorRegistrationOnlyWhenEnabled(t *testing.T) {
	loadMirror(t)
	caps := registrationCapabilities()
	if caps.Executor {
		t.Fatal("executor capability declared while executor mode is off")
	}
	if caps.ExecutorModelScope != "" || len(caps.ExecutorInputFormats) != 0 {
		t.Fatalf("executor formats declared while off: %+v", caps)
	}
}

func TestExecutorIdentifierUsesConfiguredProviderKey(t *testing.T) {
	loadMirror(t)
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			Identifier string `json:"identifier"`
		} `json:"result"`
	}
	if errUnmarshal := json.Unmarshal(handleExecutorIdentifier(), &decoded); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !decoded.OK || decoded.Result.Identifier != defaultExecutorProvider {
		t.Fatalf("identifier = %s", handleExecutorIdentifier())
	}
}

// The wire contract: the host decodes pluginapi.ExecutorRequest from untagged
// Go fields. A snake_case-only parser would read nothing, exactly like the
// interceptor bug that made v0.1.4 a silent no-op.
func TestParseExecutorRequestAcceptsCPAGoStyleKeys(t *testing.T) {
	raw := []byte(`{"AuthID":"auth-1","AuthProvider":"agy-bridge","Model":"gemini-3.1-pro","Format":"openai","Stream":true,"Alt":"","Headers":{"Authorization":["Bearer client-key"],"X-AGY-Device":["device_0123456789abcdef"]},"Payload":"eyJtZXNzYWdlcyI6W119","SourceFormat":"openai","HostCallbackID":"cb-42"}`)
	req, errParse := parseExecutorRequest(raw)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if req.Model != "gemini-3.1-pro" || !req.Stream {
		t.Fatalf("request lost fields: %+v", req)
	}
	if req.AuthID != "auth-1" || req.HostCallbackID != "cb-42" {
		t.Fatalf("auth/callback context lost: %+v", req)
	}
	if string(req.Payload) != `{"messages":[]}` {
		t.Fatalf("payload not decoded: %q", string(req.Payload))
	}
	if req.Headers["X-AGY-Device"][0] != "device_0123456789abcdef" {
		t.Fatalf("headers not parsed: %+v", req.Headers)
	}
}

func TestBuildUpstreamRequestAttachesIdentityHeaders(t *testing.T) {
	loadMirror(t)
	settings := currentPluginSettings()
	settings.Agy2apiIdentitySecret = "signing-secret"
	withSettings(t, settings)
	root, errParse := parseYAMLMap([]byte(mirrorConfigYAML))
	if errParse != nil {
		t.Fatal(errParse)
	}
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("no mirrored provider")
	}
	req, errParse2 := parseExecutorRequest([]byte(`{"Model":"gemini-3.1-pro","Format":"openai","Stream":false,"Headers":{"X-AGY-Principal":["principal-hash"],"X-AGY-Client-App":["codex"],"Authorization":["Bearer client-key"]},"Payload":"e30=","HostCallbackID":"cb-1"}`))
	if errParse2 != nil {
		t.Fatal(errParse2)
	}
	identity := identityFromExecutorRequest(req)
	if identity.Principal != "principal-hash" || identity.ClientApp != "codex" {
		t.Fatalf("identity not captured from client headers: %+v", identity)
	}
	upstream, errBuild := buildUpstreamRequest(req, spec, identity)
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	if upstream.URL != "http://10.21.4.101:8123/v1/chat/completions" {
		t.Fatalf("upstream URL = %q", upstream.URL)
	}
	if upstream.Method != "POST" || upstream.HostCallbackID != "cb-1" {
		t.Fatalf("upstream request = %+v", upstream)
	}
	if got := upstream.Headers["Authorization"][0]; strings.HasPrefix(got, "Bearer provider-secret") == false {
		t.Fatalf("upstream authorization = %q, want the mirrored provider key", got)
	}
	// This is the header CPA's own executor drops. It must survive here.
	if upstream.Headers["X-AGY-Principal"][0] != "principal-hash" {
		t.Fatalf("X-AGY-Principal missing from upstream request: %+v", upstream.Headers)
	}
	if upstream.Headers["X-AGY-Client-App"][0] != "codex" {
		t.Fatalf("client app missing: %+v", upstream.Headers)
	}
	if upstream.Headers["X-AGY-Timestamp"][0] == "" {
		t.Fatalf("timestamp missing: %+v", upstream.Headers)
	}
	if upstream.Headers["X-AGY-Plugin-Version"][0] != pluginVersion {
		t.Fatalf("plugin version missing: %+v", upstream.Headers)
	}
	if upstream.Headers["X-AGY-CPA-Provider-Name"][0] != spec.Name {
		t.Fatalf("provider name missing: %+v", upstream.Headers)
	}
	expectedSig := computeHMAC(identitySignatureMessage(clientIdentityContext{
		Principal:    identity.Principal,
		ClientApp:    identity.ClientApp,
		Timestamp:    upstream.Headers["X-AGY-Timestamp"][0],
		ProviderName: spec.Name,
	}, "POST", "/chat/completions"), hmacSecretForCandidate(currentPluginSettings(), providerCandidate{APIKey: spec.primaryAPIKey()}))
	if upstream.Headers["X-AGY-Signature"][0] != expectedSig {
		t.Fatalf("signature = %q, want %q", upstream.Headers["X-AGY-Signature"][0], expectedSig)
	}
	// The client's own bearer key must never be forwarded upstream.
	for key, values := range upstream.Headers {
		for _, value := range values {
			if key != "Authorization" && strings.Contains(value, "client-key") {
				t.Fatalf("client credential leaked into %s: %q", key, value)
			}
		}
	}
}

func TestExecutorStripsPublishedPrefixBeforeCallingAgy2api(t *testing.T) {
	loadMirror(t)
	root, errParse := parseYAMLMap([]byte(mirrorConfigYAML))
	if errParse != nil {
		t.Fatal(errParse)
	}
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("no mirrored provider")
	}
	req, errParse := parseExecutorRequest([]byte(`{"Model":"agy/gemini-3.1-pro","Payload":"eyJtb2RlbCI6ImFneS9nZW1pbmktMy4xLXBybyIsIm1lc3NhZ2VzIjpbXX0="}`))
	if errParse != nil {
		t.Fatal(errParse)
	}
	normalizeExecutorModel(&req, spec)
	if req.Model != "gemini-3.1-pro" {
		t.Fatalf("executor model = %q", req.Model)
	}
	upstream, errBuild := buildUpstreamRequest(req, spec, identityFromExecutorRequest(req))
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	var body map[string]any
	if errUnmarshal := json.Unmarshal(unb64(upstream.Body), &body); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if body["model"] != "gemini-3.1-pro" {
		t.Fatalf("upstream payload model = %#v", body["model"])
	}
}

func TestForceStreamingPayload(t *testing.T) {
	input := []byte(`{"model":"gemini-3.7-flash-high","messages":[]}`)
	output := forceStreamingPayload(input)
	var body map[string]any
	if err := json.Unmarshal(output, &body); err != nil {
		t.Fatal(err)
	}
	if streamed, ok := body["stream"].(bool); !ok || !streamed {
		t.Fatalf("stream flag = %#v, want true", body["stream"])
	}

	alreadyStreaming := []byte(`{"stream":true,"messages":[]}`)
	if got := string(forceStreamingPayload(alreadyStreaming)); got != string(alreadyStreaming) {
		t.Fatalf("already-streaming payload changed: %s", got)
	}

	invalid := []byte(`not-json`)
	if got := string(forceStreamingPayload(invalid)); got != string(invalid) {
		t.Fatalf("invalid payload should pass through unchanged: %s", got)
	}
}

func TestModelNamespaceOverridesOriginalPrefixForExecutor(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("no mirrored provider")
	}
	settings := currentPluginSettings()
	settings.ModelNamespace = "spike."
	withSettings(t, settings)
	req := executorRequest{
		Model:   "spike./gemini-3.1-pro",
		Payload: []byte(`{"model":"spike./gemini-3.1-pro"}`),
	}
	normalizeExecutorModel(&req, spec)
	if req.Model != "gemini-3.1-pro" {
		t.Fatalf("namespaced executor model = %q", req.Model)
	}
	var body map[string]any
	if errUnmarshal := json.Unmarshal(req.Payload, &body); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if body["model"] != "gemini-3.1-pro" {
		t.Fatalf("namespaced payload model = %#v", body["model"])
	}
}

func TestExecutorAuthSaveRequestEmbedsJSONObject(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("no mirrored provider")
	}
	authJSON, errJSON := executorAuthJSON(spec, currentPluginSettings())
	if errJSON != nil {
		t.Fatal(errJSON)
	}
	request := map[string]any{
		"name": defaultExecutorProvider + ".json",
		"json": json.RawMessage(authJSON),
	}
	raw, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var decoded map[string]json.RawMessage
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	var auth map[string]any
	if errUnmarshal := json.Unmarshal(decoded["json"], &auth); errUnmarshal != nil {
		t.Fatalf("auth JSON was encoded as a string: %v", errUnmarshal)
	}
	if auth["type"] != defaultExecutorProvider {
		t.Fatalf("auth type = %#v", auth["type"])
	}
	if _, hasLabel := auth["label"]; hasLabel {
		t.Fatalf("auth label = %#v, want omitted for canonical provider identity", auth["label"])
	}
}

func TestExecutorAuthJSONCanonicalizesDuplicateProviderKey(t *testing.T) {
	spec := providerSpec{
		BaseURL: "http://127.0.0.1:8123/v1",
		APIKeys: []string{"test-key"},
		Prefix:  "agy",
	}
	raw, errJSON := executorAuthJSON(spec, PluginSettings{
		ExecutorProvider: "ln.Antigravity-ln.Antigravity",
	})
	if errJSON != nil {
		t.Fatal(errJSON)
	}

	var auth map[string]any
	if errUnmarshal := json.Unmarshal(raw, &auth); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if auth["type"] != defaultExecutorProvider {
		t.Fatalf("auth type = %#v, want %q", auth["type"], defaultExecutorProvider)
	}
	if _, hasLabel := auth["label"]; hasLabel {
		t.Fatalf("auth label = %#v, want omitted", auth["label"])
	}
}

func TestBuildUpstreamRequestRejectsUnusableProvider(t *testing.T) {
	req, errParse := parseExecutorRequest([]byte(`{"Model":"m"}`))
	if errParse != nil {
		t.Fatal(errParse)
	}
	if _, errBuild := buildUpstreamRequest(req, providerSpec{}, identityFromExecutorRequest(req)); errBuild == nil {
		t.Fatal("expected an error when the mirrored provider has no base URL")
	}
}

func TestExecutorExecuteSurfacesUpstreamStatus(t *testing.T) {
	raw, errHandle := handleExecutorExecute([]byte(`{"Model":"m"}`))
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	// Without a mirrored provider the executor must fail loudly, not return an
	// empty success that a client would render as an empty answer.
	if !strings.Contains(string(raw), "provider_unresolved") {
		t.Fatalf("expected provider_unresolved, got %s", raw)
	}
}
