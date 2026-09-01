package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

// ensureAuthRecord creates or updates the auth record for the plugin's own
// provider key so CPA can route requests to this executor. Without it, CPA
// fails with auth_not_found before the executor is ever reached.
//
// The auth JSON mirrors the provider's base_url and API key, but with type set
// to the plugin's own provider key. CPA's buildAuthFromFileData reads type as
// the Provider, which makes it discoverable by the executor selector.
func ensureAuthRecord(spec providerSpec, settings PluginSettings) error {
	if !settings.ExecutorEnabled {
		return nil
	}
	if spec.upstreamBaseURL() == "" || spec.primaryAPIKey() == "" {
		return fmt.Errorf("mirrored provider missing base_url or api_key, cannot create auth record")
	}
	authJSON, errMarshal := json.Marshal(map[string]any{
		"type":     settings.ExecutorProvider,
		"base_url": spec.upstreamBaseURL(),
		"api_key":  spec.primaryAPIKey(),
		"label":    "ln.Antigravity executor",
	})
	if errMarshal != nil {
		return fmt.Errorf("marshal auth record: %w", errMarshal)
	}
	saveRequest, errMarshal2 := json.Marshal(map[string]any{
		"name": settings.ExecutorProvider + ".json",
		"json": json.RawMessage(authJSON),
	})
	if errMarshal2 != nil {
		return fmt.Errorf("marshal auth save request: %w", errMarshal2)
	}
	_, errCall := hostCall(pluginabi.MethodHostAuthSave, saveRequest)
	if errCall != nil {
		return fmt.Errorf("host.auth.save failed: %w", errCall)
	}
	return nil
}

// executorRequest mirrors pluginapi.ExecutorRequest plus the host callback id
// CLIProxyAPI attaches to executor calls. The host decodes untagged Go fields,
// so these keys are the Go field names.
type executorRequest struct {
	AuthID          string
	AuthProvider    string
	Model           string
	Format          string
	Stream          bool
	Alt             string
	Headers         map[string][]string
	Payload         []byte
	SourceFormat    string
	OriginalRequest []byte
	Metadata        map[string]any
	AuthAttributes  map[string]string
	HostCallbackID  string
}

func parseExecutorRequest(raw []byte) (executorRequest, error) {
	var req executorRequest
	if len(raw) == 0 {
		return req, nil
	}
	var decoded map[string]any
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		return req, errUnmarshal
	}
	req.AuthID, _ = stringValue(decoded, "auth_id")
	req.AuthProvider, _ = stringValue(decoded, "auth_provider")
	req.Model, _ = stringValue(decoded, "model")
	req.Format, _ = stringValue(decoded, "format")
	req.Stream, _ = boolValue(decoded, "stream")
	req.Alt, _ = stringValue(decoded, "alt")
	req.SourceFormat, _ = stringValue(decoded, "source_format")
	req.HostCallbackID, _ = stringValue(decoded, "host_callback_id")
	if value, ok := mapValue(decoded, "headers"); ok {
		req.Headers = headerMapFromAny(asMap(value))
	}
	if value, ok := mapValue(decoded, "metadata"); ok {
		req.Metadata = asMap(value)
	}
	if value, ok := mapValue(decoded, "auth_attributes"); ok {
		req.AuthAttributes = stringMapFromAny(asMap(value))
	}
	if value, ok := stringValue(decoded, "payload"); ok {
		if decodedPayload, errDecode := base64.StdEncoding.DecodeString(value); errDecode == nil {
			req.Payload = decodedPayload
		}
	}
	if value, ok := stringValue(decoded, "original_request"); ok {
		if decodedRequest, errDecode := base64.StdEncoding.DecodeString(value); errDecode == nil {
			req.OriginalRequest = decodedRequest
		}
	}
	return req, nil
}

func stringMapFromAny(raw map[string]any) map[string]string {
	if raw == nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		if text, ok := value.(string); ok {
			out[key] = text
		}
	}
	return out
}

// executorEnvelope is emitted with Go field names because the host decodes
// pluginapi.ExecutorResponse and ExecutorStreamResponse without json tags.
type executorEnvelope struct {
	Payload  string              `json:"Payload,omitempty"`
	Headers  map[string][]string `json:"Headers,omitempty"`
	Chunks   []streamChunk       `json:"Chunks,omitempty"`
	StreamID string              `json:"StreamID,omitempty"`
}

type streamChunk struct {
	Payload string `json:"Payload"`
}

// clientIdentity captures what we learned about the caller, which is the whole
// reason this executor exists: CLIProxyAPI's own OpenAI-compatible executor
// drops these headers before the request leaves the process.
type clientIdentity struct {
	Principal string
	ClientApp string
	Signature string
	SessionID string
}

func identityFromExecutorRequest(req executorRequest) clientIdentity {
	identity := clientIdentity{
		Principal: firstHeaderValue(req.Headers, "X-AGY-Principal", "X-AGY-Device"),
		ClientApp: firstHeaderValue(req.Headers, "X-AGY-Client-App", "X-AGY-Device"),
		Signature: firstHeaderValue(req.Headers, "X-AGY-Signature"),
		SessionID: firstHeaderValue(req.Headers, "X-AGY-Session-ID", "X-Session-ID"),
	}
	return identity
}

func identityHeaders(identity clientIdentity, spec providerSpec, req executorRequest) map[string][]string {
	headers := map[string][]string{}
	setIf := func(key, value string) {
		if strings.TrimSpace(value) != "" {
			headers[key] = []string{value}
		}
	}
	// Identity comes first in priority: a principal supplied by an upstream
	// tool call wins, otherwise we derive one from the client key.
	setIf("X-AGY-Principal", identity.Principal)
	setIf("X-AGY-Client-App", identity.ClientApp)
	setIf("X-AGY-Signature", identity.Signature)
	setIf("X-AGY-Session-ID", identity.SessionID)
	setIf("X-AGY-Upstream-Model", req.Model)
	setIf("X-AGY-Provider", spec.Name)
	if secret := hmacSecretForCandidate(currentPluginSettings(), providerCandidate{APIKey: spec.primaryAPIKey()}); secret != "" && identity.Principal != "" {
		headers["X-AGY-Signature"] = []string{computeHMAC(identity.Principal, secret)}
	}
	return headers
}

// hostHTTPRequest is the payload for host.http.do and host.http.do_stream.
type hostHTTPRequest struct {
	HostCallbackID string              `json:"host_callback_id,omitempty"`
	Method         string              `json:"method"`
	URL            string              `json:"url"`
	Headers        map[string][]string `json:"headers,omitempty"`
	Body           string              `json:"body,omitempty"`
}

func (r hostHTTPRequest) marshal() []byte {
	raw, _ := json.Marshal(r)
	return raw
}

type hostHTTPResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       string              `json:"Body"`
}

type hostHTTPStreamStart struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	StreamID   string              `json:"StreamID"`
}

type hostHTTPStreamRead struct {
	Payload string `json:"Payload"`
	Error   string `json:"Error"`
	Done    bool   `json:"Done"`
}

func b64(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func unb64(raw string) []byte {
	if raw == "" {
		return nil
	}
	out, _ := base64.StdEncoding.DecodeString(raw)
	return out
}

// buildUpstreamRequest assembles the call to agy2api. Model identity and
// client identity travel as headers, so nothing depends on the body surviving
// a protocol translation.
func buildUpstreamRequest(req executorRequest, spec providerSpec, identity clientIdentity) (hostHTTPRequest, error) {
	if spec.upstreamBaseURL() == "" {
		return hostHTTPRequest{}, fmt.Errorf("mirrored provider has no base URL")
	}
	if spec.primaryAPIKey() == "" {
		return hostHTTPRequest{}, fmt.Errorf("mirrored provider has no API key configured")
	}
	endpoint := "/chat/completions"
	payload := req.Payload
	// Image requests keep their own endpoint, which agy2api exposes the same
	// way the provider config did.
	if strings.Contains(req.Format, "image") || req.Alt == "openai-image" {
		endpoint = "/images/generations"
	}
	headers := map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", spec.primaryAPIKey())},
		"Content-Type":  {"application/json"},
		"User-Agent":    {"agy-identity-bridge-executor"},
	}
	for key, values := range identityHeaders(identity, spec, req) {
		headers[key] = values
	}
	return hostHTTPRequest{
		HostCallbackID: req.HostCallbackID,
		Method:         "POST",
		URL:            spec.upstreamBaseURL() + endpoint,
		Headers:        headers,
		Body:           b64(payload),
	}, nil
}

func handleExecutorIdentifier() []byte {
	settings := currentPluginSettings()
	return okEnvelope(map[string]string{"identifier": settings.ExecutorProvider})
}

func handleExecutorExecute(raw []byte) ([]byte, error) {
	req, errParse := parseExecutorRequest(raw)
	if errParse != nil {
		return errorEnvelope("parse_error", errParse.Error()), nil
	}
	spec, found := resolveProviderSpec()
	if !found {
		return errorEnvelope("provider_unresolved", "no mirrored provider is configured"), nil
	}
	identity := identityFromExecutorRequest(req)
	upstream, errBuild := buildUpstreamRequest(req, spec, identity)
	if errBuild != nil {
		return errorEnvelope("executor_config_error", errBuild.Error()), nil
	}
	responseRaw, errCall := hostCall(pluginabi.MethodHostHTTPDo, upstream.marshal())
	if errCall != nil {
		return errorEnvelope("upstream_call_failed", errCall.Error()), nil
	}
	var response hostHTTPResponse
	if errDecode := json.Unmarshal(responseRaw, &response); errDecode != nil {
		return errorEnvelope("upstream_decode_failed", errDecode.Error()), nil
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// surfaced verbatim so agy2api's own error detail reaches the client
		return errorEnvelope("upstream_error", fmt.Sprintf(
			"agy2api returned HTTP %d: %s", response.StatusCode, string(unb64(response.Body)))), nil
	}
	return okEnvelope(executorEnvelope{
		Payload: b64(unb64(response.Body)),
		Headers: response.Headers,
	}), nil
}

func handleExecutorExecuteStream(raw []byte) ([]byte, error) {
	req, errParse := parseExecutorRequest(raw)
	if errParse != nil {
		return errorEnvelope("parse_error", errParse.Error()), nil
	}
	spec, found := resolveProviderSpec()
	if !found {
		return errorEnvelope("provider_unresolved", "no mirrored provider is configured"), nil
	}
	identity := identityFromExecutorRequest(req)
	upstream, errBuild := buildUpstreamRequest(req, spec, identity)
	if errBuild != nil {
		return errorEnvelope("executor_config_error", errBuild.Error()), nil
	}
	startRaw, errCall := hostCall(pluginabi.MethodHostHTTPDoStream, upstream.marshal())
	if errCall != nil {
		return errorEnvelope("upstream_call_failed", errCall.Error()), nil
	}
	var start hostHTTPStreamStart
	if errDecode := json.Unmarshal(startRaw, &start); errDecode != nil {
		return errorEnvelope("upstream_decode_failed", errDecode.Error()), nil
	}
	if start.StreamID == "" {
		return errorEnvelope("upstream_stream_unavailable", "host returned no stream id"), nil
	}

	chunks := make([]streamChunk, 0, 32)
	defer hostCall(pluginabi.MethodHostHTTPStreamClose, []byte(fmt.Sprintf(`{"StreamID":%q}`, start.StreamID)))
	for {
		readRaw, errRead := hostCall(pluginabi.MethodHostHTTPStreamRead, []byte(fmt.Sprintf(`{"StreamID":%q}`, start.StreamID)))
		if errRead != nil {
			return errorEnvelope("upstream_stream_failed", errRead.Error()), nil
		}
		var read hostHTTPStreamRead
		if errDecode := json.Unmarshal(readRaw, &read); errDecode != nil {
			return errorEnvelope("upstream_stream_decode_failed", errDecode.Error()), nil
		}
		if read.Error != "" {
			return errorEnvelope("upstream_stream_error", read.Error), nil
		}
		if payload := unb64(read.Payload); len(payload) > 0 {
			chunks = append(chunks, streamChunk{Payload: b64(payload)})
		}
		if read.Done {
			break
		}
	}
	return okEnvelope(executorEnvelope{
		Headers: start.Headers,
		Chunks:  chunks,
	}), nil
}

func handleExecutorCountTokens(raw []byte) ([]byte, error) {
	req, errParse := parseExecutorRequest(raw)
	if errParse != nil {
		return errorEnvelope("parse_error", errParse.Error()), nil
	}
	spec, found := resolveProviderSpec()
	if !found {
		return errorEnvelope("provider_unresolved", "no mirrored provider is configured"), nil
	}
	identity := identityFromExecutorRequest(req)
	upstream, errBuild := buildUpstreamRequest(req, spec, identity)
	if errBuild != nil {
		return errorEnvelope("executor_config_error", errBuild.Error()), nil
	}
	responseRaw, errCall := hostCall(pluginabi.MethodHostHTTPDo, upstream.marshal())
	if errCall != nil {
		return errorEnvelope("upstream_call_failed", errCall.Error()), nil
	}
	var response hostHTTPResponse
	if errDecode := json.Unmarshal(responseRaw, &response); errDecode != nil {
		return errorEnvelope("upstream_decode_failed", errDecode.Error()), nil
	}
	return okEnvelope(executorEnvelope{
		Payload: b64(unb64(response.Body)),
		Headers: response.Headers,
	}), nil
}
