package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

var executorAuthRecordState struct {
	sync.Mutex
	fingerprint string
	ensured     bool
}

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
	provider := normalizeExecutorProviderKey(settings.ExecutorProvider)
	if provider == "" {
		provider = defaultExecutorProvider
	}
	fingerprint := provider + "\x00" + spec.upstreamBaseURL() + "\x00" +
		spec.primaryAPIKey() + "\x00" + modelNamespace(settings.ModelNamespace, spec.Prefix)
	executorAuthRecordState.Lock()
	defer executorAuthRecordState.Unlock()
	if executorAuthRecordState.ensured && executorAuthRecordState.fingerprint == fingerprint {
		return nil
	}
	authJSON, errMarshal := executorAuthJSON(spec, settings)
	if errMarshal != nil {
		return errMarshal
	}
	saveRequest := map[string]any{
		"name": provider + ".json",
		"json": json.RawMessage(authJSON),
	}
	_, errCall := hostCall(pluginabi.MethodHostAuthSave, saveRequest)
	if errCall != nil {
		return fmt.Errorf("host.auth.save failed: %w", errCall)
	}
	executorAuthRecordState.fingerprint = fingerprint
	executorAuthRecordState.ensured = true
	recordDashboardEvent("success", "Plugin executor auth record is ready")
	return nil
}

func resetExecutorAuthRecordState() {
	executorAuthRecordState.Lock()
	executorAuthRecordState.fingerprint = ""
	executorAuthRecordState.ensured = false
	executorAuthRecordState.Unlock()
}

func executorAuthRecordEnsured() bool {
	executorAuthRecordState.Lock()
	defer executorAuthRecordState.Unlock()
	return executorAuthRecordState.ensured
}

func executorAuthJSON(spec providerSpec, settings PluginSettings) ([]byte, error) {
	provider := normalizeExecutorProviderKey(settings.ExecutorProvider)
	if provider == "" {
		provider = defaultExecutorProvider
	}
	authJSON, errMarshal := json.Marshal(map[string]any{
		"type":     provider,
		"base_url": spec.upstreamBaseURL(),
		"api_key":  spec.primaryAPIKey(),
		// CPA sets auth.Label from metadata.email. Without a real email the
		// token tracker joins provider + label and shows duplicated names such
		// as ln.Antigravity-ln.Antigravity. A stable pseudo-email keeps the
		// label distinct while never exposing a credential.
		"email":  "agy-identity-bridge@local",
		"prefix": modelNamespace(settings.ModelNamespace, spec.Prefix),
	})
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal auth record: %w", errMarshal)
	}
	return authJSON, nil
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
	StreamID        string
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
	req.StreamID, _ = stringValue(decoded, "stream_id")
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
	Principal         string
	ClientApp         string
	ClientInstance    string
	CapabilityProfile string
	ConnectorID       string
	SessionID         string
	Timestamp         string
	ProviderName      string
}

func identityFromExecutorRequest(req executorRequest) clientIdentity {
	settings := currentPluginSettings()
	var (
		headerPrincipal   string
		headerClientApp   string
		headerInstance    string
		headerProfile     string
		headerConnectorID string
		headerSessionID   string
	)
	if settings.AllowExplicitClientIdentityHeaders {
		headerPrincipal = firstHeaderValue(req.Headers, "X-AGY-Principal")
		headerClientApp = firstHeaderValue(req.Headers, "X-AGY-Client-App", "X-AGY-Device")
		headerInstance = firstHeaderValue(req.Headers, "X-AGY-Client-Instance")
		headerProfile = firstHeaderValue(req.Headers, "X-AGY-Capability-Profile")
		headerConnectorID = firstHeaderValue(req.Headers, "X-AGY-Connector-Id")
		headerSessionID = firstHeaderValue(req.Headers, "X-AGY-Session-ID", "X-Session-ID")
	}
	context := clientIdentityContext{
		Principal:         headerPrincipal,
		ClientApp:         headerClientApp,
		ClientInstance:    headerInstance,
		CapabilityProfile: headerProfile,
		ConnectorID:       headerConnectorID,
		SessionID:         headerSessionID,
		ProviderName:      firstHeaderValue(req.Headers, "X-AGY-CPA-Provider-Name", "X-AGY-Provider"),
		ExplicitIdentity:  headerPrincipal != "" || headerClientApp != "" || headerInstance != "" || headerProfile != "" || headerConnectorID != "",
	}
	if headerPrincipal != "" {
		context.Timestamp = firstHeaderValue(req.Headers, "X-AGY-Timestamp")
	}
	if context.ClientApp == "" {
		context.ClientApp = normalizeClientApp("", firstHeaderValue(req.Headers, "User-Agent"))
	}
	if context.Timestamp == "" {
		context.Timestamp = defaultTimestamp()
	}
	if context.Principal == "" {
		context.Principal, context.PrincipalSource = deriveStablePrincipal(currentPluginSettings(), context, "", req.Headers)
	}
	return clientIdentity{
		Principal:         context.Principal,
		ClientApp:         context.ClientApp,
		ClientInstance:    context.ClientInstance,
		CapabilityProfile: context.CapabilityProfile,
		ConnectorID:       context.ConnectorID,
		SessionID:         context.SessionID,
		Timestamp:         context.Timestamp,
		ProviderName:      context.ProviderName,
	}
}

func identityHeaders(identity clientIdentity, spec providerSpec, req executorRequest, method, path string) map[string][]string {
	headers := map[string][]string{}
	setIf := func(key, value string) {
		if strings.TrimSpace(value) != "" {
			headers[key] = []string{value}
		}
	}
	setIf("X-AGY-Principal", identity.Principal)
	setIf("X-AGY-Client-App", identity.ClientApp)
	setIf("X-AGY-Client-Instance", identity.ClientInstance)
	setIf("X-AGY-Capability-Profile", identity.CapabilityProfile)
	setIf("X-AGY-Connector-Id", identity.ConnectorID)
	setIf("X-AGY-Session-ID", identity.SessionID)
	setIf("X-AGY-Timestamp", identity.Timestamp)
	setIf("X-AGY-Plugin-Version", pluginVersion)
	setIf("X-AGY-CPA-Provider-Name", firstNonEmpty(identity.ProviderName, spec.Name))
	setIf("X-AGY-Upstream-Model", req.Model)
	setIf("X-AGY-Provider", spec.Name)
	if secret := hmacSecretForCandidate(currentPluginSettings(), providerCandidate{APIKey: spec.primaryAPIKey()}); secret != "" && identity.Principal != "" {
		headers["X-AGY-Signature"] = []string{computeHMAC(identitySignatureMessage(clientIdentityContext{
			Principal:         identity.Principal,
			ClientApp:         identity.ClientApp,
			ClientInstance:    identity.ClientInstance,
			CapabilityProfile: identity.CapabilityProfile,
			ConnectorID:       identity.ConnectorID,
			Timestamp:         identity.Timestamp,
		}, method, path), secret)}
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
	StatusCode int
	Headers    map[string][]string
	Body       string
}

type hostHTTPStreamStart struct {
	StatusCode int
	Headers    map[string][]string
	StreamID   string
}

// CPA's host callback structs evolved across releases: the stream bridge
// marshals snake_case JSON while the non-stream HTTPResponse is an untagged
// pluginapi struct that encodes PascalCase Go field names. Decode both so
// plugin upgrades stay compatible with whichever CPA build is deployed.
func (r *hostHTTPResponse) UnmarshalJSON(data []byte) error {
	keys, errDecode := decodeJSONKeys(data)
	if errDecode != nil {
		return errDecode
	}
	if code, ok := intFromKeys(keys, "status_code", "statusCode", "StatusCode", "status"); ok {
		r.StatusCode = code
	}
	if headers, ok := headersFromKeys(keys, "headers", "Headers"); ok {
		r.Headers = headers
	}
	if body, ok := stringFromKeys(keys, "body", "Body"); ok {
		r.Body = body
	}
	return nil
}

func (s *hostHTTPStreamStart) UnmarshalJSON(data []byte) error {
	keys, errDecode := decodeJSONKeys(data)
	if errDecode != nil {
		return errDecode
	}
	if code, ok := intFromKeys(keys, "status_code", "statusCode", "StatusCode", "status"); ok {
		s.StatusCode = code
	}
	if headers, ok := headersFromKeys(keys, "headers", "Headers"); ok {
		s.Headers = headers
	}
	if id, ok := stringFromKeys(keys, "stream_id", "StreamID"); ok {
		s.StreamID = id
	}
	return nil
}

func decodeJSONKeys(data []byte) (map[string]json.RawMessage, error) {
	var keys map[string]json.RawMessage
	if errUnmarshal := json.Unmarshal(data, &keys); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return keys, nil
}

func intFromKeys(keys map[string]json.RawMessage, names ...string) (int, bool) {
	for _, name := range names {
		raw, ok := keys[name]
		if !ok {
			continue
		}
		var value int
		if errUnmarshal := json.Unmarshal(raw, &value); errUnmarshal == nil {
			return value, true
		}
	}
	return 0, false
}

func stringFromKeys(keys map[string]json.RawMessage, names ...string) (string, bool) {
	for _, name := range names {
		raw, ok := keys[name]
		if !ok {
			continue
		}
		var value string
		if errUnmarshal := json.Unmarshal(raw, &value); errUnmarshal == nil {
			return value, true
		}
	}
	return "", false
}

func headersFromKeys(keys map[string]json.RawMessage, names ...string) (map[string][]string, bool) {
	for _, name := range names {
		raw, ok := keys[name]
		if !ok {
			continue
		}
		var value map[string][]string
		if errUnmarshal := json.Unmarshal(raw, &value); errUnmarshal == nil {
			return value, true
		}
	}
	return nil, false
}

type hostHTTPStreamRead struct {
	Payload string
	Error   string
	Done    bool
}

func (r *hostHTTPStreamRead) UnmarshalJSON(data []byte) error {
	keys, errDecode := decodeJSONKeys(data)
	if errDecode != nil {
		return errDecode
	}
	if payload, ok := stringFromKeys(keys, "payload", "Payload"); ok {
		r.Payload = payload
	}
	if errMsg, ok := stringFromKeys(keys, "error", "Error"); ok {
		r.Error = errMsg
	}
	if done, ok := boolFromKeys(keys, "done", "Done"); ok {
		r.Done = done
	}
	return nil
}

func boolFromKeys(keys map[string]json.RawMessage, names ...string) (bool, bool) {
	for _, name := range names {
		raw, ok := keys[name]
		if !ok {
			continue
		}
		var value bool
		if errUnmarshal := json.Unmarshal(raw, &value); errUnmarshal == nil {
			return value, true
		}
	}
	return false, false
}

// sseStreamParser reassembles complete SSE events from upstream reads that may
// split a frame anywhere. It exists so the bridge never loses an upstream
// frame: multi-line data fields are rejoined per the SSE spec, and both the
// "data: x" and "data:x" spellings are accepted, because a strict prefix test
// on one spelling silently discards the other.
type sseStreamParser struct {
	pending string
}

func (p *sseStreamParser) feed(chunk []byte) [][]byte {
	if len(chunk) > 0 {
		p.pending += strings.ReplaceAll(string(chunk), "\r\n", "\n")
	}
	return p.drain(false)
}

// flush processes whatever is left when the upstream stream ends, so a final
// event that arrived without its trailing blank line is still delivered.
func (p *sseStreamParser) flush() [][]byte {
	return p.drain(true)
}

func (p *sseStreamParser) drain(final bool) [][]byte {
	var out [][]byte
	for {
		end := strings.Index(p.pending, "\n\n")
		if end < 0 {
			break
		}
		block := p.pending[:end]
		p.pending = p.pending[end+2:]
		if payload, ok := sseEventPayload(block); ok {
			out = append(out, payload)
		}
	}
	if final {
		rest := p.pending
		p.pending = ""
		if payload, ok := sseEventPayload(rest); ok {
			out = append(out, payload)
		}
	}
	return out
}

// sseEventPayload returns the data carried by one SSE event block. ok is false
// for frames with no data field, such as a bare event: or a keep-alive
// comment; those carry nothing a chat client can render.
func sseEventPayload(block string) ([]byte, bool) {
	var data []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ":") {
			continue
		}
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		value := strings.TrimPrefix(trimmed, "data:")
		value = strings.TrimPrefix(value, " ")
		if strings.TrimSpace(value) == "" {
			continue
		}
		data = append(data, value)
	}
	if len(data) == 0 {
		return nil, false
	}
	joined := strings.Join(data, "\n")
	if strings.TrimSpace(joined) == "[DONE]" {
		return nil, false
	}
	return []byte(joined), true
}

// emitUpstreamEvents forwards completed upstream events through the host
// stream bridge in arrival order and reports how many were accepted. ok turns
// false as soon as the bridge rejects one, so the caller stops emitting
// instead of spinning against a closed stream.
func emitUpstreamEvents(streamID string, events [][]byte) (emitted int, ok bool) {
	for _, event := range events {
		emitPayload, errMarshal := json.Marshal(map[string]any{
			"stream_id": streamID,
			"payload":   event,
		})
		if errMarshal != nil {
			continue
		}
		if _, errEmit := hostCall(pluginabi.MethodHostStreamEmit, emitPayload); errEmit != nil {
			return emitted, false
		}
		emitted++
	}
	return emitted, true
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
	endpoint := upstreamEndpoint(req.Model, req.Format, req.Alt, requestPathFromMetadata(req.Metadata), spec)
	payload := rewritePayloadModel(req.Payload, settingsModelPrefix(currentPluginSettings(), spec))
	headers := map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", spec.primaryAPIKey())},
		"User-Agent":    {"agy-identity-bridge-executor"},
	}
	// The inbound content type has to survive the hop. CPA rewrites multipart
	// image edits into its own multipart body with a fresh boundary, so
	// hardcoding application/json labels multipart bytes as JSON and the
	// upstream rejects the body before any handler runs.
	if contentType := firstHeaderValue(req.Headers, "Content-Type"); contentType != "" {
		headers["Content-Type"] = []string{contentType}
	} else {
		headers["Content-Type"] = []string{"application/json"}
	}
	for key, values := range identityHeaders(identity, spec, req, "POST", endpoint) {
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

func settingsModelPrefix(settings PluginSettings, spec providerSpec) string {
	return modelNamespace(settings.ModelNamespace, spec.Prefix)
}

// The agy2api routes the bridge knows about, expressed relative to the
// mirrored provider's base URL. agy2api verifies the canonical payload with
// this same convention, so the value must stay base-relative and must not
// grow the /v1 prefix that already lives in base_url.
const (
	chatCompletionsEndpoint  = "/chat/completions"
	imageGenerationsEndpoint = "/images/generations"
	imageEditsEndpoint       = "/images/edits"
)

// knownUpstreamRoutes are the agy2api routes the bridge may target. The
// inbound path is matched against this set instead of being appended to the
// base URL verbatim, so a crafted request path cannot steer the upstream URL
// somewhere else.
var knownUpstreamRoutes = map[string]string{
	chatCompletionsEndpoint:  chatCompletionsEndpoint,
	"/responses":             "/responses",
	imageGenerationsEndpoint: imageGenerationsEndpoint,
	imageEditsEndpoint:       imageEditsEndpoint,
}

// requestPathFromMetadata reads the inbound HTTP path CPA attaches to every
// HTTP-originated execution. It is the only reliable way to tell an image edit
// from an image generation, because both arrive as image traffic and only the
// edit carries a multipart body.
func requestPathFromMetadata(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata["request_path"]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

// routeFromRequestPath maps an inbound path onto a known base-relative route,
// or returns "" when the path is absent or unrecognised.
func routeFromRequestPath(requestPath string) string {
	path := strings.ToLower(strings.TrimSpace(requestPath))
	if path == "" || !strings.HasPrefix(path, "/") {
		return ""
	}
	if trimmed, cut := strings.CutPrefix(path, "/v1"); cut {
		path = trimmed
	}
	if route, ok := knownUpstreamRoutes[path]; ok {
		return route
	}
	return ""
}

// upstreamEndpoint is the single source of truth for which agy2api route a
// request uses. The executor signs this value and the request interceptor must
// sign the identical one: agy2api verifies a canonical payload that includes
// the path, so a signature computed against a different endpoint fails
// verification outright rather than just producing a bad audit record.
//
// The inbound path wins whenever CPA supplied one. The format and capability
// heuristics remain the fallback for hosts that do not, and deliberately keep
// the historical behaviour of sending image traffic to generations, which is
// the only route that can be served from a JSON body.
func upstreamEndpoint(model, format, alt, requestPath string, spec providerSpec) string {
	if route := routeFromRequestPath(requestPath); route != "" {
		return route
	}
	if strings.Contains(strings.ToLower(format), "image") || strings.EqualFold(strings.TrimSpace(alt), "openai-image") {
		return imageGenerationsEndpoint
	}
	if spec.servesImageModel(model) {
		return imageGenerationsEndpoint
	}
	return chatCompletionsEndpoint
}

// servesImageModel reports whether the mirrored provider declares model with
// image capability. model may still carry the public prefix at intercept time.
func (s providerSpec) servesImageModel(model string) bool {
	bare := strings.ToLower(strings.TrimSpace(stripModelPrefix(model, s.Prefix)))
	if bare == "" {
		return false
	}
	for _, item := range s.Models {
		if !item.Image {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Name), bare) || strings.EqualFold(strings.TrimSpace(item.Alias), bare) {
			return true
		}
	}
	return false
}

func stripModelPrefix(modelID, prefix string) string {
	modelID = strings.TrimSpace(modelID)
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return modelID
	}
	if strings.HasPrefix(strings.ToLower(modelID), strings.ToLower(prefix)+"/") {
		return modelID[len(prefix)+1:]
	}
	return modelID
}

func normalizeExecutorModel(req *executorRequest, spec providerSpec) {
	if req == nil {
		return
	}
	req.Model = stripModelPrefix(req.Model, settingsModelPrefix(currentPluginSettings(), spec))
	req.Payload = rewritePayloadModel(req.Payload, settingsModelPrefix(currentPluginSettings(), spec))
}

func rewritePayloadModel(payload []byte, prefix string) []byte {
	if len(payload) == 0 || strings.TrimSpace(prefix) == "" {
		return payload
	}
	var body map[string]any
	if errUnmarshal := json.Unmarshal(payload, &body); errUnmarshal != nil {
		return payload
	}
	model, ok := body["model"].(string)
	if !ok {
		return payload
	}
	rewritten := stripModelPrefix(model, prefix)
	if rewritten == model {
		return payload
	}
	body["model"] = rewritten
	out, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		return payload
	}
	return out
}

func forceStreamingPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	var body map[string]any
	if errUnmarshal := json.Unmarshal(payload, &body); errUnmarshal != nil {
		return payload
	}
	if current, ok := body["stream"].(bool); ok && current {
		return payload
	}
	body["stream"] = true
	out, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		return payload
	}
	return out
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
	visibleModel := req.Model
	spec, found := resolveProviderSpec()
	if !found {
		return errorEnvelope("provider_unresolved", "no mirrored provider is configured"), nil
	}
	normalizeExecutorModel(&req, spec)
	visibleModel = req.Model
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
	recordExecutorUpstreamStatus(response.StatusCode)
	recordUsageFromExecutorResponse(unb64(response.Body), response.Headers, spec.Name, visibleModel, identity.ClientApp, identity.Principal, "execute")
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
	visibleModel := req.Model
	spec, found := resolveProviderSpec()
	if !found {
		return errorEnvelope("provider_unresolved", "no mirrored provider is configured"), nil
	}
	normalizeExecutorModel(&req, spec)
	visibleModel = req.Model
	// CPA may select execute_stream for a request whose original payload did
	// not carry stream=true. The host stream callback requires an actual
	// upstream stream, so make the agy2api request streaming as well.
	req.Payload = forceStreamingPayload(req.Payload)
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

	var streamUsageBuffer []byte
	defer hostCall(pluginabi.MethodHostHTTPStreamClose, []byte(fmt.Sprintf(`{"stream_id":%q}`, start.StreamID)))
	// Progressive streaming: when CPA opened a host stream bridge for this
	// call, each upstream chunk is forwarded through host.stream.emit right
	// away instead of batching until the upstream response ends. Clients then
	// see the first token as soon as agy2api produces it, which matters for
	// long thinking requests where a full batch would otherwise look stalled.
	emitStreamID := req.StreamID
	usedEmit := false
	sse := &sseStreamParser{}
	closeHostStreamEmit := func(errorMessage string) {
		if emitStreamID == "" {
			return
		}
		payload, errMarshal := json.Marshal(map[string]string{
			"stream_id": emitStreamID,
			"error":     errorMessage,
		})
		if errMarshal == nil {
			_, _ = hostCall(pluginabi.MethodHostStreamClose, payload)
		}
	}
	if emitStreamID == "" {
		// Older CPA builds do not pass a bridge stream id; fall back to the
		// previous batched response shape.
		usedEmit = false
	}
	for {
		readRaw, errRead := hostCall(pluginabi.MethodHostHTTPStreamRead, []byte(fmt.Sprintf(`{"stream_id":%q}`, start.StreamID)))
		if errRead != nil {
			if emitStreamID != "" {
				closeHostStreamEmit(errRead.Error())
			}
			return errorEnvelope("upstream_stream_failed", errRead.Error()), nil
		}
		var read hostHTTPStreamRead
		if errDecode := json.Unmarshal(readRaw, &read); errDecode != nil {
			if emitStreamID != "" {
				closeHostStreamEmit(errDecode.Error())
			}
			return errorEnvelope("upstream_stream_decode_failed", errDecode.Error()), nil
		}
		if read.Error != "" {
			if emitStreamID != "" {
				closeHostStreamEmit(read.Error)
			}
			return errorEnvelope("upstream_stream_error", read.Error), nil
		}
		if payload := unb64(read.Payload); len(payload) > 0 {
			streamUsageBuffer = append(streamUsageBuffer, payload...)
			streamUsageBuffer = append(streamUsageBuffer, '\n')
			if emitStreamID != "" {
				// CPA's stream bridge wraps each emitted chunk in its own SSE
				// data frame, so the plugin strips the upstream framing and
				// emits one payload per completed event, in arrival order.
				// [DONE] is skipped because CPA writes its own done tail.
				emitted, accepted := emitUpstreamEvents(emitStreamID, sse.feed(payload))
				usedEmit = usedEmit || emitted > 0
				if !accepted {
					closeHostStreamEmit("")
					emitStreamID = ""
				}
			}
		}
		if read.Done {
			break
		}
	}
	if emitStreamID != "" {
		emitted, accepted := emitUpstreamEvents(emitStreamID, sse.flush())
		usedEmit = usedEmit || emitted > 0
		if !accepted {
			closeHostStreamEmit("")
		}
	}
	recordUsageFromExecutorResponse(streamUsageBuffer, start.Headers, spec.Name, visibleModel, identity.ClientApp, identity.Principal, "stream")
	if usedEmit {
		// Success path: the bridge stream stays open until the plugin closes
		// it, otherwise CPA keeps streaming keep-alive comments and clients
		// wait for their own timeout instead of finishing cleanly.
		closeHostStreamEmit("")
		return okEnvelope(executorEnvelope{
			Headers: start.Headers,
		}), nil
	}
	return okEnvelope(executorEnvelope{
		Headers: start.Headers,
		Chunks:  []streamChunk{{Payload: b64(streamUsageBuffer)}},
	}), nil
}

func handleExecutorCountTokens(raw []byte) ([]byte, error) {
	req, errParse := parseExecutorRequest(raw)
	if errParse != nil {
		return errorEnvelope("parse_error", errParse.Error()), nil
	}
	visibleModel := req.Model
	spec, found := resolveProviderSpec()
	if !found {
		return errorEnvelope("provider_unresolved", "no mirrored provider is configured"), nil
	}
	normalizeExecutorModel(&req, spec)
	visibleModel = req.Model
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
	recordExecutorUpstreamStatus(response.StatusCode)
	recordUsageFromExecutorResponse(unb64(response.Body), response.Headers, spec.Name, visibleModel, identity.ClientApp, identity.Principal, "count_tokens")
	return okEnvelope(executorEnvelope{
		Payload: b64(unb64(response.Body)),
		Headers: response.Headers,
	}), nil
}
