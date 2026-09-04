package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRouteFromRequestPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/v1/images/edits", imageEditsEndpoint},
		{"/v1/images/generations", imageGenerationsEndpoint},
		{"/v1/chat/completions", chatCompletionsEndpoint},
		{"/images/edits", imageEditsEndpoint},
		{"/v1/../admin/secrets", ""},
		{"/v1/images/edits/../../x", ""},
		{"", ""},
		{"images/edits", ""},
		{"/v1/not-a-route", ""},
	}
	for _, tc := range cases {
		if got := routeFromRequestPath(tc.in); got != tc.want {
			t.Errorf("routeFromRequestPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUpstreamEndpointPrefersRealInboundPathOverHeuristic(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, _ := extractProviderSpec(root, currentPluginSettings())

	// An edit is image traffic, so every heuristic in the file points at
	// generations. Only the inbound path can route it correctly.
	if got := upstreamEndpoint("gemini-image", "openai-image", "", "/v1/images/edits", spec); got != imageEditsEndpoint {
		t.Fatalf("edits routed to %q, want %q", got, imageEditsEndpoint)
	}
	// Without a path the historical generations default must survive.
	if got := upstreamEndpoint("gemini-image", "openai-image", "", "", spec); got != imageGenerationsEndpoint {
		t.Fatalf("pathless image traffic routed to %q, want %q", got, imageGenerationsEndpoint)
	}
}

func TestBuildUpstreamRequestPreservesMultipartContentTypeAndBody(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, _ := extractProviderSpec(root, currentPluginSettings())

	boundary := "cpa-boundary-7f3a"
	body := []byte("--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"model\"\r\n\r\ngemini-image\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"prompt\"\r\n\r\npose1 canonical layout\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"image\"; filename=\"a.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x89, 0x50, 0x4e, 0x47}, 4096)) + "\r\n" +
		"--" + boundary + "--\r\n")

	req := executorRequest{
		Model:  "gemini-image",
		Format: "openai-image",
		Headers: map[string][]string{
			"Content-Type": {"multipart/form-data; boundary=" + boundary},
		},
		Payload:  body,
		Metadata: map[string]any{"request_path": "/v1/images/edits"},
	}
	built, errBuild := buildUpstreamRequest(req, spec, clientIdentity{Principal: strings.Repeat("a", 64), ClientApp: "hermes"})
	if errBuild != nil {
		t.Fatal(errBuild)
	}

	if !strings.HasSuffix(built.URL, imageEditsEndpoint) {
		t.Fatalf("upstream URL = %q, want it to end at %q", built.URL, imageEditsEndpoint)
	}
	if got := built.Headers["Content-Type"][0]; got != "multipart/form-data; boundary="+boundary {
		t.Fatalf("content type rewritten to %q; multipart boundary must survive intact", got)
	}
	if roundTrip := unb64(built.Body); !bytes.Equal(roundTrip, body) {
		t.Fatalf("multipart body altered in transit: sent %d bytes, upstream %d bytes", len(body), len(roundTrip))
	}
}

// NailArt posts real product photos, so the body is hundreds of kilobytes of
// base64. The bridge must not truncate, re-encode, or re-marshal it.
func TestBuildUpstreamRequestForwardsLargeBase64BodyByteIdentical(t *testing.T) {
	loadMirror(t)
	root, _ := parseYAMLMap([]byte(mirrorConfigYAML))
	spec, _ := extractProviderSpec(root, currentPluginSettings())

	raw := make([]byte, 600*1024)
	if _, errRead := rand.Read(raw); errRead != nil {
		t.Fatal(errRead)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	body, errMarshal := json.Marshal(map[string]any{
		"model":           "gemini-image",
		"prompt":          "a red square",
		"size":            "1024x1024",
		"response_format": "b64_json",
		"image":           encoded,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}

	req := executorRequest{
		Model:   "gemini-image",
		Format:  "openai-image",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Payload: body,
		Metadata: map[string]any{
			"request_path": "/v1/images/generations",
		},
	}
	built, errBuild := buildUpstreamRequest(req, spec, clientIdentity{Principal: strings.Repeat("b", 64), ClientApp: "hermes"})
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	if !strings.HasSuffix(built.URL, imageGenerationsEndpoint) {
		t.Fatalf("upstream URL = %q, want %q", built.URL, imageGenerationsEndpoint)
	}
	roundTrip := unb64(built.Body)
	if !bytes.Equal(roundTrip, body) {
		t.Fatalf("large JSON body corrupted: sent %d bytes, upstream %d bytes", len(body), len(roundTrip))
	}

	// The body must still be valid JSON after the hop, and the image field must
	// be the exact same base64 the client sent.
	var decoded map[string]any
	if errUnmarshal := json.Unmarshal(roundTrip, &decoded); errUnmarshal != nil {
		t.Fatalf("upstream body is not parseable JSON: %v", errUnmarshal)
	}
	if decoded["image"] != encoded {
		t.Fatal("base64 image field changed in transit")
	}
	if len(roundTrip) < 800*1024 {
		t.Fatalf("body looks truncated at %d bytes", len(roundTrip))
	}
}
