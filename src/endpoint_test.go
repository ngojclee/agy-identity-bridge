package main

import (
	"strings"
	"testing"
)

func TestUpstreamEndpointMatchesImageCapability(t *testing.T) {
	loadMirror(t)
	root, errParse := parseYAMLMap([]byte(mirrorConfigYAML))
	if errParse != nil {
		t.Fatal(errParse)
	}
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("fixture provider was not mirrored")
	}

	cases := []struct {
		name   string
		model  string
		format string
		alt    string
		want   string
	}{
		{"chat model", "gemini-3.1-pro", "chat-completions", "", chatCompletionsEndpoint},
		{"image model by capability", "gemini-image", "", "", imageGenerationsEndpoint},
		{"prefixed image model", "agy/gemini-image", "", "", imageGenerationsEndpoint},
		{"image format wins", "gemini-3.1-pro", "openai-image", "", imageGenerationsEndpoint},
		{"image alt wins", "gemini-3.1-pro", "", "openai-image", imageGenerationsEndpoint},
		{"unknown model defaults to chat", "not-registered", "", "", chatCompletionsEndpoint},
	}
	for _, tc := range cases {
		if got := upstreamEndpoint(tc.model, tc.format, tc.alt, spec); got != tc.want {
			t.Errorf("%s: upstreamEndpoint(%q,%q,%q) = %q, want %q", tc.name, tc.model, tc.format, tc.alt, got, tc.want)
		}
	}
}

func TestIdentitySignatureCoversRealImageRoute(t *testing.T) {
	loadMirror(t)
	root, errParse := parseYAMLMap([]byte(mirrorConfigYAML))
	if errParse != nil {
		t.Fatal(errParse)
	}
	spec, _ := extractProviderSpec(root, currentPluginSettings())

	identity := clientIdentityContext{
		Principal:      "abc123",
		Timestamp:      "1788428832",
		ClientApp:      "hermes",
		ClientInstance: "inst-1",
	}
	message := identitySignatureMessage(identity, "POST", upstreamEndpoint("gemini-image", "", "", spec))

	if !strings.Contains(message, "path=/images/generations") {
		t.Fatalf("signature payload must carry the real image route, got %q", message)
	}
	if strings.Contains(message, "/chat/completions") {
		t.Fatalf("image request must not sign the chat endpoint: %q", message)
	}
	// agy2api locks this exact shape: eight newline-joined key=value fields in
	// this order, and the path must stay base-relative without the /v1 prefix.
	fields := strings.Split(message, "\n")
	if len(fields) != 8 {
		t.Fatalf("canonical payload field count = %d, want 8: %q", len(fields), message)
	}
	wantOrder := []string{"principal=", "timestamp=", "client_app=", "client_instance=", "capability_profile=", "connector_id=", "method=", "path="}
	for index, prefix := range wantOrder {
		if !strings.HasPrefix(fields[index], prefix) {
			t.Fatalf("field %d = %q, want prefix %q", index, fields[index], prefix)
		}
	}
	if strings.Contains(message, "path=/v1/") {
		t.Fatalf("path must stay relative to base_url which already carries /v1: %q", message)
	}
}
