package main

import (
	"net/url"
	"strings"
	"testing"
)

// agy2api verifies the canonical payload against request.url.path, so the
// signed path has to be the path that actually goes on the wire. base_url
// carries the /v1 prefix, and the routed endpoints are deliberately stored
// without it so the known-routes allowlist stays strict.
const signedPathConfigYAML = `
plugins:
  configs:
    agy-identity-bridge:
      enabled: true
      auto_discover: true
      include_native_antigravity: false
      executor_enabled: true
      hmac_secret_source: config
      hmac_secret: test-shared-secret
openai-compatibility:
  - name: Antigravity
    prefix: agy
    base-url: http://10.21.4.101:8123/v1
    api-key-entries:
      - api-key: provider-secret
    models:
      - name: gemini-3.8-flash-high
      - name: gemini-image
        image: true
`

func loadSignedPathFixture(t *testing.T) providerSpec {
	t.Helper()
	applyPluginConfiguration(loadPluginConfiguration([]byte(signedPathConfigYAML)))
	storeProviderSpec(providerSpec{}, false)
	root, errParse := parseYAMLMap([]byte(signedPathConfigYAML))
	if errParse != nil {
		t.Fatal(errParse)
	}
	spec, found := extractProviderSpec(root, currentPluginSettings())
	if !found {
		t.Fatal("fixture provider was not mirrored")
	}
	return spec
}

func TestSignatureCoversTheWirePathOnEveryRoute(t *testing.T) {
	spec := loadSignedPathFixture(t)
	secret := currentPluginSettings().hmacSecret()
	if secret == "" {
		t.Fatal("fixture did not provide an hmac secret")
	}

	identity := clientIdentity{
		Principal:      strings.Repeat("c", 64),
		ClientApp:      "hermes",
		Timestamp:      "1788516317",
		ClientInstance: "install-abc",
	}

	cases := []struct {
		name        string
		model       string
		format      string
		requestPath string
		wantPath    string
	}{
		{"chat", "gemini-3.8-flash-high", "chat-completions", "/v1/chat/completions", "/v1/chat/completions"},
		{"translated responses traffic", "gemini-3.8-flash-high", "chat-completions", "/v1/responses", "/v1/chat/completions"},
		{"image generations", "gemini-image", "openai-image", "/v1/images/generations", "/v1/images/generations"},
		{"image edits", "gemini-image", "openai-image", "/v1/images/edits", "/v1/images/edits"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built, errBuild := buildUpstreamRequest(executorRequest{
				Model:    tc.model,
				Format:   tc.format,
				Metadata: map[string]any{"request_path": tc.requestPath},
			}, spec, identity)
			if errBuild != nil {
				t.Fatal(errBuild)
			}

			parsed, errParse := url.Parse(built.URL)
			if errParse != nil {
				t.Fatal(errParse)
			}
			if parsed.Path != tc.wantPath {
				t.Fatalf("wire path = %q, want %q", parsed.Path, tc.wantPath)
			}

			ctx := clientIdentityContext{
				Principal:      identity.Principal,
				Timestamp:      identity.Timestamp,
				ClientApp:      identity.ClientApp,
				ClientInstance: identity.ClientInstance,
			}
			got := firstHeaderValue(built.Headers, "X-AGY-Signature")
			if got == "" {
				t.Fatal("no signature emitted")
			}
			if want := computeHMAC(identitySignatureMessage(ctx, "POST", parsed.Path), secret); got != want {
				t.Fatalf("signature was not computed over the wire path %q", parsed.Path)
			}

			// The previous defect: signing the allowlisted endpoint instead of
			// the wire path. Assert it is now distinguishable.
			stripped := strings.TrimPrefix(parsed.Path, "/v1")
			if legacy := computeHMAC(identitySignatureMessage(ctx, "POST", stripped), secret); legacy == got {
				t.Fatalf("signature still matches the stripped endpoint %q", stripped)
			}
		})
	}
}

func TestKnownRoutesAllowlistStillRejectsUnknownPaths(t *testing.T) {
	spec := loadSignedPathFixture(t)
	// A path outside the allowlist must not become the signed route.
	if got := signedUpstreamPath("gemini-3.8-flash-high", "chat-completions", "", "/v1/../admin", spec); got != "/v1/chat/completions" {
		t.Fatalf("crafted path leaked into the signed route: %q", got)
	}
	if got := signedUpstreamPath("gemini-3.8-flash-high", "chat-completions", "", "", spec); got != "/v1/chat/completions" {
		t.Fatalf("default chat route = %q", got)
	}
}
