package main

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestDerivePrincipal(t *testing.T) {
	token := "agy_abc123"
	hash1 := derivePrincipal(token)
	hash2 := derivePrincipal(token)

	if hash1 != hash2 {
		t.Errorf("derivePrincipal not deterministic")
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(hash1))
	}
	if hash1 == derivePrincipal("different_token") {
		t.Errorf("different tokens should produce different hashes")
	}
}

func TestExtractBearerToken(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer agy_test_token_123"},
	}
	token := extractBearerToken(headers)
	if token != "agy_test_token_123" {
		t.Errorf("expected agy_test_token_123, got %q", token)
	}

	// No authorization header.
	empty := map[string][]string{}
	if extractBearerToken(empty) != "" {
		t.Errorf("expected empty for no auth header")
	}
}

func TestExtractClientApp(t *testing.T) {
	codexHeaders := map[string][]string{
		"User-Agent": {"codex-tui/0.128.0"},
	}
	if got := extractClientApp(codexHeaders); got != "codex" {
		t.Errorf("expected codex, got %q", got)
	}

	hermesHeaders := map[string][]string{
		"User-Agent": {"Hermes/1.0"},
	}
	if got := extractClientApp(hermesHeaders); got != "hermes" {
		t.Errorf("expected hermes, got %q", got)
	}

	customHeaders := map[string][]string{
		"X-AGY-Client-App": {"my-custom-app"},
	}
	if got := extractClientApp(customHeaders); got != "my-custom-app" {
		t.Errorf("expected my-custom-app, got %q", got)
	}
}

func TestComputeHMAC(t *testing.T) {
	sig1 := computeHMAC("principal1", "secret1")
	sig2 := computeHMAC("principal1", "secret1")
	sig3 := computeHMAC("principal1", "secret2")

	if sig1 != sig2 {
		t.Errorf("same input should produce same HMAC")
	}
	if sig1 == sig3 {
		t.Errorf("different secret should produce different HMAC")
	}
	if len(sig1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(sig1))
	}
}

func TestDeriveStablePrincipalUsesExplicitClientIdentity(t *testing.T) {
	settings := PluginSettings{AllowExplicitClientIdentityHeaders: true}
	payload := InterceptRequestPayload{
		Headers: map[string][]string{
			"X-AGY-Client-App":         {"codex"},
			"X-AGY-Client-Instance":    {"instance-1"},
			"X-AGY-Capability-Profile": {"pro"},
			"X-AGY-Connector-Id":       {"connector-1"},
			"User-Agent":               {"Codex/1.0"},
		},
	}
	first := deriveClientIdentityFromIntercept(payload, settings)
	second := deriveClientIdentityFromIntercept(payload, settings)
	if first.Principal == "" || first.Principal != second.Principal {
		t.Fatalf("principal not stable: %+v %+v", first, second)
	}
	payload.Headers["X-AGY-Client-Instance"] = []string{"instance-2"}
	third := deriveClientIdentityFromIntercept(payload, settings)
	if third.Principal == first.Principal {
		t.Fatalf("principal did not change when client instance changed: %+v %+v", first, third)
	}
	if first.PrincipalSource != "explicit" {
		t.Fatalf("principal source = %q, want explicit", first.PrincipalSource)
	}
}

func TestPluginRegistration(t *testing.T) {
	reg := pluginRegistration()
	if !reg.Capabilities.RequestInterceptor {
		t.Errorf("RequestInterceptor capability should be true")
	}
	if reg.Metadata.Name != "agy-identity-bridge" {
		t.Errorf("plugin name = %q, want agy-identity-bridge", reg.Metadata.Name)
	}
}

func TestPluginEnvelopesUseCPAABIShape(t *testing.T) {
	var success pluginabi.Envelope
	if err := json.Unmarshal(okEnvelope(map[string]string{"status": "ok"}), &success); err != nil {
		t.Fatal(err)
	}
	if !success.OK || len(success.Result) == 0 || success.Error != nil {
		t.Fatalf("success envelope = %+v", success)
	}

	var failure pluginabi.Envelope
	if err := json.Unmarshal(errorEnvelope("bad_request", "invalid payload"), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.OK || failure.Error == nil || failure.Error.Code != "bad_request" {
		t.Fatalf("failure envelope = %+v", failure)
	}
}
