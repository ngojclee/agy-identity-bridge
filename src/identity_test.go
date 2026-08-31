package main

import (
	"testing"
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

func TestPluginRegistration(t *testing.T) {
	reg := pluginRegistration()
	if !reg.Capabilities.RequestInterceptor {
		t.Errorf("RequestInterceptor capability should be true")
	}
	if reg.Metadata.Name != "agy-identity-bridge" {
		t.Errorf("plugin name = %q, want agy-identity-bridge", reg.Metadata.Name)
	}
}
