package main

import (
	"strings"
	"testing"
)

// The Hermes deployment shares one X-AGY-Client-Instance (its per-install id at
// %LOCALAPPDATA%\hermes\install_id) across every persona and relies on a
// distinct X-AGY-Capability-Profile to separate them. That only works because
// the principal seed carries both fields, so this pair is load-bearing.

func hermesPayload(instance, profile string) InterceptRequestPayload {
	headers := map[string][]string{
		"X-AGY-Client-App":      {"hermes"},
		"X-AGY-Client-Instance": {instance},
		"User-Agent":            {"openai/python/2.24.0"},
	}
	if profile != "" {
		headers["X-AGY-Capability-Profile"] = []string{profile}
	}
	return InterceptRequestPayload{Headers: headers}
}

func TestSharedInstanceSeparatesProfilesWithoutConnectorID(t *testing.T) {
	settings := PluginSettings{AllowExplicitClientIdentityHeaders: true}
	const installID = "3f2a9c1e7b6d4a5f8e0c1d2b3a4f5e6d"

	profiles := []string{"nyx", "hannah", "tutor", "root"}
	seen := map[string]string{}
	for _, profile := range profiles {
		identity := deriveClientIdentityFromIntercept(hermesPayload(installID, profile), settings)
		if identity.Principal == "" {
			t.Fatalf("profile %q produced no principal", profile)
		}
		// Hermes never sends connector_id, so explicit mode must engage on
		// app + instance + profile alone.
		if identity.PrincipalSource != "explicit" {
			t.Fatalf("profile %q source = %q, want explicit", profile, identity.PrincipalSource)
		}
		if previous, clash := seen[identity.Principal]; clash {
			t.Fatalf("profiles %q and %q collapsed onto one principal %s", previous, profile, redactedIdentityLabel(identity.Principal))
		}
		seen[identity.Principal] = profile
	}
	if len(seen) != len(profiles) {
		t.Fatalf("distinct principals = %d, want %d", len(seen), len(profiles))
	}

	// Stability: the same instance and profile must keep producing the same
	// principal across requests, which is what a connector binding relies on.
	first := deriveClientIdentityFromIntercept(hermesPayload(installID, "nyx"), settings)
	again := deriveClientIdentityFromIntercept(hermesPayload(installID, "nyx"), settings)
	if first.Principal != again.Principal {
		t.Fatalf("principal unstable for one profile: %s vs %s", redactedIdentityLabel(first.Principal), redactedIdentityLabel(again.Principal))
	}

	// A missing profile is its own distinct identity, and must not collide with
	// any persona above.
	blank := deriveClientIdentityFromIntercept(hermesPayload(installID, ""), settings)
	if _, clash := seen[blank.Principal]; clash {
		t.Fatal("profile-less request collided with a named profile principal")
	}
}

func TestSignaturePayloadDiffersOnlyInProfileLine(t *testing.T) {
	const installID = "3f2a9c1e7b6d4a5f8e0c1d2b3a4f5e6d"
	base := clientIdentityContext{
		Principal:      strings.Repeat("a", 64),
		Timestamp:      "1788472062",
		ClientApp:      "hermes",
		ClientInstance: installID,
	}

	one := base
	one.CapabilityProfile = "nyx"
	two := base
	two.CapabilityProfile = "hannah"

	left := strings.Split(identitySignatureMessage(one, "POST", chatCompletionsEndpoint), "\n")
	right := strings.Split(identitySignatureMessage(two, "POST", chatCompletionsEndpoint), "\n")
	if len(left) != len(right) {
		t.Fatalf("payload field count differs: %d vs %d", len(left), len(right))
	}

	differences := 0
	for index := range left {
		if left[index] != right[index] {
			differences++
			if !strings.HasPrefix(left[index], "capability_profile=") || !strings.HasPrefix(right[index], "capability_profile=") {
				t.Fatalf("line %d differs outside the profile field: %q vs %q", index, left[index], right[index])
			}
		}
	}
	if differences != 1 {
		t.Fatalf("expected exactly one differing line, got %d", differences)
	}
	if !strings.Contains(strings.Join(right, "\n"), "client_instance="+installID) {
		t.Fatal("shared install id must appear verbatim in the signed payload")
	}
}
