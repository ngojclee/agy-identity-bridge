package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

type clientIdentityContext struct {
	Principal         string
	ClientApp         string
	ClientInstance    string
	CapabilityProfile string
	ConnectorID       string
	SessionID         string
	ProviderName      string
	Timestamp         string
	ClientKeyHash     string
	PrincipalSource   string
	ExplicitIdentity  bool
}

func deriveClientIdentityFromIntercept(payload InterceptRequestPayload, settings PluginSettings) clientIdentityContext {
	headers := payload.Headers
	if headers == nil {
		headers = map[string][]string{}
	}
	metadata := payload.Metadata
	context := clientIdentityContext{
		ClientApp:         firstHeaderValue(headers, "X-AGY-Client-App"),
		ClientInstance:    firstHeaderValue(headers, "X-AGY-Client-Instance"),
		CapabilityProfile: firstHeaderValue(headers, "X-AGY-Capability-Profile"),
		ConnectorID:       firstHeaderValue(headers, "X-AGY-Connector-Id"),
		SessionID:         firstHeaderValue(headers, "X-AGY-Session-ID", "X-Session-ID"),
	}
	if settings.AllowExplicitClientIdentityHeaders {
		context.ClientApp = firstNonEmpty(context.ClientApp, metadataString(metadata, "client_app", "client-app"))
		context.ClientInstance = firstNonEmpty(
			context.ClientInstance,
			metadataString(metadata, "client_instance", "client-instance", "device_id", "device-id"),
		)
		context.CapabilityProfile = firstNonEmpty(
			context.CapabilityProfile,
			metadataString(metadata, "capability_profile", "capability-profile", "profile"),
		)
		context.ConnectorID = firstNonEmpty(
			context.ConnectorID,
			metadataString(metadata, "connector_id", "connector-id"),
		)
		context.ExplicitIdentity = strings.TrimSpace(context.ClientApp) != "" ||
			strings.TrimSpace(context.ClientInstance) != "" ||
			strings.TrimSpace(context.CapabilityProfile) != "" ||
			strings.TrimSpace(context.ConnectorID) != ""
	}
	context.ClientApp = normalizeClientApp(context.ClientApp, firstHeaderValue(headers, "User-Agent"))
	clientToken := extractBearerToken(headers)
	context.ClientKeyHash = hashString(clientToken)
	context.Principal, context.PrincipalSource = deriveStablePrincipal(settings, context, clientToken, headers)
	context.Timestamp = strconv.FormatInt(time.Now().UTC().Unix(), 10)
	return context
}

func deriveClientIdentityFromExecutor(req executorRequest) clientIdentityContext {
	headers := req.Headers
	if headers == nil {
		headers = map[string][]string{}
	}
	context := clientIdentityContext{
		Principal:         firstHeaderValue(headers, "X-AGY-Principal"),
		ClientApp:         firstHeaderValue(headers, "X-AGY-Client-App"),
		ClientInstance:    firstHeaderValue(headers, "X-AGY-Client-Instance"),
		CapabilityProfile: firstHeaderValue(headers, "X-AGY-Capability-Profile"),
		ConnectorID:       firstHeaderValue(headers, "X-AGY-Connector-Id"),
		SessionID:         firstHeaderValue(headers, "X-AGY-Session-ID", "X-Session-ID"),
		ProviderName:      firstHeaderValue(headers, "X-AGY-CPA-Provider-Name", "X-AGY-Provider"),
		Timestamp:         firstHeaderValue(headers, "X-AGY-Timestamp"),
		ExplicitIdentity:  true,
	}
	if context.Timestamp == "" {
		context.Timestamp = strconv.FormatInt(time.Now().UTC().Unix(), 10)
	}
	if context.ClientApp == "" {
		context.ClientApp = normalizeClientApp("", firstHeaderValue(headers, "User-Agent"))
	}
	if context.Principal == "" {
		clientToken := extractBearerToken(headers)
		context.ClientKeyHash = hashString(clientToken)
		context.Principal, context.PrincipalSource = deriveStablePrincipal(currentPluginSettings(), context, clientToken, headers)
	}
	return context
}

func deriveStablePrincipal(settings PluginSettings, context clientIdentityContext, clientToken string, headers map[string][]string) (string, string) {
	settings = normalizeSettings(settings)
	clientApp := normalizeClientApp(context.ClientApp, firstHeaderValue(headers, "User-Agent"))
	namespace := identityNamespace(context)

	if settings.AllowExplicitClientIdentityHeaders && context.ExplicitIdentity {
		seed := strings.Join(compactNonEmpty([]string{
			"namespace=" + namespace,
			"app=" + clientApp,
			"instance=" + context.ClientInstance,
			"profile=" + context.CapabilityProfile,
			"connector=" + context.ConnectorID,
		}), "\x00")
		if seed != "" {
			return hashString("agy-identity-bridge\x00explicit\x00" + seed), "explicit"
		}
	}

	switch settings.PrincipalFallbackMode {
	case "disabled":
		return "", "disabled"
	case "user_agent_plus_session":
		seed := strings.Join(compactNonEmpty([]string{
			"namespace=" + namespace,
			"app=" + clientApp,
			"session=" + context.SessionID,
		}), "\x00")
		if seed == "" {
			return "", "disabled"
		}
		return hashString("agy-identity-bridge\x00ua-session\x00" + seed), "user_agent_plus_session"
	default:
		tokenHash := hashString(clientToken)
		instanceOrKey := firstNonEmpty(context.ClientInstance, tokenHash, context.SessionID)
		if instanceOrKey != "" {
			seed := strings.Join(compactNonEmpty([]string{
				"namespace=" + namespace,
				"app=" + clientApp,
				"id=" + instanceOrKey,
			}), "\x00")
			if seed != "" {
				return hashString("agy-identity-bridge\x00client-key\x00" + seed), "client_key_hash"
			}
		}
		if clientApp != "" {
			return hashString("agy-identity-bridge\x00client-key\x00namespace=" + namespace + "\x00app=" + clientApp), "client_key_hash"
		}
		return "", "disabled"
	}
}

func identityNamespace(context clientIdentityContext) string {
	namespace := normalizeProviderKey(firstNonEmpty(context.ProviderName, defaultExecutorProvider))
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		return "agy-identity-bridge"
	}
	return namespace
}

func normalizeClientApp(clientApp, userAgent string) string {
	clientApp = strings.ToLower(strings.TrimSpace(clientApp))
	if clientApp != "" {
		return clientApp
	}
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case strings.Contains(ua, "codex"):
		return "codex"
	case strings.Contains(ua, "hermes"):
		return "hermes"
	case strings.Contains(ua, "cursor"):
		return "cursor"
	case strings.Contains(ua, "openai/python"):
		// This identifies the transport SDK, not the originating product.
		// Do not label it as Hermes or another app without an explicit
		// X-AGY-Client-App header.
		return "openai-python"
	case ua != "":
		return "unknown"
	default:
		return "unknown"
	}
}

func identitySignatureMessage(identity clientIdentityContext, method, path string) string {
	return strings.Join([]string{
		"principal=" + strings.TrimSpace(identity.Principal),
		"timestamp=" + strings.TrimSpace(identity.Timestamp),
		"client_app=" + strings.TrimSpace(identity.ClientApp),
		"client_instance=" + strings.TrimSpace(identity.ClientInstance),
		"capability_profile=" + strings.TrimSpace(identity.CapabilityProfile),
		"connector_id=" + strings.TrimSpace(identity.ConnectorID),
		"method=" + strings.TrimSpace(method),
		"path=" + strings.TrimSpace(path),
	}, "\n")
}

func redactedIdentityLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if len(value) <= 12 {
		return value
	}
	return value[:6] + "…" + value[len(value)-6:]
}

func hashString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func compactNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func defaultTimestamp() string {
	return strconv.FormatInt(time.Now().UTC().Unix(), 10)
}

func debugIdentityFields(identity clientIdentityContext) map[string]any {
	return map[string]any{
		"principal":          redactedIdentityLabel(identity.Principal),
		"client_app":         identity.ClientApp,
		"client_instance":    redactedIdentityLabel(identity.ClientInstance),
		"capability_profile": identity.CapabilityProfile,
		"connector_id":       redactedIdentityLabel(identity.ConnectorID),
		"provider":           identity.ProviderName,
	}
}

func ensureIdentityTimestamp(identity clientIdentityContext) clientIdentityContext {
	if strings.TrimSpace(identity.Timestamp) == "" {
		identity.Timestamp = defaultTimestamp()
	}
	return identity
}
