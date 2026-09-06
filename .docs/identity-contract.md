# Identity Contract

This document defines the identity bridge contract between the CPA plugin and
agy2api. It is scoped to inference traffic only. The plugin does not read,
forward, or depend on Business MCP Hub app assertions, Ed25519 app identity, or
Hub `app_id` fields.

## Headers

The plugin may add these headers to upstream agy2api requests:

| Header | Meaning | Notes |
| --- | --- | --- |
| `X-AGY-Principal` | Opaque 64-hex device or client principal | Required for agy2api principal refinement |
| `X-AGY-Client-App` | Client application label | Explicit header wins over User-Agent classification |
| `X-AGY-Client-Instance` | Stable installed app instance | Required for multi-app separation on one machine |
| `X-AGY-Capability-Profile` | Policy/profile scope | Separate profiles must produce separate principals |
| `X-AGY-Connector-Id` | Optional connector identifier | Not required for explicit identity to engage |
| `X-AGY-Session-ID` | Optional session identifier | Used by fallback modes |
| `X-AGY-Timestamp` | Unix timestamp in seconds | Freshness is checked by agy2api |
| `X-AGY-Plugin-Version` | Plugin version | Diagnostic only |
| `X-AGY-CPA-Provider-Name` | Mirrored provider name | Used for namespace and diagnostics |
| `X-AGY-Upstream-Model` | Model after prefix normalization | Diagnostic only |
| `X-AGY-Provider` | Mirrored provider name | Diagnostic and compatibility alias |
| `X-AGY-Signature` | HMAC-SHA256 of canonical payload | Required when agy2api enforces signatures |

Source:

- `src/identity.go`
- `src/executor.go`
- `src/dispatch.go`

## Canonical Signed Payload

The signed payload is newline-joined in this exact order:

```text
principal=<principal>
timestamp=<timestamp>
client_app=<client_app>
client_instance=<client_instance>
capability_profile=<capability_profile>
connector_id=<connector_id>
method=<HTTP method>
path=<wire request path>
```

agy2api verifies the same shape using `request.url.path`. Because the mirrored
provider `base-url` may already include `/v1`, the plugin signs the path from
the constructed upstream URL, not the allowlisted route fragment. For example,
if the provider base URL is `http://agy2api.example/v1`, the signed chat path is
`/v1/chat/completions`.

The known-routes allowlist still normalizes inbound paths for matching. That
normalization must not leak into the signed path.

Source:

- `identitySignatureMessage` in `src/identity.go`
- `upstreamRequestURL` and `signedUpstreamPath` in `src/executor.go`
- `_identity_signature_message` in agy2api `app/core/security.py`

## Principal Derivation

Explicit identity is used when `allow_explicit_client_identity_headers` is true
and at least one of these is present:

- `X-AGY-Client-App`
- `X-AGY-Client-Instance`
- `X-AGY-Capability-Profile`
- `X-AGY-Connector-Id`

The explicit principal seed is built from non-empty terms only:

```text
namespace=<provider namespace>
app=<normalized client app>
instance=<client instance>
profile=<capability profile>
connector=<connector id>
```

The terms are joined with NUL and hashed with the plugin principal prefix.

Important consequences:

- Two apps on one machine must send distinct `X-AGY-Client-App` and
  `X-AGY-Client-Instance` values.
- A shared instance with distinct capability profiles produces distinct
  principals.
- A shared instance with identical or empty profiles can collapse into one
  principal.
- `connector_id` is optional for explicit identity, but adding it later changes
  the principal and can orphan existing connector bindings unless the server
  lane migrates aliases.

Fallback modes:

- `client_key_hash`: default; uses client instance, bearer token hash, or
  session id when available.
- `user_agent_plus_session`: uses normalized app and session id.
- `disabled`: returns no principal.

Source:

- `deriveStablePrincipal` in `src/identity.go`
- `src/identity_profiles_test.go`

## App Identity And User-Agent

`User-Agent` identifies transport, not product. For example,
`openai/python 2.24.0` is normalized to `openai-python`. The plugin must not
guess Hermes, Codex, Cursor, or another app from that transport string.

For app-specific connector, skill, or MCP policy, the client must send explicit
identity headers:

```text
X-AGY-Client-App: hermes
X-AGY-Client-Instance: <stable install id>
X-AGY-Capability-Profile: <profile name>
```

When `allow_explicit_client_identity_headers` is false, explicit identity headers
are ignored for principal derivation and sanitized from the identity context.

Source:

- `normalizeClientApp` in `src/identity.go`
- `deriveClientIdentityFromIntercept` in `src/identity.go`
- `src/identity_test.go`

## Trusted Proxy Boundary

The plugin does not decide trust. agy2api does.

agy2api uses the raw TCP peer unless the peer is explicitly listed in
`AGY_IDENTITY_BRIDGE_FORWARDED_ALLOW` and sends `X-Forwarded-For`. XFF from any
other peer is ignored. The identity bridge only refines a principal when:

- `AGY_IDENTITY_BRIDGE_ENABLED` is true;
- `X-AGY-Principal` is a 64-hex digest;
- the resolved client is in `AGY_IDENTITY_BRIDGE_TRUSTED_PROXIES`, or that set
  is empty;
- if `AGY_IDENTITY_BRIDGE_REQUIRE_SIGNATURE` is true, the HMAC matches.

The current deployment does not need `AGY_IDENTITY_BRIDGE_FORWARDED_ALLOW`
because CPA's real peer address reaches agy2api intact.

Source:

- `_raw_peer_ip`, `_request_client_ip`, `_identity_bridge_trusted`, and
  `refine_principal` in agy2api `app/core/security.py`
- `IDENTITY_BRIDGE_*` entries in agy2api `app/core/config.py`

## Secret Precedence

The plugin resolves the HMAC secret in this order:

1. `agy2api_identity_secret`
2. `hmac_secret`
3. `AGY_PLUGIN_SECRET`
4. provider API key, only when `hmac_secret_source: provider_api_key` and no
   stronger source exists
5. empty, which leaves requests unsigned

agy2api verifies with `AGY_IDENTITY_BRIDGE_SECRET` from its credential store or
environment. The plugin reports only whether a secret is configured and which
source wins. It never returns secret values in diagnostics.

Source:

- `hmacSecret` and `hmacSecretSource` in `src/config.go`
- `hmacSecretForCandidate` in `src/providers.go`
- `src/providerspec_test.go`

## No-Secret Rules

- Do not print raw secrets, bearer tokens, provider API keys, or raw signatures.
- Diagnostics may show redacted principal labels and safe identity fields.
- The dedicated `agy2api_identity_secret` field is write-only in settings views.
- Public browser resources omit config paths, URLs, auth indexes, and credential
  values until a management key is supplied.

Source:

- `redactedIdentityLabel` and `debugIdentityFields` in `src/identity.go`
- `src/management.go`
- `src/providers.go`
