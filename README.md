# AGY Identity Bridge

CLIProxyAPI plugin that injects identity headers into requests routed to
Antigravity or agy2api providers. It also exposes provider matching
diagnostics through the CPA Management API.

## What It Does

For a matched request the plugin:

1. Reads the selected request context after CPA authentication.
2. Derives an opaque SHA-256 principal from the Bearer token.
3. Detects the client application from `X-AGY-Client-App` or a small,
   conservative User-Agent classifier.
4. Adds `X-AGY-Principal`, `X-AGY-Client-App`, and optionally
   `X-AGY-Signature`.

The plugin does not modify unrelated providers.

Release 0.2.15 keeps the identity bridge canonical payload stable for agy2api
while preserving the legacy signing fallback during the transition period and
adds passive usage telemetry for the mirrored provider.

## CPA Configuration

Use the canonical CPA shape:

```yaml
plugins:
  enabled: true
  configs:
    agy-identity-bridge:
      enabled: true
      priority: 100
      auto_discover: true
      include_native_antigravity: true
      match_mode: any
      match_name: ""
      match_url: ""
      match_api_key: ""
      match_provider: ""
      match_providers: []
      match_model: "agy/*"
      match_models: []
      hmac_secret_source: env
```

## How the plugin identifies a provider at request time

CLIProxyAPI calls the after-auth interceptor with `pluginapi.RequestInterceptRequest`,
which carries the source format, the selected upstream model, the client
requested model and the request headers. It does **not** carry the provider
name or base URL for OpenAI-compatible providers, and `ToFormat` is just
`openai` for all of them.

The one field that does identify the provider is the requested model prefix.
So the plugin reads `openai-compatibility` from the mounted CPA config, keeps
the providers your selectors match, and maps a live request back to its
provider by that provider's `prefix`. A request for `agy/gemini-3.5-flash-low`
is therefore attributed to the provider whose `prefix: agy`.

That means a provider you want to affect must have a `prefix` in CPA config.
The status endpoint lists what it found under `active_prefixes` and warns when
a matched provider has none, because such a provider cannot be identified per
request.

When all `match_*` selectors are empty and `auto_discover` is enabled, the
plugin matches:

- native CPA requests whose `ToFormat` is `antigravity`;
- requests whose model carries the prefix of a provider that auto discovery
  matched;
- providers whose name, provider key, or base URL contains `antigravity` or
  `agy2api`.

Explicit selectors support case-insensitive substring matching and `*`/`?`
wildcards:

- `match_name`: provider name;
- `match_url`: provider base URL;
- `match_api_key`: exact provider API key;
- `match_provider`: one provider name/key selector (legacy-compatible alias);
- `match_providers`: additional provider name/key patterns;
- `match_model`: requested model, for example `agy/*`;
- `match_models`: additional requested model patterns;
- `match_mode: any`: at least one configured selector must match;
- `match_mode: all`: every configured selector must match.

`match_name` and `match_url` describe which config providers the plugin owns
and shape the diagnostics view. Add `match_model` when you want the request
path pinned explicitly as well, which is the most precise option.

`match_api_key` is a selector only. It is not silently reused as the HMAC
secret.

## Executor mode

CLIProxyAPI's OpenAI-compatible executor builds its upstream request from
scratch and never applies the headers an interceptor returned, so identity
headers injected by this plugin cannot reach agy2api through that provider.
Executor mode removes that limitation by making this plugin the caller.

```yaml
plugins:
  configs:
    agy-identity-bridge:
      executor_enabled: true
      executor_provider: ln.Antigravity
      model_namespace: "spike."
```

The plugin mirrors the provider it matches in `openai-compatibility`: base URL,
API keys, extra headers, priority, disable-cooling, prefix and the model list.
Model metadata is mapped the same way the host does it, so alias wins over name,
`image: true` becomes the `openai-image` type, and a chat model without explicit
thinking still advertises `low`, `medium` and `high`. Nothing is invented: if the
provider declares no models, the plugin publishes none.

With `model_namespace: ""`, the mirrored models keep the original provider
prefix. For example, an original `prefix: agy` publishes
`agy/gemini-3.7-flash-high` through the plugin after cutover. The executor
removes that prefix before forwarding the upstream request to agy2api. Setting
`model_namespace` overrides the original prefix for a parallel test.

The mirrored provider keeps the original's priority as a base and adds a boost:
`priority = max(original priority + 100, 10)`. Today CLIProxyAPI ignores
priority when two providers publish the same model ID, but if a future version
starts honoring it, the plugin provider wins instead of splitting traffic.

The plugin returns model names without a provider prefix during model
registration. CPA applies the prefix from the plugin-owned auth record, so the
visible client model remains `agy/<model>` (or the configured namespace)
without becoming `agy/agy/<model>`.

CPA calls both interceptor phases. The plugin handles `request.intercept_before`
as an intentional no-op because provider identity and the selected client
credential are only available in the after-auth phase, where the identity
headers are added.

`executor_enabled` defaults to false, and installing a new plugin version does
not change routing on its own.

### Collision guard

While the mirrored provider is still enabled, the plugin withholds its models
unless `model_namespace` is set. Two providers publishing the same model ID would
make CLIProxyAPI load balance across them, and the requests that land on the
original provider silently lose their identity. The status endpoint reports
`models_served` and warns while this is in effect.

To finish the switch, disable the mirrored provider in CPA config and clear
`model_namespace`. The plugin then publishes the same visible model names
clients already use after CPA applies the preserved provider prefix.

### Replacement modes

The status endpoint reports `replacement_mode` so the operator always knows
which path serves a model:

- `withheld`: executor is on, the original provider is still enabled, and
  `model_namespace` is empty. The plugin publishes nothing; the original
  provider serves all traffic.
- `namespace`: executor is on and `model_namespace` is set. The plugin publishes
  the mirrored models under the namespace prefix for parallel testing while the
  original keeps serving the un-prefixed names.
- `active`: executor is on, `model_namespace` is empty, and the original
  provider is disabled in CPA config. The plugin is the only serving path for
  these models; the status page warns that re-enabling the original provider is
  required before disabling or uninstalling the plugin.

`provider_original_enabled` mirrors the original provider's `disabled` flag so
the transition can be verified from diagnostics alone. CPA notifies the plugin
through `plugin.reconfigure` whenever `config.yaml` changes, so disabling the
original provider in the CPA UI takes effect without a restart.

## HMAC Secret

The signing key is resolved in strict priority order:

1. `agy2api_identity_secret`: the dedicated plugin config field. When set, it
   wins over every other source, including an explicit `none`.
2. `hmac_secret`: the legacy plugin config field.
3. `AGY_PLUGIN_SECRET`: the CPA container environment variable.
4. `provider_api_key`: only when `hmac_secret_source: provider_api_key` and no
   stronger source has a value.

agy2api verifies the signature on every request, so an unsigned request is
rejected with 401. When the executor sees that happen, diagnostics add a
signature mismatch warning and record the failing status in
`last_executor_status`, which usually means the plugin secret and the agy2api
`AGY_IDENTITY_BRIDGE_SECRET` do not match.

The dedicated field is write-only: `GET /settings` and diagnostics report
`agy2api_identity_secret_configured: true` but never the value itself.

The legacy `hmac_secret_source` selector still exists for compatibility:

```yaml
plugins:
  configs:
    agy-identity-bridge:
      hmac_secret_source: env
```

Its remaining effect: `provider_api_key` signs with the selected provider API
key when no stronger source is configured (not available for native OAuth
auths), and `none` suppresses signing only when no secret is configured
anywhere. Prefer setting `agy2api_identity_secret` (or `AGY_PLUGIN_SECRET`) and
leaving the selector alone.

The receiver must use the same signature contract. The plugin never returns
the secret or raw provider API keys in diagnostics.

## Rollback

The plugin normally mirrors the configured provider without changing it. The
Provider View dashboard can also save deliberate edits back to `config.yaml`;
API keys and the agy2api identity secret are write-only there, so leaving those
fields empty preserves the existing values.

1. Re-enable the original `Antigravity` provider in CPA
   (`openai-compatibility`, toggle the provider back on). CPA reloads the
   config, the plugin receives `plugin.reconfigure`, the collision guard
   re-engages, and the plugin withholds its models again. Traffic returns to
   CPA's built-in OpenAI executor with the latest saved provider settings.
2. Optionally set `executor_enabled: false` in the plugin config (or disable
   the plugin) to remove the executor path entirely. Models published by the
   plugin disappear; the interceptor keeps running so identity headers keep
   working for the original provider path.

Order matters: re-enable the original provider **before** disabling or
uninstalling the plugin. While `replacement_mode` is `active`, the plugin is the
only serving path for the mirrored models, and removing it without re-enabling
the original would take those models offline.

## Diagnostics

Authenticated Management API routes:

```text
GET  /v0/management/plugins/agy-identity-bridge/status
GET  /v0/management/plugins/agy-identity-bridge/provider
GET  /v0/management/plugins/agy-identity-bridge/provider/config
POST /v0/management/plugins/agy-identity-bridge/provider/save
POST /v0/management/plugins/agy-identity-bridge/provider/test
POST /v0/management/plugins/agy-identity-bridge/provider/fetch-models
GET  /v0/management/plugins/agy-identity-bridge/settings
POST /v0/management/plugins/agy-identity-bridge/rescan
```

The status response reports:

- whether the mounted CPA config was found;
- whether this plugin has a config block;
- whether the plugin instance is enabled and its configured priority;
- the active matching mode and number of explicit selectors;
- separate counts for configured records and runtime auth records;
- number of records and unique providers matched;
- the provider names and redacted URLs affected by the plugin, with match
  reasons;
- the complete scanned provider list on the authenticated route, including
  unmatched records;
- whether API keys are configured, without returning their values;
- warnings for native OAuth/API-key selector limitations.

`providers` contains only records the plugin will affect. `scanned_providers`
contains both matched and unmatched records so a wrong selector can be
diagnosed without guessing.

CPA also exposes a redacted browser resource:

```text
/v0/resource/plugins/agy-identity-bridge/status
/v0/resource/plugins/agy-identity-bridge/provider
/v0/resource/plugins/agy-identity-bridge/usage
```

These resources intentionally omit config paths, URLs, auth indexes, and
credential values until a management key is supplied in the Provider View. CPA
serves plugin resource routes without management authentication, so account
labels (native Antigravity auth labels are account emails) are also stripped
from this projection. Use the authenticated status route when you need them.

The `AGY Identity Bridge` resource is a single dashboard for the mirrored
`ln.Antigravity` path. Its main surface keeps the operational state, live model
IDs, runtime log, usage filters, token totals, and compact usage analysis
visible. Provider configuration and deeper usage analysis open in one wider
right-side drawer with `Provider` and `Usage analytics` tabs.

The provider tab has the same core fields as an OpenAI-compatible provider:
name, base URL, prefix, priority, disabled state, disable cooling, headers,
API keys, and custom models. API key entries, headers, models, and thinking
levels can be collapsed independently. Saving requires the CPA management key
and writes only the selected mirrored provider plus this plugin's executor
settings.

Usage analytics reads `usage` data from agy2api responses when present, keeps
the response body and headers untouched for other trackers, and groups the
statistics by period, minute/hour/day/week/month bucket, source, model share,
client source, cache performance, and recent observations. The period presets
are `Last 5 hours`, `Last 7 days`, `Last 30 days`, `Current month`, and
`All time`.

### Client identity and transport User-Agent

`User-Agent` identifies the transport layer more reliably than the originating
application. For example, `openai/python 2.24.0` is recorded as
`openai-python`; it must not be interpreted as Hermes. The plugin cannot
reliably recover the original application from that adapter string.

When agy2api must apply app-specific connector, skill, or MCP policy, the
originating client should send a trusted explicit identity header such as
`X-AGY-Client-App: hermes`, preferably with
`X-AGY-Client-Instance` and `X-AGY-Capability-Profile`. The plugin preserves
those explicit values, includes them in the stable principal/signature
contract, and never guesses Hermes from `openai/python`. If no explicit
identity is available, use a separate client key or session context for each
application installation.

## CPA Lifecycle Statuses

The `Configured`, `Registered`, and `Inactive` labels in CPA Manager describe
the host lifecycle, not provider matching:

- `Configured`: `plugins.configs.agy-identity-bridge` exists in `config.yaml`.
- `Registered`: CPA loaded the dynamic library and accepted
  `plugin.register`.
- `Effective`: global `plugins.enabled`, per-plugin `enabled`, and
  registration are all active.
- `Inactive`: usually global plugins are disabled, the per-plugin flag is
  false, or registration failed.
- `Not registered`: CPA did not load the binary, the path/architecture is
  wrong, or CPA needs a restart.

Provider matching details are available from the authenticated status route
after the plugin is registered.

## Building

The release artifact is a Linux amd64 CGO shared library. Build on Linux with
Go 1.26 and GCC:

```sh
make test
make build VERSION=0.2.15
```

The output is:

```text
dist/agy-identity-bridge-v0.2.15.so
```

The GitHub Actions workflow builds and packages:

```text
agy-identity-bridge_0.2.15_linux_amd64.zip
checksums.txt
```

## Plugin Store

Add the registry source to CPA:

```yaml
plugins:
  store-sources:
    - https://raw.githubusercontent.com/ngojclee/agy-identity-bridge/main/registry.json
```

After a tagged release, refresh the CPA Plugin Store and restart CPA after
installation so the dynamic library is registered.

## Tests

```sh
go vet ./...
go test ./...
```

## License

MIT
