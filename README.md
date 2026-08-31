# AGY Identity Bridge

CLIProxyAPI plugin that injects identity headers into requests routed to
Antigravity or agy2api providers. It also exposes provider matching
diagnostics through the CPA Management API.

## What It Does

For a matched request the plugin:

1. Reads the selected request context after CPA authentication.
2. Derives an opaque SHA-256 principal from the Bearer token.
3. Detects the client application from `X-AGY-Client-App` or `User-Agent`.
4. Adds `X-AGY-Principal`, `X-AGY-Client-App`, and optionally
   `X-AGY-Signature`.

The plugin does not modify unrelated providers.

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
      executor_provider: agy-bridge
      model_namespace: "spike."
```

The plugin mirrors the provider it matches in `openai-compatibility`: base URL,
API keys, extra headers, priority, disable-cooling and the model list. Model
metadata is mapped the same way the host does it, so alias wins over name,
`image: true` becomes the `openai-image` type, and a chat model without explicit
thinking still advertises `low`, `medium` and `high`. Nothing is invented: if the
provider declares no models, the plugin publishes none.

`executor_enabled` defaults to false, and installing a new plugin version does
not change routing on its own.

### Collision guard

While the mirrored provider is still enabled, the plugin withholds its models
unless `model_namespace` is set. Two providers publishing the same model ID would
make CLIProxyAPI load balance across them, and the requests that land on the
original provider silently lose their identity. The status endpoint reports
`models_served` and warns while this is in effect.

To finish the switch, disable the mirrored provider in CPA config and clear
`model_namespace`. The plugin then publishes the exact model names clients
already use.

## HMAC Secret

The default source is the `AGY_PLUGIN_SECRET` environment variable:

```yaml
plugins:
  configs:
    agy-identity-bridge:
      hmac_secret_source: env
```

Other explicit modes are:

- `hmac_secret_source: provider_api_key`: sign with the selected provider API
  key when one is available. This is not available for native OAuth auths.
- `hmac_secret_source: none`: do not add `X-AGY-Signature`.
- `hmac_secret_source: config` plus `hmac_secret`: supported for controlled
  deployments, but environment injection is preferred.

The receiver must use the same signature contract. The plugin never returns
the secret or raw provider API keys in diagnostics.

## Diagnostics

Authenticated Management API routes:

```text
GET  /v0/management/plugins/agy-identity-bridge/status
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
```

This resource intentionally omits config paths, URLs, auth indexes, and
credential values. CPA serves plugin resource routes without management
authentication, so account labels (native Antigravity auth labels are account
emails) are also stripped from this projection. Use the authenticated status
route when you need them.

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
make build VERSION=0.1.8
```

The output is:

```text
dist/agy-identity-bridge-v0.1.8.so
```

The GitHub Actions workflow builds and packages:

```text
agy-identity-bridge_0.1.8_linux_amd64.zip
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
