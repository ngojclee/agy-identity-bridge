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
      hmac_secret_source: env
```

When all `match_*` selectors are empty and `auto_discover` is enabled, the
plugin matches:

- native CPA requests whose `ToFormat` is `antigravity`;
- providers whose name, provider key, or base URL contains `antigravity` or
  `agy2api`.

Explicit selectors support case-insensitive substring matching and `*`/`?`
wildcards:

- `match_name`: provider name;
- `match_url`: provider base URL;
- `match_api_key`: exact provider API key;
- `match_provider`: one provider name/key selector (legacy-compatible alias);
- `match_providers`: additional provider name/key patterns;
- `match_mode: any`: at least one configured selector must match;
- `match_mode: all`: every configured selector must match.

`match_api_key` is a selector only. It is not silently reused as the HMAC
secret.

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
credential values.

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
make build VERSION=0.1.5
```

The output is:

```text
dist/agy-identity-bridge-v0.1.5.so
```

The GitHub Actions workflow builds and packages:

```text
agy-identity-bridge_0.1.5_linux_amd64.zip
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
