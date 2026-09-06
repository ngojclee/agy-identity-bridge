# Install, Upgrade, and Operations

This document records how the plugin is released, discovered by the CPA Plugin
Store, verified as loaded, and rolled back. It also records model cache behaviour
and bounded smoke tests.

## Release convention

Bump the version in three places together, in one commit:

| File | Field | Example |
| --- | --- | --- |
| `src/version.go` | `pluginVersion` | `0.2.42-dev` |
| `Makefile` | `VERSION ?=` | `0.2.42` |
| `registry.json` | `plugins[0].version` | `0.2.42` |

The `-dev` suffix in `src/version.go` is the local default. CI overwrites it with
`-ldflags "-X main.pluginVersion=..."` from the tag, so the shipped binary reports
the clean release version.

Then:

```text
git commit -m "release: vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

## CI build and artifacts

`.github/workflows/build.yml` runs on tag pushes matching `v*` on
`ubuntu-latest` with Go 1.26. It:

1. builds a Linux amd64 `agy-identity-bridge.so` with
   `-X main.pluginVersion=${GITHUB_REF_NAME#v}`,
2. packages `agy-identity-bridge_<version>_linux_amd64.zip`,
3. writes `<zip>.sha256` and `dist/checksums.txt`,
4. uploads the zip, its sha256, and checksums.txt to the GitHub Release via
   `softprops/action-gh-release`.

The local `make build` target mirrors CI: it asserts `GOOS=linux` and
`GOARCH=amd64`, builds with `CGO_ENABLED=1 -buildmode=c-shared`, and removes
stray `.h` output. Run `make test` (which is `go vet ./...` plus `go test ./...`)
before tagging.

## Plugin Store discovery

The CPA Plugin Store reads the registry from:

```text
https://raw.githubusercontent.com/ngojclee/agy-identity-bridge/main/registry.json
```

`registry.json` must be committed and pushed to `main` for the store to see a new
version. A tag alone is not enough; the store keys off the registry file. If the
store shows no update after a release, confirm `registry.json` on `main` matches
the tag and that the release assets exist.

## Verifying the loaded version

The registry and the release asset are not proof of what CPA is running. Confirm
the loaded plugin from CPA logs:

```text
docker logs cli-proxy-api | grep 'plugin loaded plugin_id=agy-identity-bridge' | tail
```

The current live loaded version verified on 2026-09-06 is `0.2.41`. After an
upgrade, restart or reload CPA and re-check this line before testing behaviour.
A stale loaded plugin is the most common cause of "the fix is in the repo but the
bug is still live".

## Model cache

The plugin persists the upstream model list so it can keep serving models even
when the original provider block is removed or emptied.

- File: `agy-identity-bridge-models.json`.
- Location: the same directory as the usage file, under the CPA plugins data dir.
- Contents: a flat `models` list plus a richer `catalog` carrying image flag,
  thinking levels, and input/output modalities per model.

Precedence at registration time:

1. The mirrored provider's `models:` array in `config.yaml` wins when present.
2. The cache is the fallback when the matched provider is disabled with no models
   array, or the provider block has been removed entirely.

The dashboard "Fetch from endpoint" action calls `probeProviderModelSpecs`, which
reads the upstream `/models` list and saves the catalog. Fetch updates the cache
and the editor rows; it does not rewrite the `config.yaml` `models:` array until
the operator saves the provider editor. See
[provider-model-routing.md](provider-model-routing.md) for what gets published and
how CPA routes it.

### Stale cache divergence

The cache is a point-in-time snapshot and can drift from the config array. When the
array is non-empty the cache is never read, so a stale cache is harmless while the
array stands. The risk is the empty-array path: if the `models:` array is ever
cleared or the provider block removed, the plugin falls back to whatever the cache
last held, which may be an older model set (for example the pre-consolidation
suffixed ids such as `gemini-3.8-flash-high`) rather than the current family ids.

Operational rule: after changing the model set in the array, refresh the cache with
"Fetch from endpoint" so the two agree, or clear the cache file so a future
empty-array state cannot resurrect a stale list. A restart with a populated array
always re-registers from the array, so configured models survive restarts; only the
empty-array fallback depends on the cache.

## Rollback

The plugin is opt-in and only mirrors a provider. To roll back:

1. Re-enable the original mirrored provider in CPA config first.
2. Then disable the plugin (or set `executor_enabled: false`).

While `replacement_mode=active`, the plugin is the only serving path for the
mirrored models, so removing it without re-enabling the original provider leaves
those models unrouted. Setting `executor_enabled: false` removes the executor
serving path; the interceptor may still inject identity headers on traffic that
still reaches the provider by other means.

## Bounded smoke tests

Use placeholders for any secret. Never paste a real bearer token or provider API
key into a log, doc, or report.

Streaming chat through CPA:

```text
curl -N http://10.21.1.101:8317/v1/chat/completions \
  -H "Authorization: Bearer <cpa-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"agy/gemini-3.8-flash-high","stream":true,"messages":[{"role":"user","content":"say hi"}]}'
```

Image generation through CPA:

```text
curl http://10.21.1.101:8317/v1/images/generations \
  -H "Authorization: Bearer <cpa-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"agy/gemini-image","prompt":"a red square","size":"1024x1024","response_format":"b64_json"}'
```

Oversized history (expect a clean non-2xx, not `empty_stream`): send a chat body
large enough that agy2api answers HTTP 413, and confirm CPA surfaces the status
rather than an empty stream. See
[streaming-and-errors.md](streaming-and-errors.md).

Identity acceptance: after one signed request through the executor, the agy2api
log must show a refined `principal=device:...`. That is the only proof that the
identity bridge is live. See [identity-contract.md](identity-contract.md).

## Source of truth

- `Makefile`, `.github/workflows/build.yml`, `registry.json`, `src/version.go`.
- `src/modelcache.go` — cache file, load, save, catalog shape.
- `src/management.go` — `handleProviderFetchModels`, `probeProviderModelSpecs`.
- `src/providerspec.go` — `extractProviderSpec`, `canServeModels`.
- Live CPA logs for the loaded-version check.
