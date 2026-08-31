# agy-identity-bridge

CLIProxyAPI plugin that injects identity headers into requests going to agy2api providers.

## What It Does

When CLIProxyAPI forwards a request to an agy2api provider, this plugin:

1. Extracts the original Bearer token from the Authorization header.
2. Derives a SHA256 principal hash from the token.
3. Detects the client application from User-Agent (Codex, Hermes, Cursor).
4. Injects headers: `X-AGY-Principal`, `X-AGY-Client-App`, `X-AGY-Signature`.

This allows agy2api to identify which device/application sent the request, even when CLIProxyAPI uses a single shared API key.

## Plugin Configuration (CLIProxyAPI config.yaml)

```yaml
plugins:
  agy-identity-bridge:
    enabled: true
    match_providers:
      - "*Antigravity*"
```

Set the HMAC secret via environment variable:
```bash
export AGY_PLUGIN_SECRET="your-shared-secret-here"
```

## Building

Build on Linux (requires GCC for CGO):

```bash
make build
```

Output: `dist/agy-identity-bridge-v0.1.0.so`

## Deploying

1. Copy the `.so` file to the CLIProxyAPI plugins directory.
2. Add plugin configuration to CLIProxyAPI `config.yaml`.
3. Set `AGY_PLUGIN_SECRET` environment variable.
4. Restart CLIProxyAPI.

## Testing

```bash
go test ./src
```

## Files

- `src/main.go`: CGO exports and plugin entry point
- `src/dispatch.go`: Method routing, request interception, identity derivation
- `src/identity_test.go`: Unit tests
- `go.mod`: Go module definition
