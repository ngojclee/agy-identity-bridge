# AGY Identity Bridge Docs

This directory is the canonical contract and operations index for the CPA plugin.
The root `README.md` remains the broad project introduction and configuration
guide. When a rule affects identity, streaming, model routing, or deployment,
record it here first and link it from the root README only when operators need
to discover it.

## Document Ownership

| Document | Owns | Source of truth |
| --- | --- | --- |
| [identity-contract.md](identity-contract.md) | `X-AGY-*` headers, canonical HMAC payload, principal derivation, trusted proxy boundary, secret precedence, no-secret rules | `src/identity.go`, `src/config.go`, `src/executor.go`, `src/dispatch.go`, `src/providers.go`, and agy2api `app/core/security.py` |
| [streaming-and-errors.md](streaming-and-errors.md) | `execute` vs `execute_stream`, progressive bridge, SSE framing, keepalive/tool frames, non-2xx stream-start handling, `empty_stream` diagnosis, timeout chain | `src/executor.go`, `src/hostcalls.go`, agy2api `app/api/routes.py`, and CPA plugin host bridge source |
| [install-upgrade-operations.md](install-upgrade-operations.md) | release workflow, Plugin Store update, reload verification, model cache behavior, rollback, bounded smoke tests | `Makefile`, `.github/workflows/build.yml`, `registry.json`, `src/modelcache.go`, `src/management.go`, and live CPA logs |
| [provider-model-routing.md](provider-model-routing.md) | provider ownership, model registration, family aliases, image lane pass-through, no unrelated aliases, no cross-effort fallback | `src/providerspec.go`, `src/models.go`, `src/executor.go`, `src/management.go`, and tests |

## Verified Baseline

Verified on 2026-09-06 from current source and live read-only checks:

| Component | Baseline |
| --- | --- |
| CPA plugin repo | `v0.2.41`, commit `59801020684fba2ce28a70f8df879758020af854` |
| CPA plugin loaded live | `agy-identity-bridge version=0.2.41` |
| CPA core live | `v7.2.151`, commit `5208aec` |
| agy2api live | `1.10.40.202609061250` |
| agy2api timeout chain live | `hub_call_seconds=660`, `cli_subprocess_seconds=780`, `chat_stream_cap_seconds=810`, `nested=true`, `clamped=false` |

The live timeout chain is readable without secrets at:

```text
GET http://10.21.4.101:8123/api/app-info
```

under the `timeout_chain` field.

## Change Checklist

Update these docs in the same change as code when any of the following moves:

- A new `X-AGY-*` header is read, forwarded, signed, or verified.
- The canonical HMAC field order or newline-joined format changes.
- The secret precedence chain changes.
- The trusted proxy or X-Forwarded-For boundary changes.
- The executor route allowlist or signed wire path rule changes.
- The progressive stream bridge, `host.stream.emit`, `host.stream.close`, SSE
  framing, `[DONE]`, keepalive, or connector activity behavior changes.
- Non-2xx stream-start handling or HTTP status propagation changes.
- Model registration, family alias handling, image lane pass-through, effort
  suffix normalization, or provider collision rules change.
- Release, Plugin Store, reload, model cache, rollback, or smoke-test procedure
  changes.

Do not record secrets, raw provider API keys, raw signatures, unrestricted
command output, base64 image payloads, or client bearer tokens in these docs.
