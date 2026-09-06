# Provider and Model Routing

This document records how the plugin owns providers, publishes models, and how
CLIProxyAPI (CPA) routes a requested model to the plugin executor. It is the
reference for family aliases, effort metadata, and image lane behaviour.

Scope: identity bridge and metadata bridge only. The plugin does not change CPA
provider selection, does not replace the CPA extractor, and does not decide tool
routing. It mirrors one matched Antigravity provider and publishes the models it
is told to publish.

## Provider ownership

The plugin mirrors exactly one `openai-compatibility` provider, selected by the
configured matchers (name, base URL, API key, provider, model). It never touches
unrelated providers.

Source: `extractProviderSpec` in `src/providerspec.go`.

- A live (non-disabled) matched provider is preferred.
- If the only match is disabled, the plugin falls back to that disabled match so
  an operator can mirror a provider they have already switched off.
- The mirrored provider is a replacement, not a peer. Its priority is offset
  upward (`priority + 100`, floor 10) so it wins any future collision resolution
  while preserving relative order between multiple mirrors.

## What the plugin publishes

The plugin publishes models through `handleModelRegister`, `handleModelStatic`,
and `handleModelForAuth` (`src/models.go`). All three return
`currentModelResponse()`, which is gated by `canServeModels`.

`canServeModels` (`src/providerspec.go`) is the collision guard. The plugin keeps
its models out of the registry while the mirrored provider is still enabled and
no test namespace is set, because two providers serving the same model would let
CPA load balance across them and some requests would silently bypass the bridge.

The published list is `spec.Models`, resolved in this precedence:

1. The mirrored provider's `models:` array in CPA `config.yaml`, when present.
   This is authoritative for a live provider.
2. The persisted model cache (`agy-identity-bridge-models.json`) when the matched
   provider is disabled and its `models:` array is empty, or when the provider
   block has been removed entirely.

The plugin returns bare model IDs. CPA applies the prefix from the plugin-owned
auth record itself, so returning prefixed IDs here would produce duplicates such
as `agy/agy/model`.

Source: `modelInfos`, `modelInfosForRegistration`, `cachedModelSpecs`,
`cachedProviderSpecFromCache`.

## How CPA routes a model to the plugin

CPA resolves the provider for a requested model **only** from the global model
registry. In CPA `internal/util/provider.go`, `GetProviderName` calls
`registry.GetGlobalRegistry().GetModelProviders(modelName)` and returns those
providers. There is no string heuristic fallback in the current CPA line.

Consequences:

- A model name, including a family alias, is routable **if and only if it is
  registered in the model registry** under some provider. The plugin registers
  every model it publishes under its own provider, so a published alias routes to
  the plugin executor.
- If no provider registered the name, `getRequestDetailsWithOptions` in
  `sdk/api/handlers/handlers.go` returns "unknown provider for model", which
  surfaces as `model_not_found`. This happens before the plugin sees the request.

So an alias that nobody registers cannot be matched at all. The registration is
the thing that makes it routable.

## Family aliases

A family alias such as `gemini-3.8-flash` is a first-class model name in this
contract, distinct from the suffixed concrete IDs (`gemini-3.8-flash-high`).

The plugin recognises these family names and gives them narrow default thinking
levels when no source metadata is present
(`defaultThinkingLevelsForModel` in `src/providerspec.go`):

| Family | Default levels |
| --- | --- |
| `gemini-3.1-pro` | none, low, high |
| `gemini-3.6-flash` | none, low, medium, high |
| `gemini-3.7-flash` | none, low, medium, high |
| `gemini-3.8-flash` | none, low, medium, high |
| `gemini-image` | none, low, high |

Concrete suffixed IDs and unknown models must not get invented levels unless the
source (provider config or the upstream `/models` catalog) declares them.

For a family alias to be routable it must be registered. The plugin registers a
family alias only when it appears in `spec.Models`, which means either:

- it is in the mirrored provider's `models:` array in `config.yaml`, or
- it is in the persisted cache because "Fetch from endpoint" pulled it from the
  upstream `/models` list and the provider block is disabled/empty so the cache
  is the active source.

The plugin does not synthesise family aliases from the suffixed IDs it already
publishes. That is deliberate: the plugin mirrors what the upstream advertises and
must not invent model IDs the upstream does not serve.

## Effort suffix normalisation on the executor path

When a request reaches the executor, `normalizeExecutorModel`
(`src/executor.go`) strips the public prefix and, for non-image models, splits a
trailing effort suffix off the model name:

```text
agy/gemini-3.8-flash(high)  ->  model=gemini-3.8-flash, reasoning_effort=high
```

Rules:

- An explicit `reasoning_effort` (or `effort`, `thinking`, `reasoning.effort`)
  already in the body wins over the suffix.
- The suffix is only recognised for the known level set
  (`none, off, minimal, low, medium, high, xhigh, max, auto`).
- After normalisation the executor forwards the bare model plus
  `reasoning_effort` upstream. It does not map a family name to a suffixed name;
  resolving family plus effort into a concrete model is the upstream's job.

## Image lane pass-through

Image traffic has its own upstream contract. `isImageLaneModel` treats a model as
image lane when the bare name contains `image` or the mirrored provider declares
image capability for it.

For image lane models the executor only strips the public prefix. It does not
inject `reasoning_effort` and does not apply effort suffix normalisation. This is
why `gemini-image` can reach agy2api unchanged, including when agy2api serves it
through `/v1/chat/completions`.

## Effort metadata exposure through CPA

The plugin carries thinking/effort metadata in `modelInfo.Thinking`, and CPA
preserves it into the registry (`pluginModelInfoToRegistryModelInfo` in
CPA `internal/pluginhost/adapters.go` maps `Thinking` through).

But CPA exposes that metadata on only one discovery shape:

- Plain `GET /v1/models` is hard-filtered to `id`, `object`, `created`,
  `owned_by` in CPA `sdk/api/handlers/openai/openai_handlers.go`. Effort is not
  present there. This is a CPA host limitation, not a plugin choice.
- `GET /v1/models?client_version=...` (the Codex client shape) emits
  `supported_reasoning_levels` and `default_reasoning_level`, derived from the
  registry `Thinking.Levels` for the model
  (`applyCodexClientThinkingMetadata` in CPA
  `sdk/api/handlers/openai/codex_client_models.go`).

So a harness behind CPA that needs effort from discovery must use the
`client_version` shape, or send `reasoning_effort` without a discovery hint. The
plugin cannot make the plain `/v1/models` emit fields CPA strips.

## Hard rules

- The plugin must not offer or alias models that agy2api does not serve. For
  example `gpt-image-1` and `gpt-image-2` belong to other providers and must never
  be mapped to `gemini-image`. There is no `gpt-image` alias path in source; this
  is a rule, not a feature.
- No cross-effort or cross-family fallback inside the plugin. The plugin forwards
  the exact model it was given after prefix and suffix normalisation. Any
  substitution between families, versions, or effort levels is the upstream's
  decision, never the bridge's.
- Toggling the plugin off, or removing it, must leave the original provider
  working. The plugin is opt-in and only ever mirrors; it does not own the
  upstream.

## Tests that lock this behaviour

- `src/providerspec_test.go` — provider matching, collision guard, model mapping.
- `src/executor_test.go` — prefix strip, effort suffix normalisation, image lane.
- `src/forwarding_test.go` — body forwarding integrity, model rewriting.
- `src/management_test.go` — `/models` parsing, editor payload, cache round trip.

Run them with `go test ./src/...` from the plugin directory.
