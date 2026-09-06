# Streaming and Errors

This document records how the plugin serves `execute` and `execute_stream`, how
progressive streaming reaches the client, how SSE framing is handled, and how
non-2xx upstream responses are surfaced. It is the reference for diagnosing
`empty_stream`, batching, and provider-error reports.

## Two executor paths

- `execute` (`handleExecutorExecute`) is the non-streaming path. It performs one
  host HTTP call and returns the full upstream payload and headers.
- `execute_stream` (`handleExecutorExecuteStream` in `src/executor.go`) is the
  streaming path. It opens a host HTTP stream and relays events to CPA through
  the host stream bridge.

Both paths call `normalizeExecutorModel` first, so model prefix stripping, effort
suffix normalisation, and image lane handling are identical. See
[provider-model-routing.md](provider-model-routing.md).

## Forcing upstream streaming

CPA may select `execute_stream` for a request whose original payload did not carry
`stream=true`. The host stream callback needs a real upstream stream, so the
plugin forces `stream=true` on the agy2api request via `forceStreamingPayload`.
This is why a client that asked for a stream always gets a genuine upstream
stream, even if the inbound body said otherwise.

## Progressive bridge and early return

When CPA opens a stream it hands the plugin a bridge `stream_id`. CPA's RPC
adapter cannot pass that downstream bridge channel to the HTTP response writer
until `executor.execute_stream` returns. If the plugin held the call open and
pumped synchronously, the bridge buffer would only drain after the upstream
response ended, which looks exactly like full-response batching to the client.

So when a bridge `stream_id` is present (`executorStreamShouldReturnEarly`), the
plugin returns immediately with the upstream headers and keeps pumping chunks from
a goroutine (`pumpExecutorStreamToBridge`). Without a bridge `stream_id`, it falls
back to the batched path (`executorStreamBatched`).

The pump goroutine:

- reads host HTTP stream chunks in order,
- parses them into completed SSE events,
- emits each event through `host.stream.emit` in arrival order,
- records usage from the buffered stream on completion,
- closes the bridge exactly once via `closeBridge`, including on panic recovery.

## SSE framing

CPA's stream bridge wraps each emitted chunk in its own SSE `data:` frame. To
avoid a doubled `data:` prefix, the plugin strips the upstream SSE framing and
emits one payload per completed event (`sseStreamParser`, `sseEventPayload`,
`emitUpstreamEvents`).

Details that matter:

- Both `data: x` and `data:x` spellings are accepted. A strict prefix test on one
  spelling silently discards the other.
- `[DONE]` is skipped because CPA writes its own done tail.
- A final event that arrives without its trailing blank line is still delivered,
  because the pump calls `sse.flush()` when the upstream stream ends.
- Frames with no `data:` field are dropped: a bare `event:` line, a keep-alive
  comment (`:` prefix), or an empty data value. These carry nothing a chat client
  can render.

### Progress and reasoning frames

`reasoning_content` and thinking text that arrive inside a `data:` JSON chunk are
forwarded verbatim, in order, with arrival timing intact, because they are part of
the data payload.

The plugin does **not** preserve a distinct SSE `event:` name. Because CPA's
bridge re-wraps every emitted payload as a `data:` frame, a structured progress
frame that relies on its own `event:` line (rather than a discriminator inside the
`data:` JSON) loses that event name on this path. If agy2api adds named progress
frames, the client-visible contract must carry the frame type inside the `data:`
JSON, not only in the SSE `event:` field. This is a CPA bridge limitation, not a
plugin choice, and the plugin must not buffer a progress frame until the response
completes; it emits as chunks arrive.

## Non-2xx stream start

A non-2xx stream start is not an SSE stream. agy2api can answer a chat request
with a plain JSON error, such as HTTP 413 for an oversized body, before any SSE
event is produced. Feeding that body to the SSE parser would emit no frames and
CPA would surface a misleading `empty_stream` error.

So `isNonSuccessStreamStart(status)` is true when `status > 0 && (status < 200 ||
status > 299)`. On that condition the plugin:

1. drains a bounded body (`drainHostHTTPStreamBody`, capped at
   `maxUpstreamErrorBodyBytes = 8192`),
2. closes the host HTTP stream once,
3. returns `upstream_error` carrying the real HTTP status via
   `errorEnvelopeStatus`.

This is what turns an agy2api HTTP 413 JSON error into a faithful status instead
of a false `empty_stream`.

## Host returned no stream id

If the host HTTP stream start succeeds but returns an empty `stream_id`, the
plugin returns `upstream_stream_unavailable` with "host returned no stream id".
That message is a CPA plugin host condition, not an agy2api failure. When it
appears intermittently it usually means the host stream channel was not ready;
the fix is on the CPA side (reload or restart), not in the bridge.

## Host call timeout

All host calls go through `hostCall` (`src/hostcalls.go`). The plugin sets no
explicit upstream timeout of its own. CPA's host HTTP bridge uses timeout `0`
(no timeout) for plugin host calls. On a long stream the first timeout is
expected to come from a downstream client, not from CPA or the plugin.

## Timeout chain

agy2api derives and clamps its own chain so that `hub < cli < stream`. The live
baseline verified on 2026-09-06 is:

```text
hub_call_seconds=660
cli_subprocess_seconds=780
chat_stream_cap_seconds=810
env_agy_timeout_seconds=780
nested=true
clamped=false
```

Read it without secrets from `GET http://10.21.4.101:8123/api/app-info` under the
`timeout_chain` field.

Note: an earlier snapshot reported a 750s cap with `env_agy_timeout_seconds=180`
and `clamped=true`. That snapshot is stale; the current live chain is the 810s
baseline above. Treat 810s as the documented figure until a new read contradicts
it.

## Hermes and Codex client timeouts

Hermes local config was checked and exposes tool/terminal/code-execution timeouts
(`terminal.timeout`, `code_execution.timeout`) but no explicit LLM request
timeout. The Codex client-side timeout was not confirmed. When a long request
fails, compare the client timeout against the 810s agy2api stream cap before
blaming the bridge.

## Provider error that is really a completed answer

A past failure mode was the gateway reporting `agy2api returned HTTP 0` while the
error payload contained a complete assistant answer. That is a status misread on
the gateway side, not an upstream death. The non-2xx stream-start handling above
is the plugin-side guard so a real upstream status is forwarded instead of being
collapsed into a generic error.

## Source of truth

- `src/executor.go` — `handleExecutorExecuteStream`,
  `executorStreamShouldReturnEarly`, `isNonSuccessStreamStart`,
  `executorUpstreamError`, `drainHostHTTPStreamBody`, `pumpExecutorStreamToBridge`,
  `emitUpstreamEvents`, `sseStreamParser`, `forceStreamingPayload`.
- `src/hostcalls.go` — `hostCall`.
- CPA plugin host bridge — `internal/pluginhost/http_bridge.go`,
  `internal/pluginhost/rpc_client_stream.go`, `internal/pluginhost/host_callbacks.go`.
