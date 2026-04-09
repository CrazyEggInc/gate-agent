# Runtime

This document describes runtime expectations that tie the product together.

## Goal

Runtime behavior must be predictable, fail closed, and support local debugging.

The command surface must also remain compact and ergonomic for common local workflows.

## Startup expectations

The product startup flow must be:

1. parse CLI args
2. load runtime config
3. construct runtime state
4. bind TCP listener
5. build the HTTP router
6. start serving requests

CLI success, including built-in `--help`, must exit zero.

CLI failure output must match the current command behavior:

- `config validate` exits non-zero and prints a JSON error payload to stderr when config validation fails
- other CLI failures print a human-readable error and exit non-zero

## App state

Runtime state must contain:

- parsed secrets/config
- an index from API key to client slug
- a shared reqwest client
- startup settings such as bind address, log level, and the explicit config source (`Path(...)` or `Stdin`)

Runtime rules:

- duplicate client API keys are rejected at state construction time
- API config lookup is fail-closed
- client lookup by API key checks expiration on every auth exchange

## HTTP client behavior

Upstream HTTP behavior must be explicit.

Redirects must not be followed implicitly. Timeouts must be explicit and owned by the proxy.

## Error model

All HTTP-facing errors must use a consistent JSON payload shape:

```json
{
  "error": {
    "code": "invalid_token",
    "message": "authentication failed",
    "request_id": "req-123"
  }
}
```

Expected properties:

- payload messages are safe/public-facing messages, not raw internal error strings
- internal/config/secrets errors are collapsed to `internal server error`
- invalid bearer token responses include `WWW-Authenticate: Bearer`
- request IDs are included in the payload when available

## Time helpers

The system must use shared timestamp helpers for:

- JWT issuance/validation
- API key expiration checks

This keeps auth behavior consistent and reduces duplicated time logic.

## Telemetry

The runtime must carry a configurable log level and attach request IDs so logs and error responses can be correlated with incoming requests.

Expected logging behavior:

- tracing must be initialized during startup using the configured log level
- every CLI command that can produce logs must accept `--log-level`
- `--log-level` controls gate-agent application verbosity, not raw tracing filter syntax
- invalid `--log-level` input must fail startup with a clear human-readable error instead of silently falling back
- the selected level applies only to `gate-agent` targets
- dependency targets must remain limited to warning and error output even when the application runs at `debug`
- each HTTP request must emit a completion log with method, URI, status, latency, request ID, and `client_id`
- `client_id` is the authenticated client slug when the request authenticates successfully, otherwise `<unknown>`
- proxy request completion logs must also include safe upstream metadata: API slug, outbound method, outbound URL, upstream status, and timeout
- completion logs must include `error_code` only when the response came from an application error
- logs must not include API keys, bearer tokens, JWTs, or upstream secret values
- logged request URIs and upstream URLs must exclude query strings, fragments, and userinfo
