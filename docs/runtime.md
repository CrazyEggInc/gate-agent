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

The runtime router must expose both product entrypoints:

- `/proxy/...` for direct HTTP proxy traffic
- `/mcp` for MCP JSON-RPC traffic over HTTP

CLI success, including built-in `--help`, must exit zero.

CLI failure output must match the current command behavior:

- `config validate` exits non-zero and prints a JSON error payload to stderr when config validation fails
- other CLI failures print a human-readable error and exit non-zero

When the selected config file is encrypted, runtime startup may pause before state construction to obtain a password. Runtime password lookup order is CLI flag, environment, system keyring entry for the selected config path, then interactive prompt.

Startup should pause only after flag, environment, and keyring lookup all fail. Failure to obtain or use that password is a startup failure.

Keyring backend policy is platform-specific but explicit:

- Linux uses the native keyutils backend from the `keyring` crate
- macOS uses the native Keychain backend
- Windows uses the native Credential Manager backend

## App state

Runtime state must contain:

- parsed secrets/config
- an in-memory bearer-token lookup indexed by `bearer_token_id`
- a shared reqwest client
- startup settings such as bind address, log level, and the explicit config source (`Path(...)` or `Stdin`)

Runtime rules:

- the bearer-token lookup must resolve each token ID to the owning client and its stored bearer credential metadata
- server-side bearer credential material is limited to `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- duplicate configured bearer token identifiers are rejected at state construction time
- API config lookup is fail-closed
- bearer-token lookup checks expiration on every proxy request

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

Route-specific behavior:

- `/proxy/...` uses the HTTP JSON error payload above for application errors
- `/mcp` uses the same HTTP auth failure behavior before MCP dispatch, including `401 invalid_token`, `WWW-Authenticate: Bearer`, and the standard JSON error payload shape
- after `/mcp` authentication succeeds, MCP protocol errors are returned as JSON-RPC error responses on HTTP `200 OK`
- operators should expect MCP parse, invalid request, invalid params, and method-not-found failures to appear as JSON-RPC errors rather than the HTTP error envelope

## Time helpers

The system must use shared timestamp helpers for:

- bearer-token expiration checks

This keeps auth behavior consistent and reduces duplicated time logic.

## Telemetry

The runtime must carry a configurable log level and attach request IDs so logs and error responses can be correlated with incoming requests.

This request-ID behavior applies to both `/proxy/...` and `/mcp`. Callers may supply `x-request-id`; otherwise the router generates one and propagates it on responses.

Authentication expectations also apply consistently across both route families. `/mcp` is not an anonymous control plane endpoint: callers must present exactly one valid `Authorization: Bearer <token>` header before any MCP request is parsed or dispatched.

All runtime logging must use newline-delimited JSON. Each emitted line must be a complete JSON object that can be shipped, filtered, or parsed without depending on terminal formatting.

This JSON policy applies consistently to:

- startup logs
- per-request completion logs

The schema should stay vendor-neutral and portable. Consumers may rely on stable business fields such as client, request ID, method, URI, status, latency, API slug, upstream metadata, error code, and error message, but they must not depend on formatter-specific field ordering or nesting details.

Expected logging behavior:

- tracing must be initialized during startup using the configured log level
- every CLI command that can produce logs must accept `--log-level`
- `--log-level` controls gate-agent application verbosity, not raw tracing filter syntax
- invalid `--log-level` input must fail startup with a clear human-readable error instead of silently falling back
- the selected level applies only to `gate-agent` targets
- dependency targets must remain limited to warning and error output even when the application runs at `debug`
- startup logs must use the same newline-delimited JSON policy as request logs
- each HTTP request must emit a completion log with method, URI, status, latency, and request ID
- authenticated proxy completion logs must include the authorized client slug as the top-level `client` field
- authenticated `/mcp` request completion logs must also remain attributable to the authorized client
- proxy request completion logs must also include safe upstream metadata: API slug, outbound method, outbound URL, upstream status, and timeout
- completion logs must include `error_code` only when the response came from an application error
- when a top-level `status` field is present for an HTTP completion log, it represents the HTTP response status and may be rendered as a standard status line string such as `201 Created`; consumers that need only the numeric code should read that value portably rather than depend on formatter-specific duplicate fields
- logs must not include formatter-added `span` or `spans` metadata
- logs must include only sanitized, safe-to-ship values
- logs must not include bearer tokens, bearer token identifiers, bearer token hashes, or upstream secret values
- logged request URIs and upstream URLs must exclude query strings, fragments, and userinfo
- redaction and sanitization rules apply equally to startup and request-completion logs
