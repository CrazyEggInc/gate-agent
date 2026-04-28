# Authentication

This document describes the authentication feature as a product contract. A new implementation must be able to reproduce this behavior without relying on the current source layout.

## Goal

The proxy must use a clean-break single-bearer model.

- clients authenticate directly with one opaque bearer token
- clients send that bearer token on `/proxy` and `/mcp` routes
- the server validates bearer credentials against server-side state
- API authorization comes only from the matched client's configured `api_access`
- clients never provide upstream credentials directly

Authentication happens only through bearer credentials presented on product routes that require client auth.

## Required workflow

The workflow must be:

1. A client sends exactly one `Authorization: Bearer <token>` header to a `/proxy/{api}` route or `/mcp` route.
2. The server validates the bearer token as an opaque credential.
3. The validated token resolves to one configured client.
4. The server derives the client's effective `api_access` from config.
5. The server authorizes the requested operation from that effective `api_access`:
   - `/proxy` requests authorize the selected API slug and route rule
   - `/mcp` discovery only exposes APIs allowed by that client
   - `/mcp` calls only execute APIs with a matching method/path route rule
6. The server forwards the authorized upstream request using configured upstream authentication.

The bearer token is not a scope container. It is only a credential that identifies an allowed client session.

## Bearer credential contract

Bearer credentials are server-owned and validated server-side.

The server-side bearer credential material must be limited to:

- `bearer_token_id`
- `bearer_token_hash`
- `bearer_token_expires_at`

The server must not rely on self-describing token contents for authorization.

The owning client's configured `api_access` is the only scope model.

## Client authorization model

Clients are configured by slug and bearer credential.

The system must:

- reject blank bearer token identifiers
- reject blank bearer token hashes
- reject duplicate configured bearer token identifiers
- reject expired bearer credentials
- require each client to declare exactly one of `group` or inline `api_access`
- resolve group references to an effective per-client `api_access` map at load time
- authorize `/proxy` and `/mcp` access only against that effective `api_access` map for the matched client

## Bearer-token validation expectations

Bearer-token validation must:

- require exactly one `Authorization` header
- require the header value to be exactly `Bearer <token>` with exactly two parts
- reject blank bearer token values
- treat the bearer token as opaque input
- resolve the presented token to a stored `bearer_token_id`
- look up the stored bearer credential by `bearer_token_id`
- compare the presented token against the stored `bearer_token_hash`
- check `bearer_token_expires_at`
- require that the matched client still exists in config

Successful validation authenticates the owning client. It does not add or narrow scopes beyond configured effective `api_access`.

## Failure expectations

The feature must fail closed.

Expected classes of failures:

- missing, repeated, malformed, unknown, mismatched, or expired bearer credentials yield `401 invalid_token`
- every `401 invalid_token` response on authenticated route families includes `WWW-Authenticate: Bearer`
- requests for unknown or unauthorized APIs yield `403 forbidden_api`
- internal failures yield `500 internal`

## Route authorization rules

The authenticated route determines how API authorization is applied.

Effective `api_access` is a per-API route whitelist. Each API may map to zero or more route rules with:

- `method`: exact HTTP method or `*`
- `path`: exact upstream path, glob-style path pattern containing `*`, or `*`

Authorization fails closed. A configured API slug alone does not allow any request unless at least one route rule matches. Query strings are ignored for route matching.

- route family:
  - `/proxy/{api}`
  - `/proxy/{api}/`
  - `/proxy/{api}/{*path}`
- after bearer-token validation, the selected route `{api}` must be allowed by the matched client's effective `api_access`
- after `/proxy/{api}` suffix extraction, the inbound HTTP method and upstream suffix path must match one configured route rule for that API
- method `*` matches any inbound HTTP method
- `TRACE` is rejected before forwarding regardless of route-rule matches
- path `*` matches any upstream suffix path
- exact paths and glob-style path patterns are matched against the path only; query strings are not considered
- missing API access or missing route-rule match fails with `403 forbidden_api`
- the router generates an internal `x-request-id` for each request and propagates that generated value

- route family:
  - `/mcp`
  - `/mcp/`
  - `/mcp/{*path}`
- `/mcp` uses the same direct bearer-token validation model as `/proxy`
- MCP discovery must be limited to APIs allowed by the matched client's effective `api_access`
- MCP calls must authorize the targeted API against that same effective `api_access`
- if the client lacks access to the targeted API or no method/path route rule matches, the request fails with `403 forbidden_api`

## Local testing workflow

The product must support a local workflow for exercising the real auth path.

Expected helper behavior:

- proxy mode uses a caller-provided bearer token directly
- helper output for proxy requests sends exactly one `Authorization: Bearer <token>` header
- proxy mode is the default when no alternate mode is selected

The helper must exercise direct bearer authentication rather than minting, exchanging, or transforming credentials locally.
