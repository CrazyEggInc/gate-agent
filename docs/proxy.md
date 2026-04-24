# Proxy

This document describes the proxy feature as a behavior contract.

## Goal

The proxy must let authenticated clients call configured upstream APIs through a local route surface while keeping upstream credentials server-side.

This proxy contract remains intact even when MCP support is enabled. MCP clients should treat `/mcp` as the MCP protocol entrypoint. The `/proxy` routes remain the underlying HTTP forwarding surface rather than the MCP protocol contract.

## Route surface

The system must expose:

Routes:

- `/proxy/{api}`
- `/proxy/{api}/`
- `/proxy/{api}/{*path}`

These routes continue to define the direct HTTP proxy behavior. They are not replaced by `/mcp`, and MCP clients should not depend on `/proxy` as the MCP contract surface.

The router also applies:

- request timeout layer with 60 second outer timeout
- request ID generation and propagation through `x-request-id`
- request completion logging with `client_id` on every request

The per-request outer timeout is separate from the per-upstream timeout configured on each API entry.

## Proxy authorization flow

For proxy routes, the expected flow is:

1. Read `Authorization` header.
2. Reject missing, repeated, or malformed authorization headers.
3. Validate the presented bearer token as an opaque credential.
4. Extract the route `{api}` slug.
5. Derive required access from the inbound HTTP method.
6. Require that `{api}` is allowed by the matched client's configured `api_access` at sufficient access.
7. Resolve the upstream API config.
8. Map the inbound request to an outbound upstream request.
9. Execute the upstream request with the configured per-API timeout.
10. Map the upstream response back to the client.

Bearer validation expectations:

- clients send exactly one `Authorization: Bearer <token>` header
- the token is treated as opaque input
- validation is server-side lookup and hash verification, not token self-inspection
- expired, unknown, malformed, or mismatched bearer credentials fail authentication
- a validated bearer token resolves to one configured client
- that client's configured `api_access` is the only authorization scope model

Method authorization rules:

- `GET`, `HEAD`, `OPTIONS` require `read`
- `POST`, `PUT`, `PATCH`, `DELETE` require `write`
- every other method also requires `write`
- `write` satisfies `read`
- non-listed methods fail closed unless the token grants `write`

Expected error classes:

- invalid/missing bearer token → `401 invalid_token`
- every `401 invalid_token` response includes `WWW-Authenticate: Bearer`
- forbidden API access → `403 forbidden_api`
- bad proxy path → `400 bad_proxy_path`
- upstream build/request failures → `502`
- upstream timeout → `504`

## Request mapping

Request mapping expectations:

- the upstream URL is built from the configured API `base_url` plus the suffix after `/proxy/{api}`
- the route selector `{api}` is not forwarded upstream
- query strings are preserved
- if the request path does not begin with `/proxy/{api}`, mapping fails
- `/proxy/{api}` forwards to the API base path itself
- `/proxy/{api}/...` forwards only the suffix after the API selector

### Header filtering

The outbound request must strip:

- client `Authorization`
- `Host`
- hop-by-hop headers
- headers named by the incoming `Connection` header
- client forwarding headers:
  - `Forwarded`
  - `X-Forwarded-For`
  - `X-Forwarded-Host`
  - `X-Forwarded-Proto`
  - `X-Forwarded-Port`
  - `X-Forwarded-Prefix`
  - `X-Real-IP`
  - `Via`

Each API may configure zero, one, or many upstream request headers to inject.

Each API may also configure `basic_auth` for upstream HTTP basic authentication.

Configured API headers are applied as header overlay on top of filtered client headers.

If configured API header name collides with forwarded client header name, configured API header wins and overwrites forwarded value.

This includes configured `Authorization` injection when present. Client `Authorization` is still stripped before forwarding, and configured API headers may add replacement `Authorization` or any other required upstream header.

When `basic_auth` is configured, the proxy injects `Authorization: Basic <base64(username:password)>` for upstream request.

If `basic_auth.password` is omitted, the proxy still injects basic auth and encodes `username:` with empty password.

`basic_auth` and configured `headers.authorization` are mutually exclusive on same API config.

The proxy does not pass client-supplied topology headers upstream.

## Upstream execution

Each configured API carries a `timeout_ms`. When omitted in config, it defaults to `5000`.

Behavior:

- outbound requests run under the configured upstream timeout
- upstream timeouts surface distinctly from other upstream failures
- upstream redirects are followed by the shared outbound HTTP client
- redirect loops or excessive redirects surface as upstream request failures

## Response mapping

Response expectations:

- preserve upstream status code
- stream upstream response bodies back to the caller
- strip hop-by-hop headers from upstream responses
- preserve non-hop-by-hop headers

## Proxy telemetry

Proxy completion logs must include:

- `client_id` on every request completion log
- the authenticated client slug when bearer validation succeeds, otherwise `<unknown>`
- safe upstream metadata for proxied requests: API slug, outbound method, outbound URL, upstream status, and timeout
- `error_code` only when the response came from an application error
- no bearer token values, token identifiers, hashes, or upstream secrets

## Hop-by-hop header logic

Hop-by-hop filtering must recognize the standard hop-by-hop headers plus names listed by the `Connection` header, and it must apply to both request and response mapping.
