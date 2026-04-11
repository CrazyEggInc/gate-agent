# Proxy

This document describes the proxy feature as a behavior contract.

## Goal

The proxy must let authenticated clients call configured upstream APIs through a local route surface while keeping upstream credentials server-side.

## Route surface

The system must expose:

Routes:

- `/proxy/{api}`
- `/proxy/{api}/`
- `/proxy/{api}/{*path}`

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

Then the configured upstream auth header is injected:

- `auth_header`
- optional `auth_scheme`
- `auth_value`

The injected auth value overrides whatever client auth would otherwise have been forwarded.
The proxy does not pass client-supplied topology headers upstream.

## Upstream execution

Each configured API carries a `timeout_ms`. When omitted in config, it defaults to `5000`.

Behavior:

- outbound requests run under the configured upstream timeout
- upstream timeouts surface distinctly from other upstream failures
- redirect behavior must stay explicit rather than silently following upstream redirects

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
