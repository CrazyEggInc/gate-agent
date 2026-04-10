# Authentication

This document describes the authentication feature as a product contract. A new implementation must be able to reproduce the auth behavior from this document without relying on the current source layout.

## Goal

The proxy must support a server-owned authentication model.

- Clients authenticate with long-lived API keys.
- The server exchanges those API keys for short-lived bearer tokens.
- Proxy access is granted only to APIs explicitly authorized for that client.
- Clients never provide upstream credentials directly.

## Required workflow

The workflow must be:

1. A client sends its API key to `POST /auth/exchange`.
2. The request body contains the API access map the client wants to use.
3. The server validates the API key, its expiration, and the requested API access map.
4. The server returns a short-lived JWT.
5. The client uses that JWT as a bearer token when calling `/proxy/{api}` routes.
6. The proxy authorizes the route-selected API and required method access, then forwards the request upstream using configured upstream auth.

Clients do not sign their own proxy tokens.

## Exchange contract

The system must expose:

- `POST /auth/exchange`

The request must:

- require `x-api-key`
- reject missing, blank, non-UTF8, or repeated `x-api-key` headers
- require a JSON body
- accept a body shaped like:

```json
{
  "apis": {
    "projects": "read"
  }
}
```

The exchange behavior must:

- normalize requested API slugs to lowercase
- reject empty API access maps
- reject malformed API slugs
- reject unknown access levels
- authorize requested access against the client's effective configured access
- allow a client configured for `write` to request `read`
- reject a client configured for `read` that requests `write`
- reject any request where at least one requested API is unknown or not allowed for the client
- issue one token covering the approved API access map
- use a token lifetime of 10 minutes

The response must be JSON shaped like:

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 600
}
```

## Failure expectations

The feature must fail closed.

Expected classes of failures:

- missing or invalid `x-api-key` yields `401 invalid_api_key`
- malformed JSON, malformed API slugs, oversized exchange bodies, empty API access maps, or invalid access levels yield `400 bad_request`
- requesting unknown or unauthorized APIs yields `403 forbidden_api`
- internal failures yield `500 internal`

Unlike invalid bearer-token responses, invalid API key responses do not add a `WWW-Authenticate` header.

## Client authorization model

Clients are configured by slug and API key.

The system must:

- reject blank API keys
- reject expired API keys
- reject duplicate configured API keys
- require each client to declare exactly one of `group` or inline `api_access`
- resolve group references to an effective per-client `api_access` map at load time
- authorize requested APIs against that effective `api_access` map for the matched client

API key lookup and expiration failures must surface as authentication failures during exchange.

## Token contract

Issued JWTs must contain:

- `sub` — client slug
- `apis` — authorized API access as an object map
- `iss`
- `aud`
- `iat`
- `exp`

Token expectations:

- `apis` is serialized as a JSON object map from API slug to access level
- `apis` is normalized into deterministic key order
- the token is signed by the server using the configured signing secret
- token validation checks issuer, audience, timing claims, and API access

Example JWT claim shape:

```json
{
  "sub": "default",
  "apis": {
    "projects": "write",
    "billing": "read"
  },
  "iss": "gate-agent-dev",
  "aud": "gate-agent-clients",
  "iat": 1712664000,
  "exp": 1712664600
}
```

Before issuing a token, the system must ensure:

- APIs and access levels are normalized and validated
- every API must be allowed for the client at the requested access level
- every API must exist in configured upstream APIs

## Bearer-token validation expectations

Bearer-token validation must:

- authorization header must be exactly one `Bearer <token>` header with exactly two parts
- JWT header algorithm must be HS256
- `sub` must be a valid slug
- `apis` must be a non-empty object map of valid slugs to `read` or `write`
- the client named by `sub` must exist in config
- verify the token against:
  - signing secret
  - issuer
  - audience
  - required claims: `sub`, `apis`, `exp`, `iat`, `iss`, `aud`
- `iat` must not be in the future
- every API in the token must still be both:
  - allowed for the client at the claimed access level
  - present in configured upstream APIs

Access compatibility rules:

- token `read` is valid when the configured client access is `read` or `write`
- token `write` is valid only when the configured client access is `write`

Error behavior for bearer-token validation:

- malformed or invalid bearer tokens yield `401 invalid_token`
- invalid token responses include `WWW-Authenticate: Bearer`
- tokens that are structurally valid but request unauthorized APIs must yield `403 forbidden_api`

## Proxy authorization rule

The route itself selects the API being accessed.

- route family:
  - `/proxy/{api}`
  - `/proxy/{api}/`
  - `/proxy/{api}/{*path}`
- after bearer token validation, the selected route `{api}` must be present in the token’s `apis` claim
- the required access level is derived from the inbound HTTP method:
  - `GET`, `HEAD`, `OPTIONS` require `read`
  - `POST`, `PUT`, `PATCH`, `DELETE` require `write`
  - every other method requires `write` (fail closed)
- a token with `write` access satisfies `read`
- otherwise the request fails with forbidden API
- when the request includes `x-request-id`, it is copied to the response
- when it does not, the router stack generates one and propagates it

## Local testing workflow

The product must support a local workflow for exercising the real auth flow.

Expected helper behavior:

- `--auth` emits a curl config that calls `POST /auth/exchange`
- `--proxy --jwt ... --api ... --path ...` emits a curl config that calls the proxy with a bearer token
- proxy mode is the default when neither `--auth` nor `--proxy` is supplied

In auth mode, the helper must request the effective API access map allowed for the selected client.

The helper must not mint local tokens. It must always exercise the exchange-based flow.
