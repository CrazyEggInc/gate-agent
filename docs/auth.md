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
2. The request body contains the list of APIs the client wants to use.
3. The server validates the API key, its expiration, and the requested API set.
4. The server returns a short-lived JWT.
5. The client uses that JWT as a bearer token when calling `/proxy/{api}` routes.
6. The proxy authorizes the route-selected API and forwards the request upstream using configured upstream auth.

Clients do not sign their own proxy tokens.

## Exchange contract

The system must expose:

- `POST /auth/exchange`

The request must:

- require `x-api-key`
- require a JSON body
- accept a body shaped like:

```json
{
  "apis": ["projects"]
}
```

The exchange behavior must:

- normalize requested APIs to lowercase
- sort and deduplicate requested APIs before issuing a token
- reject empty API lists
- reject malformed API slugs
- reject any request where at least one requested API is unknown or not allowed for the client
- issue one token covering the approved API set
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
- malformed JSON or empty API list yields `400 bad_request`
- requesting unknown or unauthorized APIs yields `403 forbidden_api`
- internal failures yield `500 internal`

Unlike invalid bearer-token responses, invalid API key responses do not add a `WWW-Authenticate` header.

## Client authorization model

Clients are configured by slug and API key.

The system must:

- reject blank API keys
- reject expired API keys
- reject duplicate configured API keys
- authorize requested APIs against the configured `allowed_apis` list for the matched client

API key lookup and expiration failures must surface as authentication failures during exchange.

## Token contract

Issued JWTs must contain:

- `sub` — client slug
- `apis` — authorized API slugs as an array
- `iss`
- `aud`
- `iat`
- `exp`

Token expectations:

- `apis` is serialized as a JSON array, not a CSV string
- `apis` is normalized by sorting and deduplicating
- the token is signed by the server using the configured signing secret
- token validation checks issuer, audience, timing claims, and API membership

Before issuing a token, the system must ensure:

- APIs are normalized and validated
- every API must be allowed for the client
- every API must exist in configured upstream APIs

## Bearer-token validation expectations

Bearer-token validation must:

- authorization header must be `Bearer <token>` with exactly two parts
- JWT header algorithm must be HS256
- `sub` must be a valid slug
- `apis` must be a non-empty list of valid slugs
- the client named by `sub` must exist in config
- verify the token against:
  - signing secret
  - issuer
  - audience
  - required claims: `sub`, `apis`, `exp`, `iat`, `iss`, `aud`
- `iat` must not be in the future
- every API in the token must still be both:
  - allowed for the client
  - present in configured upstream APIs

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
- otherwise the request fails with forbidden API
- when the request includes `x-request-id`, it is copied to the response
- when it does not, the router stack generates one and propagates it

## Local testing workflow

The product must support a local workflow for exercising the real auth flow.

Expected helper behavior:

- `--auth` emits a curl config that calls `POST /auth/exchange`
- `--proxy --jwt ... --api ... --path ...` emits a curl config that calls the proxy with a bearer token
- proxy mode is the default when neither `--auth` nor `--proxy` is supplied

In auth mode, the helper must request the APIs allowed for the selected client.

The helper must not mint local tokens. It must always exercise the exchange-based flow.
