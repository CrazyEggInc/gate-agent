# MCP

This document describes the HTTP MCP feature as a product contract.

## Goal

`gate-agent` must expose a small MCP-over-HTTP surface for authenticated clients that already use the same bearer-token model as the proxy.

The MCP surface is for API discovery and API invocation through a tool model, not for session management or alternate authentication flows.

## Route surface

The system must expose:

- `POST /mcp`

The route accepts JSON-RPC 2.0 requests over HTTP.

This route is intentionally narrow:

- no session creation
- no session resumption
- no SSE transport
- no `GET /mcp`
- no `/auth/exchange`
- no JWT issuance or JWT validation

## Authentication and authorization

`/mcp` uses the same direct bearer authentication model as `/proxy`.

Expected behavior:

1. the client sends exactly one `Authorization: Bearer <token>` header to `POST /mcp`
2. the bearer token is treated as an opaque credential
3. the server validates that bearer token against configured server-side state
4. the matched client's effective `api_access` route whitelist becomes the MCP authorization scope

There is no secondary auth handshake for MCP. A client that can authenticate to `/proxy` with a direct bearer token must use that same model for `/mcp`.

Failure expectations before JSON-RPC dispatch:

- missing, repeated, malformed, unknown, mismatched, or expired bearer credentials yield `401 invalid_token`
- every `401 invalid_token` response includes `WWW-Authenticate: Bearer`
- authentication failure happens before MCP method handling

## Supported MCP methods

The MCP route supports only:

- `initialize`
- `tools/list`
- `tools/call`

Any other MCP method is unsupported and must fail as JSON-RPC method-not-found.

## Initialize contract

`initialize` establishes server capabilities for this HTTP MCP surface.

The result must advertise tool support and identify the server as `gate-agent`.

The MCP surface does not negotiate sessions or issue follow-up credentials during initialization.

## Tool catalog contract

`tools/list` must return exactly these tools:

- `call_api`
- `list_apis`

No other tools are part of the supported product contract.

`tools/list` is a static MCP tool catalog. It must describe the available tools and their input schemas only. It must not include configured API entries, API descriptions, or API docs URLs.

## list_apis discovery contract

`list_apis` is the discovery tool for the authenticated client.

The result must be derived from the client's effective `api_access`, including any route rules inherited through configured groups after config resolution.

Discovery expectations:

- only APIs present in the authenticated client's effective `api_access` are listed
- each listed API includes its configured slug
- each listed API includes the effective route rules available to that client
- each route rule includes `method` and `path`
- route rule `method = "*"` means any HTTP method
- route rule `path = "*"` means any upstream path for that API
- each listed API includes operator-configured `description` when present
- each listed API includes operator-configured `docs_url` when present
- API-specific discovery metadata belongs here, not in `tools/list`
- `structuredContent` should contain the full structured JSON discovery payload
- tool `content` should contain the same JSON object serialized as text for compatibility, including safe generic `call_api` examples such as `{"api":"projects","method":"GET","path":"/<endpoint>","query":{"example":"value"}}`
- discovery must tell clients that query parameters belong in `call_api.query`, not in `call_api.path`
- `call_api.path` examples must stay path-only and must not embed `?query` or `#fragment` components
- results are suitable for tool-driven discovery and should direct the client to `call_api` for actual invocation

`list_apis` is an authorization view, not a full config dump. It exposes what the authenticated client can call, not unrelated APIs or secret configuration.

## call_api request contract

`call_api` lets an authenticated MCP client call an API route that is already allowed by its effective `api_access` route whitelist.

Request expectations:

- the client specifies the target API slug
- the client specifies the outbound HTTP method
- `path` is the upstream path to call and must start with `/`
- `path` must not include query strings or fragments
- the client provides query parameters with the optional `query` object, for example `{"path":"/users","query":{"active":true}}`
- the client may provide request headers
- the client may provide a request body
- the client may provide an explicit content type when needed
- the client may set `response_headers` to `all` to include all upstream response headers; omitted means only `content-type` and `date` are returned when present

Authorization expectations:

- the selected API must be allowed by the authenticated client's effective `api_access`
- the selected method and path must match at least one configured route rule for that API
- `method = "*"` matches any requested method
- `path = "*"` matches any requested path
- exact paths and glob-style path rules are matched against `call_api.path`
- query parameters in `call_api.query` are ignored for route-rule matching
- unauthorized APIs, unknown APIs, and missing route-rule matches fail closed with `403 forbidden_api`

Forwarding expectations:

- outbound routing, upstream credential injection, timeout handling, and header filtering follow the same proxy behavior as `/proxy`
- `query` object parameters are encoded and appended to the configured upstream request URL
- client-supplied bearer auth is not forwarded upstream as client auth
- client topology headers are not forwarded upstream
- safe client headers may be forwarded when allowed by the proxy contract

## call_api response contract

`call_api` returns a tool result that represents the upstream HTTP response in MCP-friendly form.

Response expectations:

- `structuredContent` should contain the full structured JSON upstream response payload
- tool `content` should contain the same JSON object serialized as text for compatibility
- that JSON object should include the upstream HTTP status code
- that JSON object should include response headers in a structured form
- by default, that headers object should include only `content-type` and `date` when present
- when `response_headers = "all"`, that headers object should include all upstream response headers that can be represented safely as strings
- that JSON object should include the upstream content type when known
- that JSON object should include a parsed JSON body when the upstream response is JSON
- that JSON object should include a text body when the upstream response is text
- preserve upstream success and failure HTTP statuses as response data rather than hiding them behind a synthetic success shape

The MCP surface is intentionally JSON/text-friendly.

Supported body scope:

- JSON request bodies
- text request bodies
- JSON upstream responses
- text upstream responses

Explicitly unsupported behavior:

- multipart request bodies are not supported
- other binary-oriented request content types are not supported
- binary upstream response bodies are not supported
- upstream response bodies larger than the MCP payload limit are not supported

Unsupported request or response content types must fail explicitly rather than being coerced into lossy placeholder data.

The MCP implementation must also reject oversized upstream response bodies before buffering them fully for tool output. The v1 payload limit is 1 MiB.

## Error model

The MCP route has two layers of failure behavior:

### HTTP-layer auth failures

Authentication failures return the standard HTTP JSON error payload used by the rest of the product.

### JSON-RPC-layer MCP failures

Once authentication succeeds, malformed MCP payloads and unsupported MCP methods fail as JSON-RPC responses.

Tool execution failures must surface as tool errors with safe JSON object data in `structuredContent`, while `content` contains the same `{code,message}` JSON object serialized as text for compatibility.

## Non-goals

The MCP product contract explicitly excludes:

- session state
- `/auth/exchange`
- JWT-based auth flows
- browser login flows
- resource prompts, subscriptions, or non-tool MCP features
- general-purpose binary upload/download tunneling
