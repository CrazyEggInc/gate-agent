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
4. the matched client's effective `api_access` becomes the MCP authorization scope

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

## list_apis discovery contract

`list_apis` is the discovery tool for the authenticated client.

The result must be derived from the client's effective `api_access`, including any access inherited through configured groups after config resolution.

Discovery expectations:

- only APIs present in the authenticated client's effective `api_access` are listed
- each listed API includes its configured slug
- each listed API includes the effective access level available to that client
- results may include operator-configured discovery metadata such as description and docs URL when present
- results are suitable for tool-driven discovery and should direct the client to `call_api` for actual invocation

`list_apis` is an authorization view, not a full config dump. It exposes what the authenticated client can call, not unrelated APIs or secret configuration.

## call_api request contract

`call_api` lets an authenticated MCP client call an API that is already allowed by its effective `api_access`.

Request expectations:

- the client specifies the target API slug
- the client specifies the outbound HTTP method
- the client specifies a path that begins with `/`
- the client may provide query parameters
- the client may provide request headers
- the client may provide a request body
- the client may provide an explicit content type when needed

Authorization expectations:

- the selected API must be allowed by the authenticated client's effective `api_access`
- method access follows the same read/write policy as `/proxy`
- `write` access satisfies `read`
- unauthorized or unknown APIs fail closed

Forwarding expectations:

- outbound routing, upstream credential injection, timeout handling, and header filtering follow the same proxy behavior as `/proxy`
- client-supplied bearer auth is not forwarded upstream as client auth
- client topology headers are not forwarded upstream
- safe client headers may be forwarded when allowed by the proxy contract

## call_api response contract

`call_api` returns a tool result that represents the upstream HTTP response in MCP-friendly form.

Response expectations:

- include the upstream HTTP status code
- include response headers in a structured form
- include the upstream content type when known
- include a parsed JSON body when the upstream response is JSON
- include a text body when the upstream response is text
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

Tool execution failures must surface as tool errors with safe, structured error data.

## Non-goals

The MCP product contract explicitly excludes:

- session state
- `/auth/exchange`
- JWT-based auth flows
- browser login flows
- resource prompts, subscriptions, or non-tool MCP features
- general-purpose binary upload/download tunneling
