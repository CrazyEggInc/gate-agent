# Local testing environment

This document defines the local operator workflow.

> Note: `README.md` covers the installed-binary and GitHub Releases operator flow at a high level. This document intentionally covers repository-local development using `cargo run` and the local dummy upstream.

## Goal

The repository provides a repeatable local environment for exercising:

- bearer-token authentication
- proxy authorization
- upstream credential injection
- end-to-end proxying through the dummy upstream

## Components

The local environment consists of:

- the `gate-agent` process started with `cargo run -- start`
- the `dummy-upstream` service started with `docker compose`
- a local config file derived from `.secrets.dev` or created with `config init`

## Dummy upstream

Expected properties:

- start with `docker compose up -d dummy-upstream`
- binds `127.0.0.1:18081` on the host
- health endpoint at `http://127.0.0.1:18081/healthz`
- static-auth project routes under `http://127.0.0.1:18081/api/v1/...`
- dynamic-auth project routes under `http://127.0.0.1:18081/api/v2/...`
- `POST http://127.0.0.1:18081/auth/token` validates local JSON credentials and returns a generated token with `expires_in`
- v1 requests require `Authorization: Bearer local-upstream-token`
- v2 requests require an unexpired token returned by `/auth/token`

## Local config

`.secrets.dev` is ready-to-run local sample config.

Its committed bearer token metadata uses long-lived sample expiry so documented local flow does not quietly age out during normal development. It includes access to the dummy upstream through both `projects`, which injects a static token into v1 requests, and `dynamic-projects`, which obtains generated tokens from `/auth/token` before calling v2. If you create fresh config instead, prefer `config init` and save the printed token immediately.

Expected committed sample defaults:

- a `default` client is available
- `default` uses `group = "default"`
- `groups.default` grants all routes for `projects` and `dynamic-projects`
- `projects` points at dummy upstream v1
- `projects` configures `headers = { authorization = "Bearer local-upstream-token" }`
- `dynamic-projects` points at dummy upstream v2
- `dynamic-projects` obtains tokens from the dummy `/auth/token` endpoint and injects them through `headers.authorization`

The committed sample config stores only bearer token metadata. For local testing, the matching bearer token is:

```sh
export GATE_AGENT_TOKEN='default.s3cr3t'
```

Typical setup:

```sh
cp .secrets.dev .secrets
cargo run -- start --config .secrets --log-level info
```

Stdin-backed startup is also supported:

```sh
cat .secrets.dev | cargo run -- start --log-level info
```

If you create fresh config instead, `config init` prints generated default bearer token once. Save it immediately; only token id, hash, and expiry are persisted.

Fresh configs created with `config init` use the same group-backed structure as the committed sample, but they intentionally start with `clients.default.group = "default"` and `groups.default.api_access = {}`. Fresh init does not pre-authorize any API; add APIs first, then update group access or assign different group access before using proxy flow.

Fresh configs created with `config init` also write an explicit `[server]` section. The questionnaire prompts for bind and port, defaults to `127.0.0.1:8787`, and remote-access setups should use `0.0.0.0` for the bind value.

## Proxy request workflow

Use normal `curl` directly against `gate-agent`:

```sh
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks
```

Expected behavior:

- the request targets the configured local bind address
- the request carries `Authorization: Bearer <token>` to the proxy
- the proxy authorizes the selected API slug and required method access
- the proxy forwards configured upstream headers from config before sending request upstream

Exercise dynamic upstream auth against the dummy v2 API:

```sh
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/dynamic-projects/projects/1/tasks
```

Expected behavior:

- gate-agent posts the configured JSON credentials to `/auth/token`
- the dummy returns a generated token and a 60-second lifetime
- gate-agent caches the token and sends it to `/api/v2/projects/1/tasks`
- repeated requests reuse the token until gate-agent refreshes it near expiration

To exercise auth failure forwarding, change `client_secret` in the local `dynamic-projects.auth.body`. The proxy returns the dummy auth endpoint's `401` response and does not call the v2 API.

## MCP request workflow

The local environment also supports direct bearer authentication on the MCP HTTP endpoint.

Use the same local bearer token and send it directly to `/mcp`:

```sh
curl -i http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {}
  }'
```

Expected behavior:

- the request carries exactly one `Authorization: Bearer <token>` header
- the server authenticates that bearer token before JSON-RPC dispatch
- a valid request returns a JSON-RPC `initialize` result
- an invalid bearer token fails with `401 invalid_token` and `WWW-Authenticate: Bearer`

Practical smoke requests:

List supported tools:

```sh
curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }' | jq
```

List effective API access for the authenticated client:

```sh
curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "list_apis",
      "arguments": {}
    }
  }' | jq
```

Call the local `projects` API through MCP:

```sh
curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "call_api",
      "arguments": {
        "api": "projects",
        "method": "GET",
        "path": "/v1/projects/1/tasks"
      }
    }
  }' | jq
```

Call the dynamic-auth v2 API through MCP:

```sh
curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "call_api",
      "arguments": {
        "api": "dynamic-projects",
        "method": "GET",
        "path": "/projects/1/tasks"
      }
    }
  }' | jq
```

That MCP smoke flow verifies:

- bearer-token auth on `/mcp`
- MCP JSON-RPC request handling
- effective API access exposure through `list_apis`
- upstream forwarding through `call_api`

If an MCP client such as Claude Code, Codex, or OpenCode supports configuring a fixed bearer `Authorization` header for an HTTP MCP server, point it at `http://127.0.0.1:8787/mcp` and use the same local bearer token directly. There is no separate local token exchange step for MCP.

Method access rules during local testing:

- each configured API uses an explicit method/path route whitelist
- method `*` matches every method except `TRACE`
- path `*` matches every upstream suffix path
- `TRACE` is always rejected before forwarding

## Config validation workflow

Path-backed example:

```sh
cargo run -- config validate --config .secrets
```

Stdin-backed example:

```sh
cat .secrets.dev | cargo run -- config validate
```

Expected behavior:

- valid config prints `config is valid`
- invalid config prints a JSON error payload to stderr and exits non-zero

## Direct config inspection and editing

Inspect config:

```sh
cargo run -- config show --config .secrets
```

Encrypted config:

```sh
GATE_AGENT_PASSWORD='correct horse battery staple' \
  cargo run -- config show --config .secrets.encrypted
```

Edit config:

```sh
VISUAL=nvim cargo run -- config edit --config .secrets
```

Encrypted edit:

```sh
VISUAL=nvim GATE_AGENT_PASSWORD='correct horse battery staple' \
  cargo run -- config edit --config .secrets.encrypted
```

Use resource-first config mutators for local operator work.

Upsert an API:

```sh
cargo run -- config api --config .secrets \
  --name projects \
  --base-url 'http://127.0.0.1:18081/api' \
  --header 'authorization=Bearer local-upstream-token'
```

Configure a dynamic-auth API by adding `--auth` and a token-template header. The command prompts for the auth request and response fields; the raw request body is entered through a hidden prompt:

```sh
cargo run -- config api --config .secrets \
  --name dynamic-service \
  --base-url 'https://api.internal.example' \
  --header 'authorization=Bearer {{response_token}}' \
  --auth
```

Upsert a group:

```sh
cargo run -- config group --config .secrets \
  --name default \
  --api-access projects:get:*
```

Add or update client with generated token on create:

```sh
cargo run -- config client --config .secrets \
  --name partner \
  --bearer-token-expires-at '2031-02-03' \
  --group default
```

That command prints generated bearer token once on create and persists only token metadata.

Rotate an existing client token:

```sh
cargo run -- config client rotate-secret --config .secrets \
  --name partner \
  --bearer-token-expires-at '2032-03-04'
```

That command prints replacement bearer token once, persists only replacement token metadata, and leaves existing client access rules unchanged. Update any local `GATE_AGENT_TOKEN` export to use replacement token after rotation.

Delete an API:

```sh
cargo run -- config api --config .secrets --name projects --delete
```

Delete fails when any group or inline client still references that API.

Delete a group:

```sh
cargo run -- config group --config .secrets --name default --delete
```

Delete fails when any client still references that group.

Delete a client:

```sh
cargo run -- config client --config .secrets --name partner --delete
```

Delete fails when target would leave config with no clients.

## Recommended local smoke test

```sh
cp .secrets.dev .secrets
docker compose up -d dummy-upstream
curl -i http://127.0.0.1:18081/healthz
cargo run -- start --config .secrets

export GATE_AGENT_TOKEN='default.s3cr3t'
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks

curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/dynamic-projects/projects/1/tasks

curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }' | jq
```

This verifies:

- the dummy upstream is running
- bearer-token auth is working
- proxy authorization is working
- upstream auth injection is working
- dynamic token acquisition and injection are working
- proxy path forwarding is working
- MCP direct bearer auth is working
- MCP tool discovery is working

## Direct upstream comparison

When debugging proxy behavior, compare the proxied request with a direct upstream request:

```sh
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

DYNAMIC_TOKEN=$(curl -sS http://127.0.0.1:18081/auth/token \
  -H 'Content-Type: application/json' \
  --data '{"client_id":"local-client","client_secret":"local-secret"}' \
  | jq -r .token)
curl -i -H "Authorization: Bearer $DYNAMIC_TOKEN" \
  http://127.0.0.1:18081/api/v2/projects/1/tasks
```

## Shutdown

```sh
docker compose down
```
