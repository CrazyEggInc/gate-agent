# Local testing environment

This document defines the local operator workflow.

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
- a local config file derived from `.secrets.example` or created with `config init`

## Dummy upstream

Expected properties:

- start with `docker compose up -d dummy-upstream`
- binds `127.0.0.1:18081` on the host
- health endpoint at `http://127.0.0.1:18081/healthz`
- protected API routes under `http://127.0.0.1:18081/api/...`
- direct protected requests require `Authorization: Bearer local-upstream-token`

## Local config

`.secrets.example` is the ready-to-run local sample.

Its committed bearer token metadata uses a long-lived sample expiry so the documented local flow does not quietly age out during normal development. If you create a fresh config instead, prefer `config init` and save the printed token immediately.

Expected local defaults:

- a `default` client is available
- `default` uses `group = "local-default"`
- `groups.local-default` grants `api_access = { projects = "read" }`
- the `projects` API points at the dummy upstream
- the `projects` API injects `Authorization: Bearer local-upstream-token` upstream

The committed sample config stores only bearer token metadata. For local testing, the matching bearer token is:

```sh
export GATE_AGENT_TOKEN='default.s3cr3t'
```

Typical setup:

```sh
cp .secrets.example .secrets
cargo run -- start --config .secrets --log-level info
```

Stdin-backed startup is also supported:

```sh
cat .secrets.example | cargo run -- start --log-level info
```

If you create a fresh config instead, `config init` prints the generated default bearer token once. Save it immediately; only the token id, hash, and expiry are persisted.

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
- the proxy injects upstream credentials from config before forwarding the request

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

That MCP smoke flow verifies:

- bearer-token auth on `/mcp`
- MCP JSON-RPC request handling
- effective API access exposure through `list_apis`
- upstream forwarding through `call_api`

If an MCP client such as Claude Code, Codex, or OpenCode supports configuring a fixed bearer `Authorization` header for an HTTP MCP server, point it at `http://127.0.0.1:8787/mcp` and use the same local bearer token directly. There is no separate local token exchange step for MCP.

Method access rules during local testing:

- `GET`, `HEAD`, `OPTIONS` require `read`
- `POST`, `PUT`, `PATCH`, `DELETE` require `write`
- any other HTTP method also requires `write`

## Config validation workflow

Path-backed example:

```sh
cargo run -- config validate --config .secrets
```

Stdin-backed example:

```sh
cat .secrets.example | cargo run -- config validate
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

Add a client with a generated token:

```sh
cargo run -- config add-client --config .secrets \
  --name partner \
  --bearer-token-expires-at '2031-02-03T04:05:06Z' \
  --api-access projects=read
```

That command prints the generated bearer token once and persists only its metadata.

## Recommended local smoke test

```sh
cp .secrets.example .secrets
docker compose up -d dummy-upstream
curl -i http://127.0.0.1:18081/healthz
cargo run -- start --config .secrets

export GATE_AGENT_TOKEN='default.s3cr3t'
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks

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
- proxy path forwarding is working
- MCP direct bearer auth is working
- MCP tool discovery is working

## Direct upstream comparison

When debugging proxy behavior, compare the proxied request with a direct upstream request:

```sh
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks
```

## Shutdown

```sh
docker compose down
```
