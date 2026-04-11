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
```

This verifies:

- the dummy upstream is running
- bearer-token auth is working
- proxy authorization is working
- upstream auth injection is working
- proxy path forwarding is working

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
