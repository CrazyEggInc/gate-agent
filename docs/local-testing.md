# Local testing environment

This document describes the local testing environment as a product workflow.

## Goal

The repository must provide a repeatable local environment for exercising:

- auth exchange
- proxy authorization
- upstream credential injection
- end-to-end requests through a local dummy upstream

## Components

The local testing environment consists of:

- the `gate-agent` process started with `cargo run -- start`
- the `dummy-upstream` service started with `docker compose`
- a local config file derived from `.secrets.example`
- the `cargo run -- curl ...` helper for generating `curl -K -` requests

## Dummy upstream

The local environment must provide a dummy upstream service named `dummy-upstream`.

Expected properties:

- it runs through `docker compose up -d dummy-upstream`
- it binds `127.0.0.1:18081` on the host
- it serves an open health endpoint at `http://127.0.0.1:18081/healthz`
- it serves protected API routes under `http://127.0.0.1:18081/api/...`
- direct requests to protected API routes require `Authorization: Bearer local-upstream-token`

The dummy upstream exists to validate proxy forwarding behavior and upstream auth injection without depending on a real internal service.

## Local config

The local testing flow must start from `.secrets.example`.

Expected local defaults:

- a `default` client is available for local use
- the `default` client has an API key suitable for local auth exchange
- the `projects` API points at the dummy upstream base URL
- the `projects` API injects `Authorization: Bearer local-upstream-token` upstream

Typical setup:

```sh
cp .secrets.example .secrets
```

The local proxy must then be started against that config file:

```sh
cargo run -- start --config .secrets --log-level info
```

Stdin-backed startup is also supported. When stdin contains non-whitespace config content, it overrides `--config`, `GATE_AGENT_CONFIG`, `./.secrets`, and the home fallback:

```sh
cat .secrets.example | cargo run -- start --log-level info
```

When local debugging needs proxy telemetry, rerun the server with `--log-level debug`. Debug logging should stay free of noisy `reqwest` or `hyper` connection chatter, while the normal proxy completion info log includes safe upstream request details.

Request completion logs also include `client_id` on every request. Successful auth and proxy requests record the authenticated client slug; unauthenticated failures log `client_id = "<unknown>"`.

## `curl` helper

The `curl` command is part of the local testing environment.

It must print curl config suitable for piping into `curl -K -`.

It supports two local workflows:

- auth exchange request generation
- proxied request generation

### Auth exchange workflow

The auth workflow must produce a request to `POST /auth/exchange` against the local proxy.

Example:

```sh
JWT_TOKEN=$(
  cargo run --quiet -- curl --auth --client default --log-level warn | curl -s -K - | jq -r '.access_token'
)
```

This flow is used to obtain a short-lived JWT for subsequent proxy requests.

`--client` selects which configured client performs the auth exchange. When omitted, the command uses `default`.

### Proxy workflow

The proxy workflow must produce a request to `/proxy/{api}{path}` against the local proxy.

Example:

```sh
cargo run -- curl --jwt "$JWT_TOKEN" --api projects --path /v1/projects/1/tasks --log-level warn | curl -K -
```

Expected behavior:

- the request targets the configured local bind address
- the request carries `Authorization: Bearer <jwt>` to the proxy
- the proxy authorizes access to the requested API slug
- the proxy injects upstream credentials from config before forwarding the request

### Config validation workflow

Operators can verify runtime config loading before starting the server.

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
- validation uses the same strict parser and source-resolution behavior as `start`

## Recommended local smoke test

The standard local smoke test must be:

```sh
cp .secrets.example .secrets
docker compose up -d dummy-upstream
curl -i http://127.0.0.1:18081/healthz
cargo run -- start --config .secrets

JWT_TOKEN=$(
  cargo run --quiet -- curl --auth --client default | curl -s -K - | jq -r '.access_token'
)

cargo run -- curl --jwt "$JWT_TOKEN" --api projects --path /v1/projects/1/tasks | curl -K -
```

This verifies:

- the dummy upstream is running
- auth exchange is working
- JWT-based proxy authorization is working
- upstream auth injection is working
- proxy path forwarding is working

For telemetry-focused debugging, rerun the server as `cargo run -- start --config .secrets --log-level debug` and repeat the proxy request. Confirm the proxy completion info log includes the safe upstream fields and that dependency debug chatter from `reqwest` or `hyper` does not appear.

## Direct upstream comparison

When debugging proxy behavior, operators may compare proxied requests with direct upstream requests.

Example direct request:

```sh
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks
```

This isolates whether a failure is in:

- the dummy upstream itself
- proxy auth exchange
- proxy authorization
- proxy request mapping

## Shutdown

The dummy upstream must be stoppable with:

```sh
docker compose down
```
