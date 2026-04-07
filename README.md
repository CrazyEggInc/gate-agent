# gate-agent

Local Rust proxy MVP for calling internal upstream APIs through a localhost listener. It validates HS256 bearer JWTs, maps the lowercase `api` claim to an upstream in `.secrets`, injects the configured upstream auth header, and forwards the captured `/proxy/...` suffix verbatim.

## Quickstart

```sh
# Copy the sample secrets file
cp .secrets.example .secrets

# Start the dummy test service
docker compose up -d dummy-upstream

# Sanity check the dummy upstream
curl -i http://127.0.0.1:18081/healthz

# Sanity check an authenticated dummy upstream API path
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

# Sanity check the streaming dummy upstream API path
curl -N -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks/stream

# Start the gate-agent proxy
cargo run -- start --secrets-file .secrets

# Test proxied GET request
cargo run -- curl-payload --api projects --path /v1/projects/1/tasks | curl -K -

# Test proxied POST request
cargo run -- curl-payload --api projects --path /v1/projects/1/tasks \
  | curl -K - -X POST -H 'Content-Type: application/json' --data '{"name":"New task"}'
  
# Test streaming request
cargo run -- curl-payload --api projects --path /v1/projects/1/tasks/stream | curl -K -

# Stop the dummy test service when done
docker compose down
```

`curl-payload` is a local testing helper. It emits a `curl -K -` config with the local proxy URL and a short-lived bearer token signed from the current `.secrets` JWT settings.

The dummy upstream health check is open at `/healthz`. API routes under `/api/...` expect `Authorization: Bearer local-upstream-token` on direct requests. The dummy service also exposes `/api/v1/projects/1/tasks/stream` as an NDJSON streaming path. Client JWT auth is only for the proxy; the proxy injects the upstream bearer auth from `.secrets`.

## `.secrets` shape

See `.secrets.example` for the committed template.

```toml
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.projects]
base_url = "http://127.0.0.1:18081/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "local-upstream-token"
timeout_ms = 5000
```

## Development

Prereqs: Rust toolchain from `rust-toolchain.toml`.

```sh

# Run the usual Rust checks
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```
