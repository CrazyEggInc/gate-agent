# gate-agent

`gate-agent` is a small proxy for calling internal upstream APIs through a single local interface.

## Why this exists

It is meant to stay boring and easy to operate:

- clients authenticate to `gate-agent`, not directly to upstream APIs
- upstream API secrets stay in server-side config
- the CLI is simple and usable for local development and operator workflows
- it works both on a local machine and on servers
- configuration is intentionally simple and file-based

## Quick local flow

```sh
# setup dev server
cp .secrets.example .secrets
docker compose up -d dummy-upstream

# smoke test the local api
curl -i http://127.0.0.1:18081/healthz
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

# start gate-agent
cargo run -- start --config .secrets --log-level debug

# call apis using gate-agent
JWT_TOKEN=$(
  cargo run --quiet -- curl --auth --client default | curl -s -K - | jq -r '.access_token'
)

cargo run --quiet -- curl --jwt "$JWT_TOKEN" --api projects --path /v1/projects/1/tasks | curl -K -
```

The dummy upstream health check stays open at `http://127.0.0.1:18081/healthz`.

For the full local testing workflow, including the `curl` helper and `dummy-upstream`, see `docs/local-testing.md`.

For deferred future work that is intentionally not implemented yet, see `docs/pending.md`.

For implementation details, config semantics, and auth internals, see `AGENTS.md`.

## Development

```sh
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```
