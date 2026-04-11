# gate-agent

`gate-agent` is a small local proxy for calling internal upstream APIs through one operator-managed interface.

## Why this exists

- clients authenticate to `gate-agent`, not directly to upstream APIs
- upstream credentials stay in server-side config
- bearer tokens are simple to issue and rotate
- config is file-based, explicit, and easy to inspect

## Quick local flow

```sh
# setup local files and dummy upstream
cp .secrets.example .secrets
docker compose up -d dummy-upstream

# smoke test the dummy upstream
curl -i http://127.0.0.1:18081/healthz
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

# start gate-agent
cargo run -- start --config .secrets --log-level info

# call gate-agent with the sample local bearer token
export GATE_AGENT_TOKEN='default.s3cr3t'
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks
```

If you create a fresh config with `cargo run -- config init`, the command prints the default client bearer token once. Save it then; the config file only stores the token id, hash, and expiry.

See `docs/local-testing.md` for the full local workflow and `docs/pending.md` for intentionally deferred work.

## Development

```sh
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```
