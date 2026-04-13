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

# initialize MCP over HTTP
curl -i http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {}
  }'

# list MCP tools
curl -sS http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }' | jq

# list APIs available to the authenticated client
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

# call an upstream API through MCP
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

If you create a fresh config with `cargo run -- config init`, the command prints the default client bearer token once. Save it then; the config file only stores the token id, hash, and expiry.

See `docs/local-testing.md` for the full local workflow, `docs/mcp.md` for the MCP contract, and `docs/pending.md` for intentionally deferred work.

## Development

```sh
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```
