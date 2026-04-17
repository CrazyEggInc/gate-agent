# gate-agent

`gate-agent` is a small local proxy for calling internal upstream APIs through one operator-managed interface.

## Why this exists

- clients authenticate to `gate-agent`, not directly to upstream APIs
- upstream credentials stay in server-side config
- bearer tokens are simple to issue and rotate
- config is file-based, explicit, and easy to inspect

## Install

Download a release binary from GitHub Releases and put `gate-agent` on your `PATH`.

Use one archive name:

- Linux: `gate-agent-v${VERSION}-linux-x64.tar.gz`
- macOS Apple Silicon: `gate-agent-v${VERSION}-macos-arm64.tar.gz`

```sh
VERSION=1.2.3
ARCHIVE="gate-agent-v${VERSION}-linux-x64.tar.gz"
CHECKSUMS="gate-agent-v${VERSION}-sha256sums.txt"

curl -L -O \
  "https://github.com/CrazyEggInc/gate-agent/releases/download/v${VERSION}/${CHECKSUMS}"
curl -L -O \
  "https://github.com/CrazyEggInc/gate-agent/releases/download/v${VERSION}/${ARCHIVE}"

if command -v shasum >/dev/null 2>&1; then
  grep " ${ARCHIVE}\$" "${CHECKSUMS}" | shasum -a 256 -c -
else
  grep " ${ARCHIVE}\$" "${CHECKSUMS}" | sha256sum --check -
fi

tar -xzf "${ARCHIVE}"
install gate-agent /usr/local/bin/gate-agent
```

## Quick local flow

Assumes `gate-agent` is already installed.

```sh
# setup local files and dummy upstream
cp .secrets.example .secrets
docker compose up -d dummy-upstream

# smoke test the dummy upstream
curl -i http://127.0.0.1:18081/healthz
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

# start gate-agent
gate-agent start --config .secrets --log-level info

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

If you create a fresh config with `gate-agent config init`, the command prints the default client bearer token once. Save it then; the config file only stores the token id, hash, and expiry.

See `docs/local-testing.md` for the full local workflow, `docs/mcp.md` for the MCP contract, and `docs/pending.md` for intentionally deferred work.

## Development

Use Cargo only for repo-local development:

```sh
cargo run -- start --config .secrets --log-level debug
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Release process

1. update `version = "..."` in `Cargo.toml`
2. merge that change to `master`
3. create tag `vX.Y.Z` from the same commit
4. let GitHub Actions build and publish release artifacts from that tag
