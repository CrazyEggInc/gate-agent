# gate-agent

`gate-agent` is a small local proxy for calling internal upstream APIs through one operator-managed interface.

## Why this exists

- clients authenticate to `gate-agent`, not directly to upstream APIs
- upstream credentials stay in server-side config
- bearer tokens are simple to issue and rotate
- config is file-based, explicit, and easy to inspect

## Install

```sh
VERSION="$(awk -F ' *= *' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' Cargo.toml)"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET=linux-x64 ;;
  Darwin-arm64) TARGET=macos-arm64 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

ARCHIVE="gate-agent-v${VERSION}-${TARGET}.tar.gz"
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

## Quickstart

```sh
gate-agent config init
# Save the generated secret/token printed by init.

# Register for a free TheCatAPI key.
export THE_CAT_API_KEY='<thecatapi key>'

gate-agent config api \
  --name cats \
  --base-url https://api.thecatapi.com/v1 \
  --header "x-api-key=$THE_CAT_API_KEY"

gate-agent config group \
  --name local-default \
  --api-access cats=read

gate-agent start

export GATE_AGENT_TOKEN='<token from config init>'
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  'http://127.0.0.1:8787/proxy/cats/images/search?limit=10'
```

## MCP client setup

Use one of these config shapes.

### MCP Remote Config (recommended)

Use this after the server is already running through `gate-agent start`.

```json
{
  "gate-agent": {
    "url": "http://127.0.0.1:8787/mcp",
    "headers": {
      "Authorization": "Bearer <your-token>"
    }
  }
}
```

### MCP Command Config

Less safe: `GATE_AGENT_PASSWORD` must be hardcoded in the client config.

```json
{
  "gate-agent": {
    "command": "gate-agent",
    "args": ["start"],
    "env": {
      "GATE_AGENT_CONFIG": "~/.config/gate-agent/secrets",
      "GATE_AGENT_PASSWORD": "<your-config-password>"
    }
  }
}
```

## Development

Use Cargo only for repo-local development:

```sh
cargo run -- start --config=.secrets --log-level=debug
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

### Example with a test server

Uses the committed sample config and dummy api server.

```sh
# setup local files and dummy upstream
cp .secrets.example .secrets
docker compose up -d dummy-upstream

# smoke test the dummy upstream
curl -i http://127.0.0.1:18081/healthz
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

# start gate-agent
cargo run -- start --config=.secrets --log-level=info

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

## Release process

1. update `version = "..."` in `Cargo.toml`
2. merge that change to `master`
3. create tag `vX.Y.Z` from the same commit
4. let GitHub Actions build and publish release artifacts from that tag
