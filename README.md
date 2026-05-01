# gate-agent

`gate-agent` is a small proxy designed to hide authentication information from callers.

## Why this exists

- clients authenticate to `gate-agent`, not directly to upstream APIs
- upstream credentials stay in server-side config
- bearer tokens are simple to issue and rotate
- config is file-based, explicit, and easy to inspect
- agentic coding tools can call these apis without knowing the actual remote api credentials

## Install

Install the latest published release:

```sh
curl -fsSL https://raw.githubusercontent.com/CrazyEggInc/gate-agent/refs/heads/master/install.sh | sh
```

Install a pinned release or custom install directory by setting environment variables:

```sh
curl -fsSL https://raw.githubusercontent.com/CrazyEggInc/gate-agent/refs/heads/master/install.sh | VERSION=1.2.3 GATE_AGENT_INSTALL_DIR="$HOME/.local/bin" sh
```

The installer defaults to `~/.local/bin` and adds it to your shell `PATH` when needed.

## Local usage quickstart

We'll setup a remote integration with https://thecatapi.com as an example (you can register for a free key to test).

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
  --name default \
  --api-access cats:get:*

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

# call gate-agent with the sample local bearer token and broad local projects access
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

1. run GitHub Actions workflow `prepare release` with `dry_run=true`
2. re-run `prepare release` with `dry_run=false` to bump Cargo metadata and create tag `vX.Y.Z` or `vX.Y.Z-prerelease`
3. let the dispatched `release` workflow validate, build, checksum, and publish assets
4. verify latest and pinned install commands against the published release

See `docs/release.md` for release assets, checksum behavior, retries, and recovery.
