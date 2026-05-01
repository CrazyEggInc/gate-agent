# gate-agent

`gate-agent` is a small proxy designed to hide authentication information from callers.

## Why this exists

- clients authenticate to `gate-agent`, not directly to upstream APIs
- upstream credentials stay in server-side config
- bearer tokens are simple to issue and rotate
- config is file-based, explicit, and easy to inspect
- agentic coding tools can call these APIs without knowing the actual remote API credentials

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
  --api-access "cats:get:*"

gate-agent start

export GATE_AGENT_TOKEN='<token from config init>'
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  'http://127.0.0.1:8787/proxy/cats/images/search?limit=10'
```

## MCP client setup

`gate-agent` also works as an MCP server for your preferred agentic tool. You can configure it as either a remote or local MCP server.

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

## Deployment modes

You can use `gate-agent` as a local tool, or deploy it to a remote server to make it available to others. In that scenario, set up a separate client token for each user. The example [Dockerfile](examples/docker/Dockerfile) installs `gate-agent` and starts it with [start.sh](examples/docker/start.sh). Update the script for your own environment. For example, you could make it fetch configuration from your preferred secrets service.

## Example API configurations

See [examples/apis.toml](examples/apis.toml) for sample upstream API configurations.

## Development example with a test server

```sh
# setup local files and dummy upstream
cp .secrets.dev .secrets
docker compose up -d dummy-upstream

# smoke test the dummy upstream
curl -i http://127.0.0.1:18081/healthz
curl -i -H 'Authorization: Bearer local-upstream-token' \
  http://127.0.0.1:18081/api/v1/projects/1/tasks

# use cargo only for local development
cargo run -- start --config=.secrets --log-level=debug
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings

# start gate-agent
cargo run -- start --config=.secrets --log-level=info

# call example upstream api
export GATE_AGENT_TOKEN='default.s3cr3t'
curl -i -H "Authorization: Bearer $GATE_AGENT_TOKEN" \
  http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks

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

See `docs/local-testing.md` for the full local workflow.

## Release process

1. run GitHub Actions workflow `prepare release` with `dry_run=true`
2. re-run `prepare release` with `dry_run=false` to bump Cargo metadata and create tag `vX.Y.Z` or `vX.Y.Z-prerelease`
3. let the dispatched `release` workflow validate, build, checksum, and publish assets
4. verify latest and pinned install commands against the published release

See `docs/release.md` for release assets, checksum behavior, retries, and recovery.
