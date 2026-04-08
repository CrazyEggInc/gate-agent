# Configuration

This document describes the configuration feature as an operator-facing contract.

## Goal

The project must support a single runtime config file that is:

- easy to locate
- explicit to override
- safe to edit by hand
- writable by CLI commands
- strict enough to fail closed when malformed

## Config discovery

Read precedence:

1. `--config <path>`
2. `GATE_AGENT_CONFIG`
3. `./.secrets`
4. `~/.config/gate-agent/secrets`

Behavior:

- blank `--config` values are rejected
- blank `GATE_AGENT_CONFIG` is rejected
- read mode requires an existing file
- write/update mode falls back to `./.secrets` when nothing exists yet
- when nothing is found in read mode, the error reports the attempted paths
- home fallback is skipped when `HOME` is unset

## Config model

The config model must use these top-level tables:

- `[auth]`
- `[clients.<slug>]`
- `[apis.<slug>]`

Unknown fields must be rejected. Empty required strings must be rejected.

### `[auth]`

This section defines server-owned signing configuration.

Required fields:

- `issuer: String`
- `audience: String`
- `signing_secret: String`

All are required and must be non-empty. This section belongs to the server, not to individual clients.

### `[clients.<slug>]`

Each client entry defines how one client authenticates and what APIs it may request.

Required fields:

- `api_key: String`
- `api_key_expires_at: RFC3339 UTC timestamp`
- `allowed_apis: Vec<String>`

Validation expectations:

- client slug must be lowercase and contain only lowercase letters, digits, or hyphen
- `api_key` must be non-empty
- `api_key_expires_at` must be an RFC3339 UTC timestamp ending in `Z`
- allowed API slugs must be lowercase valid slugs
- duplicates in `allowed_apis` are rejected
- every allowed API must exist in `[apis.*]`

### `[apis.<slug>]`

Each API entry defines one upstream target plus the upstream credential that the proxy must inject.

Required fields:

- `base_url: String`
- `auth_header: String`
- `auth_scheme: Option<String>`
- `auth_value: String`
- `timeout_ms: u64`

Validation expectations:

- slug must be lowercase valid slug
- `base_url` must parse as a URL
- `auth_header` must parse as an HTTP header name
- required string fields must be non-empty
- `timeout_ms` must be greater than zero when written through CLI commands

## Operational expectations

At least one client is required.

The product must treat `clients.default` as the conventional local/dev client when a default client is needed.

`[apis]` may be empty in generated configs, but real proxy and exchange behavior remains fail-closed until APIs are added.

## Sample config

The committed `.secrets.example` is the runnable local/dev sample.

Expected shape:

```toml
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "local-dev-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "http://127.0.0.1:18081/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "local-upstream-token"
timeout_ms = 5000
```

## CLI-assisted config management

The product must support CLI commands that help initialize and update config without forcing operators to hand-author every field from scratch.

### `config init`

- resolves the target path using write precedence
- creates parent directories as needed
- writes a minimal config with:
  - generated signing secret
  - generated `clients.default.api_key`
  - generated `api_key_expires_at` about 180 days in the future
  - empty `allowed_apis`
  - empty `[apis]`

Generated secrets are hex-encoded bytes read from `/dev/urandom`.

This command must produce a minimal operator-owned starting point, not a fully configured production setup.

### `config add-api`

This command must accept:

- `--name`
- `--base-url`
- `--auth-header`
- `--auth-scheme`
- `--auth-value`
- `--timeout-ms`

Behavior:

- validates inputs before writing
- creates config if it does not exist yet
- upserts a single `[apis.<name>]` entry
- removes `auth_scheme` when omitted/blank
- keeps unrelated content and comments where possible

### `config add-client`

This command must accept:

- `--name`
- `--api-key`
- `--api-key-expires-at`
- repeated `--allowed-api`

Behavior:

- validates slug and timestamp inputs
- sorts and deduplicates allowed APIs before writing
- creates config if it does not exist yet
- preserves existing `api_key` and `api_key_expires_at` when omitted on update
- generates missing `api_key` / expiration when creating a new client without them
- does not verify that `allowed_apis` already exist in `[apis.*]` at write time; that is enforced by runtime config loading

## Mutation expectations

Config-writing commands must preserve unrelated structure and comments where possible rather than rewriting the file wholesale.

## Fail-closed parsing expectations

Runtime loading is stricter than CLI writing:

- at least one `[clients.*]` entry is required
- unknown fields are rejected
- client `allowed_apis` must refer to known `[apis.*]`
- malformed timestamps and invalid slugs are rejected during parse/load
