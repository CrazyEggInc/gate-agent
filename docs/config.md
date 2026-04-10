# Configuration

This document defines the operator-facing config contract.

## Goal

The runtime config must be:

- easy to locate
- explicit to override
- safe to edit by hand
- writable by CLI commands
- strict enough to fail closed when malformed
- optionally encrypted at rest with an operator-supplied password

## Config discovery

Read precedence:

1. non-empty piped stdin
2. `--config <path>`
3. `GATE_AGENT_CONFIG`
4. `./.secrets`
5. `~/.config/gate-agent/secrets`

Behavior:

- non-empty piped stdin overrides file-based sources
- empty or whitespace-only piped stdin is ignored
- blank `--config` and blank `GATE_AGENT_CONFIG` are rejected
- read mode requires an existing file
- write/update mode falls back to `~/.config/gate-agent/secrets` when `HOME` is available
- when nothing is found in read mode, the error reports attempted paths

## Config file formats

The same path may contain either:

- plaintext TOML
- ASCII-armored `age` passphrase-encrypted content

Detection is content-based. File extension does not control parsing mode.

## Password sources

For encrypted configs, password precedence is:

1. `--password` / `-p`
2. `GATE_AGENT_PASSWORD`
3. system keyring entry for the selected config path
4. interactive prompt

Behavior:

- blank flag and env passwords are rejected
- plaintext configs ignore password inputs
- non-interactive sessions fail clearly when an encrypted config needs a password and none is available
- successful decrypts cache the password in the keyring for that config path
- stale cached passwords are removed automatically when they stop decrypting the file

## Runtime config model

The runtime config has these top-level tables:

- `[groups.<slug>]`
- `[clients.<slug>]`
- `[apis.<slug>]`

There is no `[auth]` table in the runtime config contract.

Unknown fields are rejected. Empty required strings are rejected.

### `[clients.<slug>]`

Required fields:

- `bearer_token_id: String`
- `bearer_token_hash: String`
- `bearer_token_expires_at: RFC3339 UTC timestamp`
- exactly one of:
  - `group: String`
  - `api_access: { <api-slug> = "read" | "write", ... }`

Validation expectations:

- client slug must be lowercase and contain only lowercase letters, digits, or hyphen
- `bearer_token_id` must be non-empty
- `bearer_token_hash` must be non-empty
- `bearer_token_expires_at` must be an RFC3339 UTC timestamp ending in `Z`
- clients must declare exactly one of `group` or `api_access`
- `group` must reference an existing `[groups.<slug>]`
- `api_access` keys must be lowercase valid API slugs
- `api_access` values must be `read` or `write`
- every referenced API must exist in `[apis.*]`
- duplicate `bearer_token_id` values across clients are rejected

Token storage contract:

- operators use bearer tokens on the wire in the form `<token_id>.<secret>`
- config files never persist the plaintext bearer token
- config files persist only `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`

### `[groups.<slug>]`

Each group defines a reusable API access map.

Required fields:

- `api_access: { <api-slug> = "read" | "write", ... }`

Validation expectations:

- group slug must be lowercase and contain only lowercase letters, digits, or hyphen
- unknown fields are rejected
- `api_access` keys must be lowercase valid API slugs
- `api_access` values must be `read` or `write`
- every referenced API must exist in `[apis.*]`

### `[apis.<slug>]`

Required fields:

- `base_url: String`
- `auth_header: String`
- `auth_scheme: Option<String>`
- `auth_value: String`
- `timeout_ms: u64 | omitted`

Validation expectations:

- slug must be a valid lowercase slug
- `base_url` must parse as a URL
- `auth_header` must parse as an HTTP header name
- required string fields must be non-empty
- omitted `timeout_ms` falls back to `5000`
- explicit `timeout_ms` must be greater than zero

## Operational expectations

- at least one client is required
- `clients.default` is the conventional local/dev client
- generated configs may start with empty `[groups]` and `[apis]`

## Sample config

`.secrets.example` is the runnable local/dev sample:

```toml
[groups.local-default]
api_access = { projects = "read" }

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2036-10-08T12:00:00Z"
group = "local-default"

[apis.projects]
base_url = "http://127.0.0.1:18081/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "local-upstream-token"
timeout_ms = 5000
```

For the committed sample config, the matching local bearer token is `default.s3cr3t`.

## CLI-assisted config management

### `config init`

Behavior:

- resolves the target path using write precedence
- fails if the target file already exists
- creates parent directories as needed
- writes a minimal config with:
  - generated `clients.default` bearer token metadata
  - generated `bearer_token_expires_at` about 180 days in the future
  - empty `api_access = {}` for `clients.default`
  - empty `[groups]`
  - empty `[apis]`
- prints the generated default client bearer token once to stdout
- persists only the token id, hash, and expiry

When `--encrypted` is supplied:

- the generated config is encrypted immediately
- password resolution follows the standard password precedence
- interactive prompting asks twice and requires an exact match
- successful encrypted init stores the password in the system keyring for that config path

### `config show`

- resolves the target path using read precedence
- prints plaintext TOML to stdout
- decrypts first when the selected file is encrypted

### `config edit`

- resolves the target path using read precedence
- uses `VISUAL` first, then `EDITOR`
- fails if neither editor variable is set
- plaintext configs are edited in place
- encrypted configs are decrypted to a temporary file, edited, validated, then re-encrypted and atomically written back

### `config add-api`

Accepted flags:

- `--name`
- `--base-url`
- `--auth-header`
- `--auth-scheme`
- `--auth-value`
- optional `--timeout-ms`

Behavior:

- validates inputs before writing
- creates config if it does not exist yet
- upserts one `[apis.<name>]` entry
- removes `auth_scheme` when omitted or blank
- uses `5000` when `--timeout-ms` is omitted
- preserves encrypted-vs-plaintext format on update

### `config add-client`

Accepted flags:

- `--name`
- `--bearer-token-expires-at`
- `--group <slug>`
- repeated `--api-access <api=level[,api=level...]>`

Behavior:

- validates slug and timestamp inputs
- requires exactly one of `--group` or `--api-access`
- `--api-access` accepts `read` and `write`
- repeated `--api-access` flags are merged
- creates config if it does not exist yet
- if the client does not already exist, a bearer token is generated and printed once
- if the client already exists, existing token metadata is preserved
- if `--password` is supplied while bootstrapping a missing config, the new config is created encrypted
- if a config must be created first, the generated default client token is also printed once
- plaintext bearer tokens are never persisted
- writes either `group = "..."` or `api_access = { ... }` and removes the opposite field on update
- referenced APIs are validated at runtime load, not at write time

## Fail-closed parsing expectations

Runtime loading is stricter than ad-hoc file editing:

- at least one `[clients.*]` entry is required
- unknown fields are rejected
- clients must declare exactly one of `group` or `api_access`
- client and group `api_access` entries must refer to known `[apis.*]`
- malformed timestamps and invalid slugs are rejected during parse/load

## `config validate`

`config validate` checks whether a config would load at runtime.

Behavior:

- uses the same config loading behavior as `start`, including non-empty stdin override
- uses the same strict parser and runtime validation rules as `start`
- prints `config is valid` on success
- prints a JSON error payload to stderr on invalid config and exits non-zero
