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
- write/update mode resolves the target in this order: `--config`, `GATE_AGENT_CONFIG`, existing `./.secrets`, existing `~/.config/gate-agent/secrets`, otherwise a new `~/.config/gate-agent/secrets` when `HOME` is available, else a new `./.secrets`
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
- encrypted init does not store the password in the keyring
- encrypted init removes any existing cached keyring password for that config path
- successful encrypted reads may backfill the keyring for that config path
- stale cached passwords are removed automatically when they stop decrypting the file

## Runtime config model

The runtime config has these top-level tables:

- `[server]`
- `[groups.<slug>]`
- `[clients.<slug>]`
- `[apis.<slug>]`

There is no `[auth]` table in the runtime config contract.

Unknown fields are rejected. Empty required strings are rejected.

### `[server]`

Optional fields:

- `bind: String | omitted`
- `port: u16 | omitted`

Validation and default expectations:

- `bind`, when present, must be a non-empty bindable host/interface string
- `port`, when present, must be greater than zero
- omitted `bind` falls back to `127.0.0.1`
- omitted `port` falls back to `8787`
- configs that omit the entire `[server]` table remain valid and use those same defaults at runtime

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
- `auth_header: Option<String>`
- `auth_value: Option<String>`
- `timeout_ms: u64 | omitted`
- `description: Option<String>`
- `docs_url: Option<String>`
- `auth_scheme: Option<String>`

Validation expectations:

- slug must be a valid lowercase slug
- `base_url` must parse as a URL
- `auth_header`, when present, must parse as an HTTP header name
- `auth_value` is required when `auth_header` is present
- `auth_value` must be omitted when `auth_header` is omitted
- when `auth_header` is omitted, no upstream auth header is injected
- bearer-style auth is stored as the full header value in `auth_value`, for example `Bearer my-token`
- optional `description`, when present, must be non-empty
- optional `docs_url`, when present, must parse as a URL and use `http` or `https`
- omitted `timeout_ms` falls back to `5000`
- explicit `timeout_ms` must be greater than zero
- the parser accepts legacy `auth_scheme` on read, composes it into the in-memory `auth_value`, and rewrites config without persisting `auth_scheme`

## Operational expectations

- at least one client is required
- `clients.default` is the conventional local/dev client
- generated configs may start with empty group access maps and empty `[apis]`

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
auth_value = "Bearer local-upstream-token"
timeout_ms = 5000
```

For the committed sample config, the matching local bearer token is `default.s3cr3t`.

This sample is intentionally distinct from fresh `config init` output. `.secrets.example` is committed as runnable local/dev config, so it includes `projects = "read"` together with `[apis.projects]` and relies on runtime defaults for omitted optional fields like `[server]`. Fresh init bootstraps same group-backed shape but writes explicit `[server]`, keeps `groups.local-default.api_access = {}`, and leaves `[apis]` empty until operator adds APIs and access rules.

## CLI-assisted config management

### `config init`

Behavior:

- resolves the target path using write precedence
- when `--config` is omitted in an interactive session, prompts for the config path and defaults that prompt to the resolved write target
- when no `--config` or `GATE_AGENT_CONFIG` is set outside the questionnaire flow, uses the resolved write target
- interactive prompts stay on a single line and keep the wording minimal, using only the question plus inline `(default: ...)`, `(example: ...)`, or `(options: ...)` details when helpful
- fails if the target file already exists
- creates parent directories as needed
- writes a minimal config with:
  - explicit `[server]` settings for bind and port
  - explicit `[groups]` with `[groups.local-default]`
  - `groups.local-default.api_access = {}`
  - generated `clients.default` bearer token metadata
  - generated `bearer_token_expires_at` about 180 days in the future
  - `clients.default.group = "local-default"`
  - empty `[apis]`
- prints the generated default client bearer token once to stdout
- persists only the token id, hash, and expiry
- when bind or port is not supplied explicitly in an interactive session, prompts for:
  - `Server bind (default: 127.0.0.1; remote setups should use 0.0.0.0)`
  - `Server port (default: 8787)`
- when bind or port is not supplied outside the questionnaire flow, uses the same defaults and writes them explicitly into `[server]`

Fresh init keeps `groups.local-default.api_access = {}` empty on purpose. New configs start with no `[apis.*]`, so granting `projects = "read"` there would point at an API that does not exist yet and would fail runtime validation. That differs from `.secrets.example`, which is committed with populated sample API definitions and matching sample access.

- when `--encrypted` is omitted in an interactive session, prompts whether to encrypt the file and defaults that choice to yes
- explicit `--config`, `--encrypted`, and password inputs keep the command non-interactive for those decisions

When encryption is enabled:

- the generated config is encrypted immediately
- initial password resolution uses `--password`, then `GATE_AGENT_PASSWORD`, then an interactive prompt
- interactive prompting asks twice and requires an exact match
- encrypted init leaves the keyring empty for that config path and removes any stale cached password

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
- `--auth-value`
- optional `--timeout-ms`

Behavior:

- validates inputs before writing
- creates config if it does not exist yet
- upserts one `[apis.<name>]` entry
- persists `auth_header` only when upstream auth injection is configured
- persists `auth_value` only when `auth_header` is present
- persists bearer-style auth as the full header value in `auth_value`, for example `Bearer my-token`
- when `auth_header` is omitted, writes no upstream auth fields and injects no upstream auth header at runtime
- uses `5000` when `--timeout-ms` is omitted
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt without writing new keyring entries
- explicit args keep the command non-interactive
- when required operator input is missing in an interactive session, prompts for it instead of failing immediately in a single-line format with minimal wording

Interactive questionnaire flow:

- `API name:`
- `Base URL (example: https://projects.internal.example/api):`
- `Auth header (default: authorization, use 'none' for no auth):`
- `Auth value (example: Bearer my-token):` only when auth header was set

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
- if the client does not already exist, a bearer token is generated and printed once so the operator can capture it
- if the client already exists, existing bearer token metadata is preserved and no plaintext bearer token is reprinted
- if `--password` is supplied while bootstrapping a missing config, the new config is created encrypted
- if a config must be created first, the generated default client token is also printed once
- plaintext bearer tokens are never persisted
- writes either `group = "..."` or `api_access = { ... }` and removes the opposite field on update
- referenced APIs are validated at runtime load, not at write time
- does not verify that referenced APIs already exist in `[apis.*]` at write time; that is enforced by runtime config loading
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt without writing new keyring entries
- when required operator input is missing in an interactive session, prompts for it instead of failing immediately
- the access prompt shows existing group slugs as available options when any exist
- the operator may enter a group slug directly or leave that prompt blank to fall back to inline `api_access`
- prompts stay single-line and avoid extra descriptive text when the question itself is already clear
- explicit args keep the command non-interactive

### `config add-group`

This command manages `[groups.<slug>]` entries directly.

Behavior:

- accepts a group name plus repeated `--api-access <api=level[,api=level...]>`
- prompts for the name and inline `api_access` when that required input is missing in an interactive session, in a single-line format with minimal wording
- creates config if it does not exist yet
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt without writing new keyring entries
- explicit args keep the command non-interactive

## Mutation expectations

Config-writing commands must preserve unrelated structure and comments where possible rather than rewriting the file wholesale.

Encrypted updates still follow that rule by:

1. decrypting to TOML in memory
2. editing TOML
3. serializing TOML
4. re-encrypting the whole file
5. atomically replacing the original file

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
