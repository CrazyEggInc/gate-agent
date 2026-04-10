# Configuration

This document describes the configuration feature as an operator-facing contract.

## Goal

The project must support a single runtime config file that is:

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

- non-empty piped stdin overrides every file-based source
- attached non-terminal stdin is checked without blocking when no bytes are immediately available; once stdin config bytes begin arriving, the loader continues reading until EOF before parsing
- empty or whitespace-only piped stdin is ignored
- blank `--config` values are rejected
- blank `GATE_AGENT_CONFIG` is rejected
- read mode requires an existing file
- write/update mode falls back to `~/.config/gate-agent/secrets` when `HOME` is available and no explicit path or existing file was selected
- write/update mode falls back to `./.secrets` only when `HOME` is unavailable
- when nothing is found in read mode, the error reports the attempted paths
- home fallback is skipped when `HOME` is unset

## Config file formats

The product must support two on-disk config formats at the same path:

- plaintext TOML
- ASCII-armored `age` passphrase-encrypted content

Format detection is content-based:

- files starting with `-----BEGIN AGE ENCRYPTED FILE-----` are treated as encrypted
- all other files are treated as plaintext TOML

The file extension does not change the parsing mode.

`.secrets.example` remains plaintext.

## Password sources

When a command operates on an encrypted config, password precedence must be:

1. `--password` / `-p`
2. `GATE_AGENT_PASSWORD`
3. system keyring entry for the selected config path
4. interactive prompt

Behavior:

- blank `--password` is rejected
- blank `GATE_AGENT_PASSWORD` is rejected
- each config path is looked up separately in the system keyring, so different config files keep separate stored passwords
- keyring lookup is best-effort; if the stored password cannot be read, commands continue to the remaining fallback path instead of failing only because keyring access had a problem
- on Linux, the system keyring backend is explicitly pinned to the native keyutils path instead of relying on `keyring` crate defaults
- prompting is only attempted for encrypted configs, or for `config init --encrypted`
- non-interactive sessions must fail with a clear error when an encrypted config needs a password and neither flag, env var, nor readable keyring entry is available
- plaintext configs ignore password inputs
- when a flag, env var, or prompted password successfully decrypts an encrypted config, that password is cached into the system keyring for that config path
- when a cached keyring password fails to decrypt the file, the stale keyring entry is removed automatically

## Config model

The config model must use these top-level tables:

- `[auth]`
- `[groups.<slug>]`
- `[clients.<slug>]`
- `[apis.<slug>]`

Unknown fields must be rejected. Empty required strings must be rejected.

### `[auth]`

This section defines server-owned signing configuration.

Required fields:

- `issuer: String`
- `audience: String`
- `signing_secret: String`

### `[clients.<slug>]`

Required fields:

- `api_key: String`
- `api_key_expires_at: RFC3339 UTC timestamp`
- exactly one of:
  - `group: String`
  - `api_access: { <api-slug> = "read" | "write", ... }`

Validation expectations:

- client slug must be lowercase and contain only lowercase letters, digits, or hyphen
- `api_key` must be non-empty
- `api_key_expires_at` must be an RFC3339 UTC timestamp ending in `Z`
- clients must declare exactly one of `group` or `api_access`
- `group` must reference an existing `[groups.<slug>]`
- `api_access` keys must be lowercase valid API slugs
- `api_access` values must be `read` or `write`
- every referenced API must exist in `[apis.*]`

### `[groups.<slug>]`

Each group entry defines a reusable API access map that clients can reference.

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

- slug must be lowercase valid slug
- `base_url` must parse as a URL
- `auth_header` must parse as an HTTP header name
- required string fields must be non-empty
- omitted `timeout_ms` falls back to `5000`
- `timeout_ms` must be greater than zero when explicitly provided or written through CLI commands

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
group = "local-default"

[groups.local-default]
api_access = { projects = "read" }

[groups.partner-readonly]
api_access = { projects = "read" }

[clients.partner]
api_key = "partner-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
group = "partner-readonly"

[apis.projects]
base_url = "http://127.0.0.1:18081/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "local-upstream-token"
timeout_ms = 5000
```

## CLI-assisted config management

### `config init`

- resolves the target path using write precedence
- when no `--config` or `GATE_AGENT_CONFIG` is set, defaults to `~/.config/gate-agent/secrets` when `HOME` is available
- fails if the target file already exists
- creates parent directories as needed
- writes a minimal config with:
  - generated signing secret
  - generated `clients.default.api_key`
  - generated `api_key_expires_at` about 180 days in the future
  - empty `api_access = {}`
  - empty `[groups]`
  - empty `[apis]`

Generated secrets are hex-encoded bytes read from `/dev/urandom`.

When `--encrypted` is supplied:

- the generated config is encrypted immediately
- the password is resolved using the standard password precedence
- interactive prompting must ask twice and require an exact match
- after a successful encrypted init, the chosen password is stored in the system keyring for that config path
- if keyring storage fails during encrypted init, the command fails instead of silently leaving a half-configured stored-password setup

Other encrypted-config commands may read a stored keyring password for the selected config path, but they must never write or backfill keyring entries silently.

### `config show`

- resolves the target path using read precedence
- prints plaintext TOML to stdout
- decrypts first when the selected file is encrypted
- when the selected file is encrypted, password resolution follows flag → env → keyring → prompt
- is intentionally a sharp tool because it reveals secrets in plaintext output

### `config edit`

- resolves the target path using read precedence
- uses `VISUAL` first, then `EDITOR`
- fails if neither editor variable is set
- plaintext configs are edited in place
- encrypted configs are decrypted to a temporary file, edited, validated, then re-encrypted and atomically written back
- when the selected file is encrypted, password resolution follows flag → env → keyring → prompt
- if validation fails, the original encrypted config must remain untouched
- if the editor exits non-zero, the original file must remain untouched

### `config add-api`

This command must accept:

- `--name`
- `--base-url`
- `--auth-header`
- `--auth-scheme`
- `--auth-value`

Behavior:

- validates inputs before writing
- creates config if it does not exist yet
- upserts a single `[apis.<name>]` entry
- removes `auth_scheme` when omitted or blank
- uses `5000` when `--timeout-ms` is omitted
- keeps unrelated content and comments where possible
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt without writing new keyring entries

### `config add-client`

This command must accept:

- `--name`
- `--api-key`
- `--api-key-expires-at`
- `--group <slug>`
- repeated `--api-access <api=level[,api=level...]>`

Behavior:

- validates slug and timestamp inputs
- requires exactly one of `--group` or `--api-access`
- `--group` must be a valid slug
- `--api-access` accepts `read` and `write`
- repeated `--api-access` flags are merged
- comma-separated entries inside one `--api-access` flag are supported
- conflicting duplicate `api=level` entries fail
- inline `api_access` is written in stable order
- creates config if it does not exist yet
- preserves existing `api_key` and `api_key_expires_at` when omitted on update
- generates missing `api_key` / expiration when creating a new client without them
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt without writing new keyring entries
- writes either `group = "..."` or `api_access = { ... }` and removes the opposite field on update
- does not verify that referenced APIs already exist in `[apis.*]` at write time; that is enforced by runtime config loading

## Mutation expectations

Config-writing commands must preserve unrelated structure and comments where possible rather than rewriting the file wholesale.

Encrypted updates still follow that rule by:

1. decrypting to TOML in memory
2. editing TOML
3. serializing TOML
4. re-encrypting the whole file
5. atomically replacing the original file

## Fail-closed parsing expectations

Runtime loading is stricter than CLI writing:

- at least one `[clients.*]` entry is required
- unknown fields are rejected
- clients must declare exactly one of `group` or `api_access`
- client and group `api_access` entries must refer to known `[apis.*]`
- malformed timestamps and invalid slugs are rejected during parse/load

## `config validate`

`config validate` is the operator-facing way to check whether a config would load at runtime.

Behavior:

- uses the same config loading behavior as `start`, including non-empty stdin override
- uses the same strict parser and runtime validation rules as `start`
- prints `config is valid` on success
- prints a JSON error payload to stderr on invalid config and exits non-zero

Error shape:

```json
{
  "errors": [
    {
      "message": "..."
    }
  ]
}
```
