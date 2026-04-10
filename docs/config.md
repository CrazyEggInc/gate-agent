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
- `allowed_apis: Vec<String>`

Validation expectations:

- client slug must be lowercase and contain only lowercase letters, digits, or hyphen
- `api_key` must be non-empty
- `api_key_expires_at` must be an RFC3339 UTC timestamp ending in `Z`
- allowed API slugs must be lowercase valid slugs
- duplicates in `allowed_apis` are rejected
- every allowed API must exist in `[apis.*]`

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
  - empty `allowed_apis`
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
- repeated `--allowed-api`

Behavior:

- validates slug and timestamp inputs
- sorts and deduplicates allowed APIs before writing
- creates config if it does not exist yet
- preserves existing `api_key` and `api_key_expires_at` when omitted on update
- generates missing `api_key` / expiration when creating a new client without them
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt without writing new keyring entries
- does not verify that `allowed_apis` already exist in `[apis.*]` at write time; that is enforced by runtime config loading

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
- client `allowed_apis` must refer to known `[apis.*]`
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
