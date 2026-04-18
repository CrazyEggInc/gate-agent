# CLI

This document defines the operator-facing CLI contract.

## Goal

The CLI supports three jobs:

- start the local proxy
- manage config files
- print build version metadata

## Top-level commands

The top-level commands are:

- `start`
- `config`
- `version`

Command discovery uses built-in `--help` on the root command and subcommands.

## Shared encrypted-config flags

Commands that may read encrypted config files accept:

- `--password <value>`
- `-p <value>`

Supported env var:

- `GATE_AGENT_PASSWORD`

Password precedence is:

1. `--password` / `-p`
2. `GATE_AGENT_PASSWORD`
3. system keyring entry for the selected config path
4. interactive prompt

If an encrypted config needs a password in a non-interactive session and none is available, the command fails non-zero.

Encrypted read expectations:

- passphrase-encrypted `age` config reads support standard CLI `age` passphrase files in ASCII-armored or binary form
- encrypted reads reject files whose scrypt work factor exceeds gate-agent supported maximum; current maximum is `30`
- wrong-password failures stay concise
- unsupported `age` modes, malformed or corrupted encrypted files, and excessive scrypt work factors return specific operator-facing errors

## `start`

Accepted flags:

- `--bind <addr>`
- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- loads runtime config using the shared config resolution rules
- prefers non-empty piped stdin over file-backed config sources
- prompts only when the selected config is encrypted and no password flag, env var, or keyring entry is available
- validates config before starting
- when `--bind` is provided explicitly, uses that address as the listener override
- when `--bind` is omitted, uses `[server].bind` and `[server].port` from config
- configs without `[server]` remain valid and fall back to `127.0.0.1:8787`
- binds the requested listener and serves HTTP traffic

## `config`

Subcommands:

- `config init`
- `config validate`
- `config show`
- `config edit`
- `config add-api`
- `config add-group`
- `config add-client`
- `config rotate-client-secret`

Each config subcommand accepts `--log-level <level>`.

`config show`, `config edit`, `config add-api`, `config add-group`, `config add-client`, and `config rotate-client-secret` must use the shared encrypted-config password lookup order: flag, env var, keyring, then prompt.

Successful encrypted reads may backfill the password in the system keyring for that config path, and later encrypted reads may reuse that cached password through the same lookup order.

Cached passwords that no longer decrypt the selected config are removed automatically.

### `config init`

Accepted flags:

- `--config <path>`
- `--encrypted`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- fails if the target file already exists
- when `--config` is omitted in an interactive session, asks for the path and defaults that prompt to the resolved write target: `--config`, `GATE_AGENT_CONFIG`, existing `./.secrets`, existing `~/.config/gate-agent/secrets`, otherwise a new `~/.config/gate-agent/secrets` when `HOME` is available, else a new `./.secrets`
- when `--config` is omitted outside the questionnaire flow, uses that same resolved write target
- when `--encrypted` is omitted in an interactive session, asks whether to encrypt and defaults that prompt to yes
- interactive prompts stay on a single line and keep the wording minimal, using only the question plus inline `(default: ...)`, `(example: ...)`, or `(options: ...)` details when helpful
- when `--encrypted` is absent outside the questionnaire flow, writes plaintext TOML
- creates a minimal config with no `[auth]` table
- writes an explicit `[server]` section with bind and port
- when server bind and port are not provided explicitly in an interactive session, asks:
  - `Server bind (default: 127.0.0.1; remote setups should use 0.0.0.0)`
  - `Server port (default: 8787)`
- when server bind and port are not provided outside the questionnaire flow, writes `127.0.0.1` and `8787`
- creates `clients.default` with generated bearer token metadata and an expiry about 180 days in the future
- prints the generated default client bearer token once for operator capture
- persists only `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- when encryption is enabled, writes encrypted config and confirms interactive passwords by double entry
- when encryption is enabled, resolves the initial password from `--password`, then `GATE_AGENT_PASSWORD`, then an interactive prompt
- when encrypted init succeeds, leaves the system keyring empty for the selected config path and removes any stale cached password for that path
- later successful encrypted reads may also backfill the password for that config path, and later encrypted reads may reuse cached passwords through the standard lookup order
- explicit args keep the command non-interactive for those inputs

### `config validate`

Accepted flags:

- `--config <path>`
- `--log-level <level>`

Behavior:

- validates the selected config using the same rules as `start`
- prints `config is valid` on success
- prints a JSON error payload to stderr and exits non-zero on failure

### `config show`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- prints plaintext TOML to stdout
- decrypts first when the config is encrypted, for both ASCII-armored and binary `age` files

### `config edit`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- uses `VISUAL` first, then `EDITOR`
- fails clearly if no editor is configured
- plaintext config files are edited in place
- encrypted config files are decrypted, edited, validated, then re-encrypted and atomically replaced

### `config add-api`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--base-url`
- `--auth-header`
- `--auth-value`
- optional `--timeout-ms`

Behavior:

- creates config if it does not exist yet
- when creating a missing config, also bootstraps `clients.default`
- when that bootstrap happens, prints `Generated token for client 'default': <token>` to stdout exactly once so operators and scripts can capture it
- upserts a single API entry
- persists only `auth_header` and `auth_value`; `auth_scheme` is not part of the persisted API config model
- `auth_header` is optional
- `auth_value` is required when `auth_header` is configured and must be omitted otherwise
- when `auth_header` is omitted, no upstream auth header is configured or injected
- bearer-style auth uses the full header value in `auth_value`, for example `Bearer my-token`
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password lookup follows flag, env var, keyring, then prompt
- successful decrypts from flag, env var, or prompt backfill the system keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- if required fields are omitted in an interactive session, the command prompts for them in a single-line format with minimal wording
- the interactive questionnaire asks exactly:
  - `API name:`
  - `Base URL (example: https://projects.internal.example/api):`
  - `Auth header (default: authorization, use 'none' for no auth):`
  - `Auth value (example: Bearer my-token):` only when auth header was set
- explicit args keep the command non-interactive

### `config add-group`

Must accept:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- repeated `--api-access <api=level[,api=level...]>`

Behavior:

- creates config if it does not exist yet
- when creating a missing config, also bootstraps `clients.default`
- when that bootstrap happens, prints `Generated token for client 'default': <token>` to stdout exactly once so operators and scripts can capture it
- upserts a single group entry
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password lookup follows flag, env var, keyring, then prompt
- successful decrypts from flag, env var, or prompt backfill the system keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- if required fields are omitted in an interactive session, the command prompts for the group name and access map in a single-line format with minimal wording
- explicit args keep the command non-interactive

### `config add-client`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--bearer-token-expires-at`
- `--group <slug>`
- repeated `--api-access <api=level[,api=level...]>`

Rules and behavior:

- exactly one of `--group` or `--api-access` is required
- `--group` and `--api-access` are mutually exclusive
- `--api-access` accepts `read` and `write`
- repeated `--api-access` flags are merged
- if `--bearer-token-expires-at` is supplied, it must use the exact UTC form `YYYY-MM-DDTHH:MM:SSZ`
- one flag may contain comma-separated pairs such as `--api-access projects=read,billing=write`
- when required fields are omitted in an interactive session, the command prompts for them
- when groups already exist, the group prompt shows those slugs as available options so the operator can pick one or type one directly
- leaving the group prompt blank falls back to prompting for inline `api_access`
- prompts stay single-line and avoid extra descriptive text when the question itself is already clear
- if the client does not already exist, the command generates a bearer token and prints it once for operator capture
- if the client already exists, existing token metadata is preserved unless a future rotation workflow changes it
- if the config file does not exist yet and `--password` is supplied, the bootstrap config is created encrypted
- when creating a missing config, also bootstraps `clients.default`
- when that bootstrap happens, prints `Generated token for client 'default': <token>` to stdout exactly once so operators and scripts can capture it
- the plaintext bearer token is never persisted
- persisted client fields use `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- when updating an encrypted config, password lookup follows flag, env var, keyring, then prompt
- successful decrypts from flag, env var, or prompt backfill the system keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- explicit args keep the command non-interactive

### `config rotate-client-secret`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--bearer-token-expires-at`

Rules and behavior:

- rotates credentials for one existing client only
- fails if config file does not already exist
- fails if target client does not already exist
- when required fields are omitted in an interactive session, the command prompts for the client name
- if `--bearer-token-expires-at` is supplied, it must use the exact UTC form `YYYY-MM-DDTHH:MM:SSZ`
- if `--bearer-token-expires-at` is omitted, existing expiry is preserved exactly
- rotation generates a brand-new bearer token and replaces persisted `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- existing `group` or inline `api_access` stays unchanged
- the replacement bearer token is printed to stdout exactly once for operator capture
- the previous bearer token is never reprinted
- the plaintext bearer token is never persisted
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password lookup follows flag, env var, keyring, then prompt
- successful decrypts from flag, env var, or prompt backfill the system keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- explicit args keep the command non-interactive

## `version`

Accepted flags:

- none

Behavior:

- prints the exact build version string to stdout followed by a trailing newline
- writes nothing to stderr on success
- exits zero on success
- does not read config
- does not write config
- does not prompt
- does not contact upstream services

## Logging control

The CLI exposes `--log-level <level>` as application verbosity control.

Expected values:

- `warn`
- `info`
- `debug`

Invalid values fail startup.

## `--help`

The CLI must rely on built-in `--help` output instead of a separate help command.

Operator-facing examples use the compiled `gate-agent` binary. In a repo-local development checkout, `cargo run --` is the equivalent prefix.

Examples:

```sh
gate-agent --help
gate-agent start --help
gate-agent config --help
gate-agent version --help
gate-agent config init --help
gate-agent config validate --help
gate-agent config show --help
gate-agent config edit --help
gate-agent config add-api --help
gate-agent config add-group --help
gate-agent config add-client --help
gate-agent config rotate-client-secret --help
gate-agent version
```

## Exit behavior

- successful commands exit zero
- `version` success means exact version string on stdout, empty stderr, and exit code `0`
- `config validate` prints structured JSON errors on invalid config
- other failures print a human-readable error to stderr and exit non-zero
