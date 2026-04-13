# CLI

This document defines the operator-facing CLI contract.

## Goal

The CLI supports two jobs:

- start the local proxy
- manage config files

## Top-level commands

The top-level commands are:

- `start`
- `config`

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

Each config subcommand accepts `--log-level <level>`.

`config show`, `config edit`, `config add-api`, `config add-group`, and `config add-client` must use the shared encrypted-config password lookup order: flag, env var, keyring, then prompt.

`config show` and `config edit` write the resolved password back to the keyring after a successful encrypted read via `remember_password_if_needed()`, so operators can trace that side effect to the implementation.

`config add-api`, `config add-group`, and `config add-client` may read a password from the keyring, but they do not create or update keyring entries as a side effect.

### `config init`

Accepted flags:

- `--config <path>`
- `--encrypted`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- fails if the target file already exists
- when `--config` is omitted in an interactive session, asks for the path and defaults that prompt to `~/.config/gate-agent/secrets` when `HOME` is available
- when `--config` is omitted outside the questionnaire flow, targets `~/.config/gate-agent/secrets` when `HOME` is available
- when `--encrypted` is omitted in an interactive session, asks whether to encrypt and defaults that prompt to yes
- interactive prompts stay on a single line and keep the wording minimal, using only the question plus inline `(default: ...)`, `(example: ...)`, or `(options: ...)` details when helpful
- when `--encrypted` is absent outside the questionnaire flow, writes plaintext TOML
- creates a minimal config with no `[auth]` table
- creates `clients.default` with generated bearer token metadata and an expiry about 180 days in the future
- prints the generated default client bearer token once for operator capture
- persists only `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- when encryption is enabled, writes encrypted config and confirms interactive passwords by double entry
- when encryption is enabled, accepts the shared password flag/env inputs for the initial password choice
- when encrypted init succeeds, stores that password in the system keyring for the selected config path
- only this explicit encrypted init flow may store credentials in the keyring; later runtime and config reads may reuse the stored password but must not silently backfill it
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
- decrypts first when the config is encrypted

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
- explicit args keep the command non-interactive

## Logging control

The CLI exposes `--log-level <level>` as application verbosity control.

Expected values:

- `warn`
- `info`
- `debug`

Invalid values fail startup.

## `--help`

Examples:

```sh
cargo run -- --help
cargo run -- start --help
cargo run -- config --help
cargo run -- config init --help
cargo run -- config validate --help
cargo run -- config show --help
cargo run -- config edit --help
cargo run -- config add-api --help
cargo run -- config add-group --help
cargo run -- config add-client --help
```

## Exit behavior

- successful commands exit zero
- `config validate` prints structured JSON errors on invalid config
- other failures print a human-readable error to stderr and exit non-zero
