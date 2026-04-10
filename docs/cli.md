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
- `config add-client`

Each config subcommand accepts `--log-level <level>`.

`config show`, `config edit`, `config add-api`, and `config add-client` use the shared encrypted-config password lookup order.

### `config init`

Accepted flags:

- `--config <path>`
- `--encrypted`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- fails if the target file already exists
- defaults to `~/.config/gate-agent/secrets` when no explicit path is supplied and `HOME` is available
- writes plaintext TOML unless `--encrypted` is supplied
- creates a minimal config with no `[auth]` table
- creates `clients.default` with generated bearer token metadata and an expiry about 180 days in the future
- prints the generated default client bearer token once
- persists only `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- when encrypted init succeeds, stores that password in the keyring for the selected config path

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
- `--auth-scheme`
- `--auth-value`
- optional `--timeout-ms`

Behavior:

- creates config if it does not exist yet
- upserts a single API entry
- preserves encrypted-vs-plaintext format on update

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
- if the client does not already exist, the command generates a bearer token and prints it once
- if the client already exists, existing token metadata is preserved unless a future rotation workflow changes it
- if the config file does not exist yet and `--password` is supplied, the bootstrap config is created encrypted
- the plaintext bearer token is never persisted
- persisted client fields use `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`

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
cargo run -- config add-client --help
```

## Exit behavior

- successful commands exit zero
- `config validate` prints structured JSON errors on invalid config
- other failures print a human-readable error to stderr and exit non-zero
