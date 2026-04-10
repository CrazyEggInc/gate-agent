# CLI

This document describes the CLI as a feature contract.

## Goal

The CLI must support three jobs:

- start the local proxy
- help operators manage config
- make local auth/proxy workflows straightforward to exercise

## Top-level commands

The top-level commands must be:

- `start`
- `curl`
- `config`

Command discovery must use built-in `--help` on the root command and on subcommands.

## Shared encrypted-config flags

Commands that may read encrypted config files must accept:

- `--password <value>`
- `-p <value>`

Supported env var:

- `GATE_AGENT_PASSWORD`

Password precedence is:

1. `--password` / `-p`
2. `GATE_AGENT_PASSWORD`
3. system keyring entry for the selected config path
4. interactive prompt

Runtime commands and config commands that read an existing encrypted config must automatically check the keyring after flag/env lookup and before prompting.

If an encrypted config needs a password in a non-interactive session and neither flag, env var, nor keyring entry is available, the command must fail non-zero.

When an encrypted config is successfully opened with a password from flag, env var, or prompt, that password is cached into the system keyring for that config path. If a cached keyring password later fails to decrypt the file, the stale keyring entry is removed automatically.

## `start`

The `start` command must accept:

- `--bind <addr>`
- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- loads runtime config using the shared config resolution rules
- when stdin is piped and begins providing any non-whitespace bytes, loads config from stdin instead of `--config`, `GATE_AGENT_CONFIG`, `./.secrets`, or `~/.config/gate-agent/secrets`
- ignores piped stdin when it is empty or whitespace-only, then falls back to normal path resolution
- prompts for a password only when the selected config is encrypted and no password flag, env var, or keyring entry is available
- validates that the selected config exists and parses correctly
- constructs runtime state
- binds the requested listener
- starts serving HTTP traffic

## `curl`

The `curl` command must accept:

- `--bind <addr>`
- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--client <slug>` (default `default`)
- `--auth`
- `--proxy`
- `--jwt <token>`
- `--api <slug>`
- `--path <path>`

It must use the same config-resolution and encrypted-config behavior as `start`.

For encrypted file-backed config, that means `curl` must try flag, env var, and keyring before falling back to an interactive prompt.

## `config`

The subcommands must be:

- `config init`
- `config validate`
- `config show`
- `config edit`
- `config add-api`
- `config add-client`

Each config subcommand must accept `--log-level <level>`.

`config validate`, `config show`, `config edit`, `config add-api`, and `config add-client` must use the shared encrypted-config password lookup order: flag, env var, keyring, then prompt.

Those commands may read a password from the keyring, but they must never create or update keyring entries as a side effect.

### `config init`

Must accept:

- `--config <path>`
- `--encrypted`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- fails if the target file already exists
- when no `--config` or `GATE_AGENT_CONFIG` is supplied, targets `~/.config/gate-agent/secrets` when `HOME` is available
- when `--encrypted` is absent, writes plaintext TOML
- when `--encrypted` is present, writes encrypted config and confirms interactive passwords by double entry
- when `--encrypted` is present, accepts the shared password flag/env inputs for the initial password choice
- when encrypted init succeeds, stores that password in the system keyring for the selected config path
- only this explicit encrypted init flow may store credentials in the keyring; later runtime and config reads may reuse the stored password but must not silently backfill it

### Auth mode

Behavior:

- loads config using the same config-path logic as `start`
- selects the configured client by slug using `--client`
- uses `default` when `--client` is omitted
- rejects unknown clients
- rejects clients with no `api_access`
- rejects combinations that also provide `--jwt`, `--api`, or `--path`
- prints a `POST /auth/exchange` request with:
  - `x-api-key`
  - `content-type: application/json`
  - JSON body containing the client effective API access map

Auth payload shape:

```json
{
  "apis": {
    "projects": "read",
    "billing": "write"
  }
}
```

Client access for auth mode comes from the effective runtime config:

- inline `api_access = { ... }`, or
- a referenced `group = "..."`

### Proxy mode

Behavior:

- requires `--jwt`, `--api`, and `--path`
- rejects empty `--jwt`, `--api`, and `--path` values after trimming
- rejects paths that do not start with `/`
- rejects unknown API slugs
- prints a request to `http://{bind}/proxy/{api}{path}`
- sets `Authorization: Bearer <jwt>`

### `config show`

Must accept:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- prints plaintext TOML to stdout
- decrypts first when the config is encrypted

### `config edit`

Must accept:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`

Behavior:

- uses `VISUAL` first, then `EDITOR`
- fails clearly if no editor is configured
- plaintext config files are edited in place
- encrypted config files are decrypted, edited, validated, then re-encrypted and atomically replaced

### `config add-api`

Must accept:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--base-url`
- `--auth-header`
- `--auth-scheme`
- `--auth-value`

`--timeout-ms` is optional and defaults to `5000`.

### `config add-client`

Must accept:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--api-key`
- `--api-key-expires-at`
- `--group <slug>`
- repeated `--api-access <api=level[,api=level...]>`

Rules:

- exactly one of `--group` or `--api-access` is required
- `--group` and `--api-access` are mutually exclusive
- `--api-access` accepts `read` and `write`
- repeated `--api-access` flags are merged
- one flag may contain comma-separated pairs such as `--api-access projects=read,billing=write`

## Logging control

The CLI must expose `--log-level <level>` as application verbosity control.

Expected values:

- `warn`
- `info`
- `debug`

Behavior:

- the selected level applies to `gate-agent` application logs
- dependency targets stay at warning and error output only
- the flag is not raw tracing filter syntax
- invalid values fail command startup and do not silently fall back

## `--help`

The CLI must rely on built-in `--help` output instead of a separate help command.

Examples:

```sh
cargo run -- --help
cargo run -- start --help
cargo run -- curl --help
cargo run -- config --help
cargo run -- config init --help
cargo run -- config validate --help
cargo run -- config show --help
cargo run -- config edit --help
cargo run -- config add-api --help
cargo run -- config add-client --help
```

## Exit behavior

CLI commands must return success on success.

Failure output is split by command behavior:

- `config validate` exits non-zero and prints a JSON error payload to stderr when the selected config is invalid
- other CLI failures print a human-readable error to stderr and exit non-zero
