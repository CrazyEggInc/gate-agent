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

## `start`

The `start` command must accept:

- `--bind <addr>`
- `--config <path>`
- `--log-level <level>`

Behavior:

- loads runtime config using the shared config resolution rules
- validates that the selected config exists and parses correctly
- constructs runtime state
- binds the requested listener
- starts serving HTTP traffic

## `curl`

The `curl` command is a developer/operator helper command. It must print curl config suitable for `curl -K -`.

It must accept:

- `--bind <addr>`
- `--config <path>`
- `--log-level <level>`
- `--client <slug>` (default `default`)
- `--auth`
- `--proxy`
- `--jwt <token>`
- `--api <slug>`
- `--path <path>`

It must use the same config-resolution behavior as `start`.

Mode rules:

- `--auth` selects auth mode
- `--proxy` selects proxy mode
- proxy mode is the default when no mode flag is supplied
- `--auth` and `--proxy` are mutually exclusive

### Auth mode

Workflow:

```sh
cargo run -- curl --auth --client default | curl -K -
```

Behavior:

- loads config using the same config-path logic as `start`
- selects the configured client by slug using `--client`
- uses `default` when `--client` is omitted
- rejects unknown clients
- rejects clients with no `allowed_apis`
- rejects combinations that also provide `--jwt`, `--api`, or `--path`
- prints a `POST /auth/exchange` request with:
  - `x-api-key`
  - `content-type: application/json`
  - JSON body containing all allowed APIs for the client

### Proxy mode

Workflow:

```sh
cargo run -- curl --jwt "$JWT_TOKEN" --api projects --path /v1/projects/1/tasks | curl -K -
```

Behavior:

- requires `--jwt`, `--api`, and `--path`
- rejects empty `--jwt`, `--api`, and `--path` values after trimming
- rejects paths that do not start with `/`
- rejects unknown API slugs
- prints a request to `http://{bind}/proxy/{api}{path}`
- sets `Authorization: Bearer <jwt>`

### Invalid combinations

The CLI must fail fast on invalid combinations.

- `--auth` cannot be combined with `--proxy`, `--jwt`, `--api`, or `--path`
- without `--auth`, missing `--jwt`, `--api`, or `--path` is an error

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
- invalid values fail command startup instead of silently falling back

## `--help`

The CLI must rely on built-in `--help` output instead of a separate help command.

Operators must be able to discover the command surface from the root command and then drill into subcommands with `--help`.

Examples:

```sh
cargo run -- --help
cargo run -- start --help
cargo run -- curl --help
cargo run -- config --help
cargo run -- config init --help
cargo run -- config add-api --help
cargo run -- config add-client --help
```

## `config`

The subcommands must be:

- `config init`
- `config add-api`
- `config add-client`

Each config subcommand must also accept `--log-level <level>` with the same application-only verbosity semantics used by `start` and `curl`.

See `docs/config.md` for detailed config command semantics.

## Exit behavior

CLI commands must return success on success, and on failure they must print a human-readable error to stderr and exit non-zero.
