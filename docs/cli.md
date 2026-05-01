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

- `--bind <host:port>` (for example, `0.0.0.0:8787`)
- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>` (`warn`, `info`, or `debug`)

Behavior:

- loads runtime config using the shared config resolution rules
- prefers non-empty piped stdin over file-backed config sources
- prompts only when the selected config is encrypted and no password flag, env var, or keyring entry is available
- validates config before starting
- when `--bind` is provided explicitly, uses that full socket address as the listener override
- when `--bind` is omitted, uses `[server].bind` and `[server].port` from config
- configs without `[server]` remain valid and fall back to `127.0.0.1:8787`
- binds the requested listener and serves HTTP traffic

## `config`

Subcommands:

- `config init`
- `config validate`
- `config show`
- `config edit`
- `config api`
- `config group`
- `config client`
- `config client rotate-secret`

Each config subcommand accepts `--log-level <level>`.

`config show`, `config edit`, `config api`, `config group`, `config client`, and `config client rotate-secret` must use the shared encrypted-config password lookup order: flag, env var, keyring, then prompt.

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

### `config api`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--base-url`
- `--basic-auth`
- repeated `--header <name=value>` (for example, `--header x-api-key=secret`)
- optional `--timeout-ms`
- `-d` / `--delete`

Behavior:

- creates config if it does not exist yet
- when creating a missing config, also bootstraps `clients.default`
- when that bootstrap happens, prints `Generated token for client 'default': <token>` to stdout exactly once so operators and scripts can capture it
- adds or updates one API entry by name
- `-d` / `--delete` deletes one existing API entry instead of add-or-update
- `config api` runs the optional interactive questionnaire only when no API-management flags are supplied
- API-management flags include `--name`, `--base-url`, any `--header`, `--timeout-ms`, and `--delete`
- when any API-management flag is supplied, omitted flags are treated as non-interactive omissions and preserve existing values on update
- `--basic-auth` selects upstream Basic auth mode and still prompts for credentials because the flag explicitly requests that auth flow
- `--basic-auth` selects upstream Basic auth mode and always triggers credential prompts, so it is not fully non-interactive
- `--basic-auth` fails non-zero in non-interactive sessions when credential prompts cannot run
- each `--header` value must use `<name>=<value>` format, for example `x-api-key=secret`
- repeated `--header` flags replace the stored upstream header map with exactly the provided headers for that invocation, subject to auth-mode rules below
- repeated `--header` still manages generic upstream headers
- bearer-style usage uses full value inside one repeated flag, for example `--header authorization=Bearer my-token`
- `--basic-auth` rejects same invocation when provided headers include `authorization`
- creating a new API with omitted `--header` writes no headers
- in non-interactive update mode, omitted `--header` preserves existing headers instead of clearing them
- when switching auth modes without `--header`, existing non-authorization headers are preserved
- when one or more `--header` values are supplied during an auth-mode switch, the stored header map is first replaced by the provided headers, then `headers.authorization` is removed if the selected auth mode does not allow it
- in interactive create or when no headers are configured yet, leaving headers blank means no headers
- in interactive update, blank headers answer keeps current headers
- interactive prompt accepts `none` to clear headers
- there is no separate non-interactive clear flag for headers
- interactive blank answers keep defaults
- switching auth modes preserves non-auth headers unless replacement `--header` values are supplied
- normal interactive flow asks for headers before optional Basic auth setup
- after headers, CLI offers optional Basic auth setup
- enabling Basic auth removes only `headers.authorization`; unrelated headers stay
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password lookup follows flag, env var, keyring, then prompt
- successful decrypts from flag, env var, or prompt backfill the system keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- interactive name prompts are labeled `Existing Apis`, list existing API names as plain `<name>` values for up/down selection, and include an `add new api` entry; selecting an existing API opens an action prompt with `edit`, `delete`, and `cancel`; selecting `add new api` asks for the new name
- selecting the add-new entry prompts for the name afterward
- when updating interactively, current values become prompt defaults; blank answers keep those defaults
- if required fields are omitted in an interactive create flow, the command prompts for them in a single-line format with minimal wording
- in non-interactive update mode, omitted flags preserve existing values instead of clearing them
- non-interactive delete requires explicit `--name`
- interactive delete asks with destructive wording that says the action cannot be undone and defaults to No
- the interactive questionnaire asks exactly:
  - `API name:`
  - `Base URL (example: https://projects.internal.example/api):`
  - `Headers (example: x-api-key=secret; leave empty for no headers):`
- after headers, the questionnaire offers optional Basic auth setup
- when Basic auth is enabled, the questionnaire also asks for Basic auth username and password on single lines using current stored username as default when available
- on create, blank Basic auth password stores empty password
- on create, entering `none` as Basic auth password stores username-only Basic auth without a `password` key
- on update, blank Basic auth password clears the stored `password` key and keeps the username
- on update, entering `none` as Basic auth password also clears the stored `password` key and keeps the username
- any other Basic auth password text stores that text as `basic_auth.password`
- existing Basic auth password prompt includes `blank clears existing password; enter password to keep or change`
- new Basic auth password prompt includes `blank stores empty password; enter 'none' for username-only basic auth`
- explicit API-management args skip the optional questionnaire; `--basic-auth` always prompts for credentials and therefore is not fully non-interactive

### `config group`

Must accept:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- repeated `--api-access <api:method:path[,method:path...]>` (for example, `--api-access projects:get:*`)
- `-d` / `--delete`

Behavior:

- creates config if it does not exist yet
- when creating a missing config, also bootstraps `clients.default`
- when that bootstrap happens, prints `Generated token for client 'default': <token>` to stdout exactly once so operators and scripts can capture it
- adds or updates one group entry by name
- `-d` / `--delete` deletes one existing group entry instead of add-or-update
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password lookup follows flag, env var, keyring, then prompt
- successful decrypts from flag, env var, or prompt backfill the system keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- interactive name prompts are labeled `Existing Groups`, list existing group names as plain `<name>` values for up/down selection, and include an `add new group` entry; selecting an existing group opens an action prompt with `edit`, `delete`, and `cancel`; selecting `add new group` asks for the new name
- selecting the add-new entry prompts for the name afterward
- when updating interactively, current values become prompt defaults; blank answers keep those defaults
- if required fields are omitted in an interactive create flow, the command prompts for the group name and access map in a single-line format with minimal wording
- each `--api-access` value accepts one API slug followed by one or more `method:path` route rules, for example `projects:get:*`
- repeated `--api-access` flags are merged across API slugs
- one flag may contain comma-separated route rules for one API, such as `--api-access projects:get:*,post:/projects`; use another flag for another API, such as `--api-access billing:*:*`
- in non-interactive update mode, omitted flags preserve existing values instead of clearing them
- non-interactive delete requires explicit `--name`
- interactive delete asks with destructive wording that says the action cannot be undone and defaults to No
- explicit args keep the command non-interactive

### `config client`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--bearer-token-expires-at <YYYY-MM-DD>` (for example, `2026-01-01`)
- `--group <slug>`
- repeated `--api-access <api:method:path[,method:path...]>` (for example, `--api-access projects:get:*`)
- `-d` / `--delete`

Rules and behavior:

- exactly one of `--group` or `--api-access` is required when creating a client
- `--group` and `--api-access` are mutually exclusive
- `--api-access` accepts one API slug followed by one or more `method:path` route rules, where `method` is an HTTP verb or `*` and `path` is `*` or a path starting with `/`
- repeated `--api-access` flags are merged across API slugs
- if `--bearer-token-expires-at` is supplied, it must use date-only form `YYYY-MM-DD`, for example `2026-01-01`; the stored expiry uses midnight UTC for that date
- one flag may contain comma-separated route rules for one API, such as `--api-access projects:get:*,post:/projects`; use another flag for another API, such as `--api-access billing:*:*`
- adds or updates one client entry by name
- `-d` / `--delete` deletes one existing client entry instead of add-or-update
- interactive name prompts are labeled `Existing Clients`, list existing client names as plain `<name>` values for up/down selection, and include an `add new client` entry; selecting an existing client opens an action prompt with `edit`, `delete`, and `cancel`; selecting `add new client` asks for the new name
- selecting the add-new entry prompts for the name afterward
- when updating interactively, current values become prompt defaults; blank answers keep those defaults
- when required fields are omitted in an interactive create flow, the command prompts for them; API access prompts are labeled `Api access` and list existing APIs as `<api> (edit permissions)` plus `Done`, then each API's rule screen offers `Add new rule`, existing rules as delete actions, and `Go back`
- in the interactive client flow, the CLI asks for `Access mode` before prompting for `Group name`
- when groups already exist, the `Group name` prompt references those slugs as plain `<name>` values for up/down selection and includes an `add new group` entry; choosing `add new group` asks for the group name and group `api_access` before writing the client reference
- `Group name` is required when `Access mode` is `group`; a blank response fails instead of falling back to inline `api_access`
- prompts stay single-line and avoid extra descriptive text when the question itself is already clear
- when adding a new client interactively, `Bearer token expiration` defaults to a date about six months in the future and expects `YYYY-MM-DD`
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
- in non-interactive update mode, omitted flags preserve existing values instead of clearing them
- non-interactive delete requires explicit `--name`
- interactive delete asks with destructive wording that says the action cannot be undone and defaults to No
- explicit args keep the command non-interactive

### `config client rotate-secret`

Accepted flags:

- `--config <path>`
- `--password <value>` / `-p <value>`
- `--log-level <level>`
- `--name`
- `--bearer-token-expires-at <YYYY-MM-DD>` (for example, `2026-01-01`)

Rules and behavior:

- rotates credentials for one existing client only
- fails if config file does not already exist
- fails if target client does not already exist
- when required fields are omitted in an interactive session, the command prompts for the client name with an up/down selector of existing clients
- if `--bearer-token-expires-at` is supplied, it must use date-only form `YYYY-MM-DD`, for example `2026-01-01`; the stored expiry uses midnight UTC for that date
- if `--bearer-token-expires-at` is omitted, existing expiry is preserved exactly and used as the interactive default when rotating an existing client
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
gate-agent config api --help
gate-agent config group --help
gate-agent config client --help
gate-agent config client rotate-secret --help
gate-agent version
```

## Exit behavior

- successful commands exit zero
- `version` success means exact version string on stdout, empty stderr, and exit code `0`
- `config validate` prints structured JSON errors on invalid config
- other failures print a human-readable error to stderr and exit non-zero
