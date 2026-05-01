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
- binary `age` passphrase-encrypted content

Detection is content-based. File extension does not control parsing mode.

Encrypted read expectations:

- passphrase-encrypted `age` reads support standard CLI `age` passphrase files in ASCII-armored or binary form
- encrypted reads reject files whose scrypt work factor exceeds gate-agent supported maximum; current maximum is `30`
- encrypted writes use scrypt work factor `10` unless `GATE_AGENT_ENCRYPTION_FACTOR` is set

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
- wrong-password decrypt failures stay concise and operator-facing
- unsupported `age` modes, malformed or corrupted encrypted files, and excessive scrypt work factors return specific operator-facing decrypt errors

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
  - `api_access: { <api-slug> = [{ method = "<method>|*", path = "<path>|*" }, ...], ... }`, `api_access = []`, or `api_access = [{ <api-slug> = [...] }]`

Validation expectations:

- client slug must be lowercase and contain only lowercase letters, digits, or hyphen
- `bearer_token_id` must be non-empty
- `bearer_token_hash` must be non-empty
- `bearer_token_expires_at` must be an RFC3339 UTC timestamp ending in `Z`
- clients must declare exactly one of `group` or `api_access`
- `group` must reference an existing `[groups.<slug>]`
- `api_access` keys must be lowercase valid API slugs
- `api_access` may be empty; empty arrays grant no routes
- each route rule must contain `method` and `path`
- route rule `method` must be a valid HTTP method or `*`
- route rule `path` must be `*` or start with `/`
- route rule `path` must not contain query strings or fragments
- every referenced API must exist in `[apis.*]`
- duplicate `bearer_token_id` values across clients are rejected

Token storage contract:

- operators use bearer tokens on the wire in the form `<token_id>.<secret>`
- config files never persist the plaintext bearer token
- config files persist only `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`

### `[groups.<slug>]`

Each group defines a reusable API access map.

Required fields:

- `api_access: { <api-slug> = [{ method = "<method>|*", path = "<path>|*" }, ...], ... }`, `api_access = []`, or `api_access = [{ <api-slug> = [...] }]`

Each `api_access` value is a route whitelist for that API. Empty maps, empty top-level arrays, and empty per-API route arrays are valid and grant no routes.

Validation expectations:

- group slug must be lowercase and contain only lowercase letters, digits, or hyphen
- unknown fields are rejected
- `api_access` keys must be lowercase valid API slugs
- `api_access` may be empty; empty arrays grant no routes
- each route rule must contain `method` and `path`
- route rule `method` must be a valid HTTP method or `*`
- route rule `path` must be `*` or start with `/`
- route rule `path` must not contain query strings or fragments
- every referenced API must exist in `[apis.*]`

### `[apis.<slug>]`

Required fields:

- `base_url: String`
- `headers: TOML table or inline table of <header-name> = <value> pairs | omitted`
- `basic_auth: TOML table or inline table with username and optional password | omitted`
- `timeout_ms: u64 | omitted`
- `description: Option<String>`
- `docs_url: Option<String>`

Validation expectations:

- slug must be a valid lowercase slug
- `base_url` must parse as a URL
- `headers`, when present, must be a TOML table or inline table of HTTP header name → value pairs
- each `headers` key must parse as an HTTP header name
- reserved proxy-managed header names in `headers` are rejected with an error
- each `headers` value must be a non-empty string
- omitted `headers` means no configured injected headers
- `basic_auth`, when present, must be a TOML table or inline table with non-empty `username`
- `basic_auth.password` is optional; when omitted, config stores username-only Basic auth and upstream Basic auth uses an empty password
- `basic_auth` and `headers.authorization` cannot both be configured on same API
- optional `description`, when present, must be non-empty
- optional `docs_url`, when present, must parse as a URL and use `http` or `https`
- omitted `timeout_ms` falls back to `5000`
- explicit `timeout_ms` must be greater than zero

## Operational expectations

- at least one client is required
- `clients.default` is the conventional local/dev client
- generated configs may start with empty group access maps and empty `[apis]`
- route authorization defaults to block; adding an API to `[apis]` does not allow any client until a matching route rule is added to that client's inline `api_access` or referenced group

## Sample config

`.secrets.example` is the runnable local/dev sample:

```toml
[groups.default]
api_access = { projects = [{ method = "get", path = "*" }] }

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2036-10-08T12:00:00Z"
group = "default"

[apis.projects]
base_url = "http://127.0.0.1:18081/api"
headers = { authorization = "Bearer local-upstream-token" }
timeout_ms = 5000
```

Another valid upstream auth shape is HTTP basic auth:

```toml
[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = "user", password = "password" }
timeout_ms = 5000
```

Username-only basic auth is also valid:

```toml
[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = "user" }
timeout_ms = 5000
```

For the committed sample config, the matching local bearer token is `default.s3cr3t`.

This sample is intentionally distinct from fresh `config init` output. `.secrets.example` is committed as runnable local/dev config, so it includes a `projects` route rule together with `[apis.projects]` and relies on runtime defaults for omitted optional fields like `[server]`. Fresh init bootstraps same group-backed shape but writes explicit `[server]`, keeps `groups.default.api_access = {}`, and leaves `[apis]` empty until operator adds APIs and route rules.

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
  - explicit `[groups]` with `[groups.default]`
  - `groups.default.api_access = {}`
  - generated `clients.default` bearer token metadata
  - generated `bearer_token_expires_at` about 180 days in the future
  - `clients.default.group = "default"`
  - empty `[apis]`
- prints the generated default client bearer token once to stdout
- persists only the token id, hash, and expiry
- when bind or port is not supplied explicitly in an interactive session, prompts for:
  - `Server bind (default: 127.0.0.1; remote setups should use 0.0.0.0)`
  - `Server port (default: 8787)`
- when bind or port is not supplied outside the questionnaire flow, uses the same defaults and writes them explicitly into `[server]`

Fresh init keeps `groups.default.api_access = {}` empty on purpose. New configs start with no `[apis.*]`, so granting a `projects` route rule there would point at an API that does not exist yet and would fail runtime validation. That differs from `.secrets.example`, which is committed with populated sample API definitions and matching sample route access.

- when `--encrypted` is omitted in an interactive session, prompts whether to encrypt the file and defaults that choice to yes
- explicit `--config`, `--encrypted`, and password inputs keep the command non-interactive for those decisions

When encryption is enabled:

- the generated config is encrypted immediately
- initial password resolution uses `--password`, then `GATE_AGENT_PASSWORD`, then an interactive prompt
- encryption work factor resolution uses `--encryption-factor`, then `GATE_AGENT_ENCRYPTION_FACTOR`, then default `10`
- interactive prompting asks twice and requires an exact match
- encrypted init leaves the keyring empty for that config path and removes any stale cached password

### `config show`

- resolves the target path using read precedence
- prints plaintext TOML to stdout
- prints raw plaintext TOML values exactly as stored
- decrypts first when the selected file is encrypted, whether `age` content is ASCII-armored or binary

### `config edit`

- resolves the target path using read precedence
- uses `VISUAL` first, then `EDITOR`
- fails if neither editor variable is set
- plaintext configs are edited in place
- encrypted configs are decrypted to a temporary file, edited, validated, then re-encrypted and atomically written back

### `config api`

`config api` owns upstream auth mode for each API entry. Supported modes are:

- no upstream auth
- static `headers.authorization`
- `basic_auth = { username = ..., password = ... }`
- `basic_auth = { username = ... }`

Accepted flags:

- `--name`
- `--base-url`
- `--basic-auth`
- repeated `--header <name=value>`
- optional `--timeout-ms`
- `-d` / `--delete`

Behavior:

- validates inputs before writing
- creates config if it does not exist yet
- adds or updates one `[apis.<name>]` entry by default
- `-d` / `--delete` deletes one existing API entry instead of add-or-update
- runs the optional interactive questionnaire only when no API-management flags are supplied
- API-management flags include `--name`, `--base-url`, any `--header`, `--timeout-ms`, and `--delete`
- when any API-management flag is supplied, omitted flags are treated as non-interactive omissions and preserve existing values on update
- on interactive update, current values become prompt defaults and blank answers keep those defaults
- on non-interactive update, omitted flags preserve current values instead of clearing them
- `--basic-auth` selects upstream Basic auth mode
- `--basic-auth` never accepts credentials on command line
- `--basic-auth` still prompts for username and password
- parses each `--header` value as `<name>=<value>` and stores them in `headers = { ... }`
- when reading an existing API entry, accepts `headers` and `basic_auth` as regular TOML tables or inline tables; CLI-managed updates write those fields as inline tables
- repeated `--header` flags are merged into one header map
- duplicate normalized header names are rejected
- configured headers override collisions with same request header names at runtime
- when no headers are supplied, writes no `headers` field and injects no configured upstream headers at runtime
- in interactive create or when no headers are configured yet, leaving headers blank means no configured upstream headers
- on interactive update, leaving headers blank keeps current configured headers
- entering `none` for headers clears configured upstream headers
- when Basic auth is selected interactively, CLI prompts for username and password
- username is required
- on create, blank password stores empty password for upstream Basic auth
- on create, entering `none` at the password prompt stores username-only Basic auth as `basic_auth = { username = "..." }`
- on update, blank password clears the stored password key and keeps the username, resulting in `basic_auth = { username = "..." }`
- on update, entering `none` at the password prompt also clears the stored password key and keeps the username
- any other password prompt text stores that text as `basic_auth.password`
- interactive flow prompts for headers before any optional Basic auth setup
- after headers, CLI offers optional Basic auth setup
- enabling Basic auth removes only `headers.authorization`; unrelated headers stay configured
- `basic_auth` and `headers.authorization` cannot coexist on same API
- switching from header auth to Basic auth removes only `headers.authorization`; unrelated headers stay configured
- uses `5000` when `--timeout-ms` is omitted during create or when no stored value exists yet
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt
- successful decrypts from flag, env, or prompt backfill the keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- explicit args keep the command non-interactive
- when required operator input is missing in an interactive edit/create flow, prompts for it instead of failing immediately; resource-name prompts are labeled `Existing Apis`, use an up/down selector with existing names shown as plain `<name>` values, and include an `add new api` entry
- selecting an existing API opens an action prompt with `edit`, `delete`, and `cancel`; delete-only selectors list existing APIs only and do not include `add new api`
- selecting the add-new entry in edit/create flows prompts for the name afterward
- API delete is blocked when any group references that API in `groups.*.api_access` or any inline-access client references it in `clients.*.api_access`
- API delete never cascades; operators must remove those references first

Interactive questionnaire flow:

- `API name:`
- `Base URL (example: https://projects.internal.example/api):`
- `Headers (example: x-api-key=secret; leave empty for no headers):`
- optional Basic auth follow-up after headers
- `Basic auth username:` and `Basic auth password:` when operator enables Basic auth
- for existing Basic auth, the password prompt says `blank clears existing password; enter password to keep or change`
- for new Basic auth, the password prompt says `blank stores empty password; enter 'none' for username-only basic auth`

### `config client`

Accepted flags:

- `--name`
- `--bearer-token-expires-at`
- `--group <slug>`
- repeated `--api-access <api:method:path[,method:path...]>`
- `-d` / `--delete`

Behavior:

- validates slug inputs and bearer-token expiration dates
- requires exactly one of `--group` or `--api-access` when creating a client
- `--group` and `--api-access` are mutually exclusive in one invocation
- `--api-access` accepts one API slug followed by one or more `method:path` route rules; use another `--api-access` flag for another API slug
- `method` accepts any valid HTTP method or `*`
- `path` accepts `*` or a path beginning with `/`, without query strings or fragments
- repeated `--api-access` flags are merged across API slugs
- creates config if it does not exist yet
- adds or updates one client entry by default
- `-d` / `--delete` deletes one existing client entry instead of add-or-update
- if the client does not already exist, a bearer token is generated and printed once so the operator can capture it
- if the client already exists, normal client updates do not rotate the bearer token, do not replace bearer-token metadata except for an explicitly supplied expiry, and do not reprint a plaintext token
- if `--password` is supplied while bootstrapping a missing config, the new config is created encrypted
- if a config must be created first, the generated default client token is also printed once
- plaintext bearer tokens are never persisted
- client access mode may switch on update between `group = "..."` and inline `api_access = { ... }`
- when switching access mode, the selected mode is written and the opposite field is removed
- when updating interactively, current values become prompt defaults and blank answers keep those defaults
- when updating non-interactively, omitting both access flags preserves current access mode and current access values
- when required operator input is missing in an interactive session, prompts for it instead of failing immediately
- `--bearer-token-expires-at` accepts `YYYY-MM-DD` and stores that date as midnight UTC
- when adding a new client interactively, `Bearer token expiration` defaults to a date about six months in the future
- resource-name prompts are labeled `Existing Clients`, use an up/down selector with existing names shown as plain `<name>` values, and include an `add new client` entry in edit/create flows
- selecting an existing client opens an action prompt with `edit`, `delete`, and `cancel`; delete-only selectors list existing clients only and do not include `add new client`
- selecting the add-new entry in edit/create flows prompts for the name afterward
- the group access prompt references existing group slugs as plain `<name>` values and includes an `add new group` entry; choosing `add new group` asks for the group name and group `api_access` before writing the client reference
- referenced APIs are validated at runtime load, not at write time
- does not verify that referenced APIs already exist in `[apis.*]` at write time; that is enforced by runtime config loading
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt
- successful decrypts from flag, env, or prompt backfill the keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- explicit args keep the command non-interactive
- client delete is blocked when deleting that entry would remove the last remaining client from the config
- client delete never cascades

### `config client rotate-secret`

This command rotates bearer-token credentials for an existing `[clients.<slug>]` entry.

Accepted flags:

- `--name`
- `--bearer-token-expires-at`

Behavior:

- validates slug inputs and bearer-token expiration dates before writing
- requires an existing config file; it does not create one implicitly
- requires an existing client entry; it does not create one implicitly
- generates a brand-new bearer token for that client
- prints replacement bearer token once so the operator can capture it
- persists only `bearer_token_id`, `bearer_token_hash`, and `bearer_token_expires_at`
- never persists plaintext bearer token
- preserves current `group` or inline `api_access` unchanged
- preserves current expiry when `--bearer-token-expires-at` is omitted
- writes supplied expiry when `--bearer-token-expires-at` is present
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt
- successful decrypts from flag, env, or prompt backfill the keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- preserves existing encrypted/plaintext storage mode instead of rewriting config into a different format
- when required operator input is missing in an interactive session, prompts for client name with an up/down selector of existing clients

The CLI name uses “client secret” for operator ergonomics, but stored config model remains bearer-token metadata.

### `config group`

This command manages `[groups.<slug>]` entries directly.

Accepted flags:

- `--name`
- repeated `--api-access <api:method:path[,method:path...]>`
- `-d` / `--delete`

Behavior:

- accepts a group name plus repeated `--api-access <api:method:path[,method:path...]>`
- creates config if it does not exist yet
- adds or updates one group entry by default
- `-d` / `--delete` deletes one existing group entry instead of add-or-update
- prompts for the name and inline `api_access` when that required input is missing in an interactive edit/create flow; resource-name prompts are labeled `Existing Groups`, use an up/down selector with existing names shown as plain `<name>` values, and include an `add new group` entry in edit/create flows; selecting an existing group opens an action prompt with `edit`, `delete`, and `cancel`; delete-only selectors list existing groups only and do not include `add new group`; API access prompts are labeled `Api access` and list existing APIs as `<api> (edit permissions)` plus `Done`, then each API's rule screen offers `Add new rule`, existing rules as delete actions, and `Go back`
- when updating interactively, current values become prompt defaults and blank answers keep those defaults
- when updating non-interactively, omitting `--api-access` preserves current access values instead of clearing them
- preserves encrypted-vs-plaintext format on update
- when updating an encrypted config, password resolution follows flag → env → keyring → prompt
- successful decrypts from flag, env, or prompt backfill the keyring for that config path
- stale cached keyring passwords are removed automatically when decrypt fails with an invalid keyring password
- explicit args keep the command non-interactive
- group delete is blocked when any client still references that group through `clients.*.group`
- group delete never cascades; operators must repoint or update those clients first

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
- client and group `api_access` entries may be empty; empty top-level access and empty per-API route-rule arrays grant no routes
- route-rule methods must be valid HTTP methods or `*`
- route-rule paths must be `*` or begin with `/`, with no query string or fragment
- malformed timestamps and invalid slugs are rejected during parse/load

## `config validate`

`config validate` checks whether a config would load at runtime.

Behavior:

- uses the same config loading behavior as `start`, including non-empty stdin override
- uses the same strict parser and runtime validation rules as `start`
- prints `config is valid` on success
- prints a JSON error payload to stderr on invalid config and exits non-zero
