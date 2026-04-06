# Rust Auth Proxy CLI MVP Implementation Plan

**Goal:** Build a Rust CLI that starts a local HTTP proxy server, validates client JWTs, selects the correct upstream API credentials, injects upstream authentication, and returns the upstream response without exposing upstream secrets to clients.

**Status:** Brainstorming decisions captured and MVP contract now fixed enough for implementation planning.

**Architecture:** Implement a single binary crate with a small command layer (`start`), a strongly typed configuration/auth core, and an Axum-based proxy server backed by a reusable Reqwest client. The MVP will prefer explicit types, fail-closed auth behavior, minimal magic, and local secret storage via a structured `.secrets` file.

**Design:** Conversation request from 2026-04-06 (no separate design doc exists yet)

---

## Recommended crate stack

- `clap` - CLI parsing for `start` and future subcommands
- `tokio` - async runtime
- `axum` - local proxy HTTP server
- `reqwest` - upstream HTTP client
- `serde`, `serde_json` - config and claims serialization
- `toml` - parse `.secrets` and future config files
- `jsonwebtoken` - JWT validation for MVP
- `secrecy` - reduce accidental secret exposure in logs/debugging
- `thiserror` - explicit typed error model
- `tracing`, `tracing-subscriber` - structured logs
- `tower`, `tower-http` - request ids, tracing, timeout, panic-safe layers
- `http`, `http-body-util`, `bytes` - header/body plumbing
- `url` - safe upstream URL composition
- `assert_cmd` - CLI integration tests
- `wiremock` or `httpmock` - fake upstream API in integration tests
- `tempfile` - ephemeral `.secrets` test fixtures

Optional but recommended shortly after MVP:

- `cargo-deny` - dependency/license policy
- `cargo-audit` - vulnerability scan
- `insta` - snapshot tests for structured error responses

---

## Suggested file/module layout

```text
gate-agent/
├── Cargo.toml
├── .tool-versions
├── rust-toolchain.toml
├── .gitignore
├── .secrets.example
├── README.md
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── cli.rs
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── start.rs
│   │   └── curl_payload.rs
│   ├── config/
│   │   ├── mod.rs
│   │   ├── app_config.rs
│   │   └── secrets.rs
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── claims.rs
│   │   └── jwt.rs
│   ├── proxy/
│   │   ├── mod.rs
│   │   ├── router.rs
│   │   ├── request.rs
│   │   ├── response.rs
│   │   └── upstream.rs
│   ├── app/
│   │   ├── mod.rs
│   │   └── state.rs
│   ├── error.rs
│   └── telemetry.rs
└── tests/
    ├── cli_start.rs
    ├── cli_curl_payload.rs
    ├── config_loading.rs
    ├── secrets_loading.rs
    ├── jwt_validation.rs
    ├── proxy_request_mapping.rs
    ├── proxy_end_to_end.rs
    └── support/
        └── mod.rs
```

Implementation choice: use a library crate plus thin `main.rs` so unit and integration tests can exercise the app without shelling out except for CLI smoke tests.

---

## MVP architecture

### 1. CLI surface

- Command: `gate-agent start`
- Command: `gate-agent curl-payload`
- Main flags for MVP:
  - `--bind 127.0.0.1:8787` override listen address
  - `--secrets-file .secrets` override secrets path
  - `--log-level info`
- No daemonization, no hot reload, no admin API in MVP
- No `/tools` discovery endpoint in MVP

`curl-payload` purpose:

- generate a `curl -K -` compatible config payload for local testing
- target the local proxy base URL using the CLI bind/default listener settings
- mint or sign a local JWT using the configured JWT settings from `.secrets`
- emit the target proxy URL and `Authorization: Bearer <jwt>` header
- stay explicitly scoped to local smoke testing, not real client integrations

Recommended flags for MVP:

- `--api projects`
- `--path /v1/projects/1/tasks`

Deliberate non-features for MVP:

- no `--method`; curl should provide request method itself when needed
- no body flags; curl should provide request body arguments itself when needed
- no extra arbitrary header flags; curl should provide them directly

Example usage:

```sh
gate-agent curl-payload --api projects --path /v1/projects/1/tasks | curl -K -
```

### 2. Configuration strategy

Use two layers:

1. non-secret runtime settings from CLI flags, with sensible defaults
2. secret and upstream mapping data from `.secrets`

Recommended `.secrets` format: TOML stored in a file literally named `.secrets`.

```toml
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
```

MVP decision: keep routing metadata and credentials together in one `.secrets` TOML file because the feature is still small and local-first.

### 3. Auth model

MVP will validate a client bearer JWT from the incoming `Authorization` header.

Required claims:

- `api` - lowercase string key matching an entry in `[apis.*]`
- `exp` - expiration
- `iat` - issued-at
- `iss` - issuer
- `aud` - audience

JWT signing and verification scheme for MVP:

- `HS256`
- shared secret loaded from `.secrets`
- `curl-payload` may mint short-lived local test tokens using the same configured secret

Validation behavior:

- fail closed on missing/invalid token
- reject unsupported algorithms
- reject tokens with unknown `api`
- normalize on lowercase API identifiers end-to-end
- do not forward client JWT upstream
- log request id and resolved API name, never token or secret contents

This keeps the auth model explicit and small for the first release.

### 4. Request flow

1. Client calls `http://127.0.0.1:8787/proxy/...`
2. Axum route matches `/proxy/*path`
3. Extract `Authorization: Bearer <jwt>`
4. Validate JWT and deserialize claims
5. Resolve `claims.api` to upstream config entry
6. Build upstream URL as `api.base_url + /<captured path>`
7. Copy safe request headers and body
8. Strip hop-by-hop headers and client auth header
9. Inject upstream auth header using configured scheme/value
10. Forward using shared `reqwest::Client`
11. Copy upstream status, safe headers, and body back to client
12. Map internal failures to sanitized JSON error responses

Routing choice: everything after `/proxy/` is forwarded verbatim to the resolved upstream base URL. The JWT decides which upstream config to use; the path does not decide credentials.

There is no path rewriting in MVP.

### 5. Error handling

Use a single `AppError` enum with narrow variants:

- `ConfigLoad`
- `SecretsLoad`
- `InvalidToken`
- `ForbiddenApi`
- `BadProxyPath`
- `UpstreamBuild`
- `UpstreamRequest`
- `UpstreamTimeout`
- `ResponseMapping`
- `Internal`

HTTP mapping:

- `401` invalid/missing JWT
- `403` valid JWT but API not allowed/configured
- `400` malformed request path or headers
- `502` upstream connection/protocol failure
- `504` upstream timeout
- `500` startup/config/runtime internal failure

Response shape:

```json
{
  "error": {
    "code": "invalid_token",
    "message": "authentication failed",
    "request_id": "..."
  }
}
```

### 6. Security posture for MVP

- Bind to `127.0.0.1` by default, not `0.0.0.0`
- `.secrets` ignored by git; `.secrets.example` committed
- no secret values in debug output or panic messages
- remove client `Authorization` before forwarding
- strip hop-by-hop headers (`connection`, `te`, `trailer`, etc.)
- enforce upstream timeouts
- keep `curl-payload` documented as a local testing helper only

### 7. Streaming behavior for MVP

Streaming should be part of the MVP.

Implementation approach:

- avoid buffering full request bodies in memory when forwarding to the upstream
- avoid buffering full upstream response bodies in memory when returning them to the client
- preserve normal HTTP streaming behavior for large payloads where the Axum and Reqwest body adapters allow it

Complexity assessment:

- straightforward enough for MVP if the proxy stays close to a pass-through model
- the main care points are body type conversion, hop-by-hop header stripping, and keeping timeout/error handling sane
- WebSockets remain out of scope; plain HTTP request/response streaming is in scope

### 8. Future improvements

- additional upstream auth modes: basic auth, signed headers, query-param auth, and other provider-specific schemes
- `.secrets` encryption at rest
- external secret backends: environment, OS keychain, Vault, AWS/GCP secret managers
- remote mode where the proxy runs on a non-localhost host and supports multiple client JWT configurations plus per-client allowed API scopes
- audit logs for who called what upstream API and when
- tool registry endpoint such as `/tools` that lists configured APIs
- JWKS or remote issuer validation for non-HS256 deployments
- config reload without restart
- observability: Prometheus metrics, OpenTelemetry traces
- TLS/mTLS for local listener when needed
- richer auth policies only if they become necessary later

---

## `curl-payload` command contract

Purpose: produce a curl config payload on stdout so local developers can test the proxy without hand-crafting JWTs.

Behavior:

1. load `.secrets`
2. validate that `--api` exists in `[apis.*]`
3. construct JWT claims using the configured issuer/audience and requested API
4. sign the JWT using the local JWT signing secret for MVP
5. print curl config directives to stdout

Required CLI inputs for MVP:

- `--api <lowercase-api-slug>`
- `--path </upstream/path>`

No other request-shaping arguments are required in the command contract for MVP.

Suggested output shape:

```text
url = "http://127.0.0.1:8787/proxy/v1/projects/1/tasks"
header = "Authorization: Bearer <jwt>"
```

Notes:

- this is intended for `curl -K -`, where `-K` tells curl to read config directives and `-` means read them from stdin
- request method, request body, and any extra headers are intentionally left to curl itself in MVP
- because the command can mint a valid local JWT, it is strictly a local testing helper and not part of the real client integration surface

Example GET request:

```sh
gate-agent curl-payload --api projects --path /v1/projects/1/tasks | curl -K -
```

Example POST request where curl provides the method and body:

```sh
gate-agent curl-payload --api projects --path /v1/projects/1/tasks \
  | curl -K - -X POST -H 'Content-Type: application/json' --data '{"name":"New task"}'
```

Which behaves like:

```sh
curl \
  --url "http://127.0.0.1:8787/proxy/v1/projects/1/tasks" \
  --header "Authorization: Bearer <jwt>"
```

---

## Testing strategy

### Unit tests

- `.secrets` parsing and validation
- JWT claim validation and issuer/audience enforcement
- auth header construction for each upstream config style
- request URL mapping and header stripping
- request and response body streaming adapters
- error-to-HTTP response mapping

### Integration tests

- `start` command boots with a temp `.secrets`
- `curl-payload` emits valid `curl -K` config for a known API/path
- `curl-payload` signs a JWT whose claims match the requested API and configured issuer/audience
- end-to-end proxy request hits mock upstream and returns its response
- streamed request bodies are forwarded without full buffering semantics
- streamed upstream responses are returned correctly to the client
- invalid JWT returns `401`
- unknown `api` claim returns `403`
- upstream timeout returns `504`
- client `Authorization` header is not forwarded upstream

### Manual smoke test

- run local mock upstream
- run `gate-agent start --secrets-file .secrets`
- send curl with a valid JWT and confirm injected upstream auth header

Testing choice: keep most logic in pure functions or small services so only one or two end-to-end tests need a live server.

---

## Linting and CI

Minimum CI pipeline:

1. `cargo fmt --all --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-targets --all-features`

Recommended follow-up jobs:

4. `cargo deny check`
5. `cargo audit`

Rust best-practice defaults:

- edition `2024` if toolchain policy allows, otherwise `2021`
- include `.tool-versions` for toolchain pinning alongside Rust toolchain metadata
- deny warnings in CI, not locally by default
- keep `main.rs` thin and logic in `lib.rs`
- explicit result types, no `unwrap()` outside tests

## Build and development workflow

For a normal Rust CLI like this, the standard workflow is just Cargo.

Primary commands:

- `cargo build` for development builds
- `cargo build --release` for optimized production builds
- `cargo test` for the test suite
- `cargo fmt` and `cargo clippy` for formatting and linting
- `cargo run -- start` for local execution during development
- `cargo run -- curl-payload --api projects --path /v1/projects/1/tasks` for local smoke-test payload generation

Tooling expectations:

- no custom build system is needed for MVP beyond Cargo and the Rust toolchain
- `.tool-versions` should pin the Rust version used by contributors who rely on asdf-compatible tooling
- `rust-toolchain.toml` should pin the project toolchain for rustup users
- README should include a short development section covering install prerequisites, build, test, lint, and local run commands

---

## Dependency graph

```text
Step 1: 1.1, 1.2, 1.5 [bootstrap CLI surface and docs skeleton]
Step 2: 1.3, 1.4 [config, errors, telemetry foundation]
Step 3: 2.1, 2.2, 2.2b [JWT claims, validation, and local signing]
Step 4: 2.3, 2.4 [request and response mapping, including streaming]
Step 5: 3.1, 3.2, 3.3, 3.4 [application wiring and live proxy server]
Step 6: finalize `curl-payload` behavior and tests on top of the wired auth/config stack
Step 7: 4.1, 4.2, 4.3 [integration hardening, CI, and README polish]
```

Reason for this sequencing: the original batch notation implied parallel work, but several tasks share the same source files and test files. The implementation should therefore proceed as dependency-safe sequential steps instead of parallel batches.

---

## Phased task breakdown

### Step 1: Bootstrap and CLI shell

#### Task 1.1: Bootstrap crate and dependencies
- **Files:** `Cargo.toml`, `rust-toolchain.toml`, `.tool-versions`, `.gitignore`
- **Depends:** none
- Define binary + library targets and add the crate stack above.
- Add `.secrets` and `target/` to `.gitignore`.

#### Task 1.2: CLI entrypoint
- **Files:** `src/main.rs`, `src/cli.rs`, `src/commands/mod.rs`, `src/commands/curl_payload.rs`
- **Tests:** `tests/cli_start.rs`, `tests/cli_curl_payload.rs`
- **Depends:** none
- Implement `start` and `curl-payload` subcommands, argument parsing, and command dispatch.

#### Task 1.5: Example operator docs
- **Files:** `.secrets.example`, `README.md`
- **Depends:** none
- Document a concise summary, quickstart, development workflow, command examples, `curl -K -` testing flow, JWT expectations, and `.secrets` format.

### Step 2: Config, errors, and telemetry foundation

This step completes the validated configuration and shared error/logging surfaces needed by all later code.

#### Task 1.3: Runtime config and secrets loading
- **Files:** `src/config/mod.rs`, `src/config/app_config.rs`, `src/config/secrets.rs`
- **Tests:** `tests/config_loading.rs`, `tests/secrets_loading.rs`
- **Depends:** none
- Parse bind/log flags plus `.secrets` TOML into validated structs.
- Validate required `jwt` config and at least one `[apis.*]` entry at startup.

#### Task 1.4: Shared error and telemetry foundation
- **Files:** `src/error.rs`, `src/telemetry.rs`, `src/lib.rs`
- **Tests:** covered by downstream modules plus simple unit assertions if needed
- **Depends:** none
- Add `AppError`, HTTP-safe error payload helpers, tracing subscriber setup, and public module exports.

### Step 3: Auth primitives

#### Task 2.1: JWT claims model
- **Files:** `src/auth/mod.rs`, `src/auth/claims.rs`
- **Tests:** `tests/jwt_validation.rs`
- **Depends:** 1.3, 1.4
- Add typed claims struct with `api`, `iss`, `aud`, `exp`, `iat`.

#### Task 2.2: JWT validator
- **Files:** `src/auth/jwt.rs`
- **Tests:** `tests/jwt_validation.rs`
- **Depends:** 2.1, 1.3, 1.4
- Validate bearer token structure, algorithm, signature, issuer, audience, and expiry.

#### Task 2.2b: JWT signer for local test payload generation
- **Files:** `src/auth/jwt.rs`
- **Tests:** `tests/jwt_validation.rs`
- **Depends:** 2.1, 1.3, 1.4
- Add a small signer path used by `curl-payload` to mint short-lived local test JWTs.
- Default token TTL should be short-lived; use 5 minutes unless implementation constraints force a minor change.

### Step 4: Request and response proxy primitives

This step focuses on request/response transformation and streaming-safe proxy plumbing before full server wiring.

#### Task 2.3: Request mapping and header filtering
- **Files:** `src/proxy/request.rs`
- **Tests:** `tests/proxy_request_mapping.rs`
- **Depends:** 1.3, 1.4, 2.1
- Convert inbound Axum request into outbound Reqwest request pieces.
- Strip hop-by-hop headers and the client auth header.
- Preserve streamed request body forwarding instead of eagerly buffering the whole body.

#### Task 2.4: Upstream response mapping
- **Files:** `src/proxy/response.rs`
- **Tests:** `tests/proxy_request_mapping.rs`
- **Depends:** 1.4
- Translate Reqwest upstream response into Axum response while filtering unsafe headers and preserving streaming behavior.

### Step 5: Application wiring and live proxying

#### Task 3.1: Shared app state
- **Files:** `src/app/mod.rs`, `src/app/state.rs`
- **Tests:** covered by integration tests
- **Depends:** 1.3, 1.4, 2.2, 2.3, 2.4
- Store validated secrets config, shared Reqwest client, and startup settings.

#### Task 3.2: Upstream client execution
- **Files:** `src/proxy/upstream.rs`, `src/proxy/mod.rs`
- **Tests:** `tests/proxy_end_to_end.rs`
- **Depends:** 2.3, 2.4, 3.1
- Execute outbound requests with configured timeout and consistent error mapping.

#### Task 3.3: HTTP router and handler
- **Files:** `src/proxy/router.rs`
- **Tests:** `tests/proxy_end_to_end.rs`
- **Depends:** 2.2, 2.3, 2.4, 3.1, 3.2
- Add `/proxy/*path` route, request-id middleware, timeout layer, and handler pipeline.

#### Task 3.4: `start` command server boot
- **Files:** `src/commands/start.rs`
- **Tests:** `tests/cli_start.rs`, `tests/proxy_end_to_end.rs`
- **Depends:** 1.2, 3.1, 3.3
- Wire config loading, telemetry setup, app state creation, and Axum server startup.

### Step 6: `curl-payload` completion

At this point the auth/config stack and local listener behavior already exist, so `curl-payload` can be finalized against the real application defaults rather than mocked assumptions.

#### Task 3.5: Finalize `curl-payload`
- **Files:** `src/commands/curl_payload.rs`, `tests/cli_curl_payload.rs`
- **Depends:** 1.2, 1.3, 2.2b, 3.4
- Finalize emitted `curl -K -` config against real listener defaults and validated JWT signing configuration.
- Verify output contains the resolved local proxy URL and a valid bearer token header.

### Step 7: Delivery hardening

#### Task 4.1: End-to-end integration harness
- **Files:** `tests/support/mod.rs`, `tests/proxy_end_to_end.rs`
- **Depends:** 3.4
- Add mock upstream server helpers, JWT fixture generation, full request/response assertions, and streamed body coverage.

#### Task 4.2: CI and linting
- **Files:** `.github/workflows/ci.yml`
- **Depends:** 4.1
- Run fmt, clippy, and test jobs on push/PR.

#### Task 4.3: MVP polish and operator docs
- **Files:** `README.md`
- **Depends:** 4.1, 4.2
- Finalize concise summary, quickstart, development section, command examples, security notes, and known limitations.

---

## Clarified MVP boundaries and assumptions

### Assumptions made for this plan

1. The incoming client JWT is issued by a trusted internal system, not by the upstream API provider.
2. The JWT is supplied in the HTTP `Authorization` header as a bearer token.
3. The `api` claim maps one-to-one to a lowercase configured upstream profile in `.secrets`.
4. Forwarding path semantics are `base_url + captured_path_after_/proxy/`.
5. MVP covers HTTP proxying, including normal request/response streaming, but not WebSockets.
6. `curl-payload` is a local testing helper that is allowed to mint short-lived JWTs for smoke testing.
7. Upstream auth injection is static-header based only in MVP.
8. Listener default remains localhost-only.
9. `README.md` should stay concise: short summary, quickstart, development section, and command examples.
10. No `/tools` endpoint is included in MVP.

---

## Remaining implementation defaults

These do not need more product clarification unless preferences change:

1. default bind address: `127.0.0.1:8787`
2. default short-lived `curl-payload` token TTL: 5 minutes
3. concise JSON error envelope with stable `code` and `message`
4. `.tool-versions` should pin the Rust toolchain used by the project

---

## Recommended implementation order

1. Batch 1 completely
2. Batch 2 completely
3. Batch 3 with one mock-upstream manual smoke test
4. Batch 4 hardening and CI

This order produces a secure, testable MVP quickly while keeping the main extension seams obvious: secret source, JWT verifier, and upstream auth strategy.
