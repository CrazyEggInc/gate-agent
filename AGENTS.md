# AGENTS.md

## Project summary

`gate-agent` is a local Rust proxy for internal upstream APIs. It authenticates clients with configured bearer tokens, authorizes access to configured API slugs, injects upstream credentials, and forwards requests to the configured upstream.

## Technologies

- Rust 2024 edition
- Axum for the HTTP server and routing
- Reqwest for outbound upstream requests
- Tokio for async runtime and timeouts
- Clap for CLI parsing
- Serde / serde_json / toml for config and payload serialization
- toml_edit for config file updates
- secrecy for handling secrets in memory

## Directory map

- `src/cli.rs` — CLI argument surface
- `src/commands/` — command handlers
- `src/auth/` — bearer token lookup, validation, and API authorization
- `src/config/` — config resolution, parsing, validation, and bearer-token client definitions
- `src/proxy/` — proxy authorization, request/response mapping, and upstream execution
- `src/app/` — runtime app state
- `tests/` — integration tests
- `docs/` — canonical agent-facing documentation of current behavior

## Read this as needed

- `docs/auth.md` — authentication and authorization feature expectations
- `docs/config.md` — configuration feature expectations and operator workflows
- `docs/cli.md` — CLI contract, help behavior, and user workflows
- `docs/local-testing.md` — local testing environment, curl workflow, and dummy upstream usage
- `docs/pending.md` — deferred future work that is intentionally not implemented yet
- `docs/proxy.md` — proxy routing and forwarding expectations
- `docs/runtime.md` — runtime behavior, startup expectations, and error model

## Docs contract

The files under `docs/` are the canonical agent-facing product reference.

- They must describe the system in feature terms, not as a code walkthrough.
- They must define expected behavior, workflows, CLI usage, contracts, and failure modes.
- They should be usable as rebuild guidance for the project, even if the implementation changes.
- They must not drift into per-function or per-file implementation narration unless that detail is required to explain a product contract.

Whenever a feature is added, removed, or materially changed, the relevant files in `docs/` must be updated in the same change so the docs remain an accurate description of the current product behavior.

## README policy

Keep `README.md` concise and human-oriented. Put durable implementation details in `docs/`.

## Verification after changes

After completing implementation work:

- run the changed tests that cover the modified behavior
- run `cargo fmt`
- run `cargo clippy --all-targets --all-features -- -D warnings`
- fix any issues found before considering the work complete

Prefer the narrowest relevant test command first, then broaden only if needed.

## Commit format

Use conventional-style commit subjects:

- `feat(scope): description`
- `fix(scope): description`
- `refactor(scope): description`
- `docs(scope): description`
- `test(scope): description`
- `chore(scope): description`

Commit messages should be concise and describe the intent of the change. When a plan file exists for the work, reference it in the commit body.
