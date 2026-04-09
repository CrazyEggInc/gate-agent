# Pending work

This document tracks intentionally deferred work that is still worth keeping on the roadmap.

It is the replacement for future-looking notes that previously lived in plan files.

## Purpose

The items in this file are not part of the current product contract.

They must be treated as:

- possible future enhancements
- deferred hardening work
- optional operator or deployment improvements

They must not be described elsewhere as already implemented.

## Auth and security

- support additional upstream auth injection modes beyond static header injection
  - examples: basic auth, signed headers, query-param auth, and provider-specific schemes
- support encrypted config or secret storage at rest
- support external secret backends such as environment variables, OS keychain, Vault, or cloud secret managers
- support non-HS256 token verification models such as JWKS or remote issuer validation
- support TLS or mTLS on the local listener when deployment requirements need it
- add audit logging for who called which upstream API and when

## Runtime and operations

- add richer per-client auth policies only if they become necessary

## Product and operator surface

- add a tool or API registry endpoint such as `/tools` if discovery becomes necessary

## Notes

- This list preserves deferred ideas from earlier planning work.
- Adding an item here does not commit the project to implementing it.
- When one of these items becomes active work, the relevant product docs must be updated alongside the implementation.
