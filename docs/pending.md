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

## Build tooling

- add linux/osx/windows builds to github releases
- Update readme to use the built file on instructions
- Update readme with binary install instructions
- Add development section where we run command through cargo instead

## Auth and security

- support additional upstream auth injection modes beyond static header injection
  - examples: basic auth, signed headers, query-param auth, and provider-specific schemes
- support non-HS256 token verification models such as JWKS or remote issuer validation
- support TLS or mTLS on the local listener when deployment requirements need it

## Product and operator surface

- add a tool or API registry endpoint such as `/tools` if discovery becomes necessary
- add docs/examples with configuration examples

## Notes

- This list preserves deferred ideas from earlier planning work.
- Adding an item here does not commit the project to implementing it.
- When one of these items becomes active work, the relevant product docs must be updated alongside the implementation.
