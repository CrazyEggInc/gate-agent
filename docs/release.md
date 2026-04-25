# Release Automation

This document describes how maintainers prepare, publish, install, and verify `gate-agent` releases.

## Goals

Releases must be reproducible from a clean checkout at one git tag. Automation must fail before publishing when source validation, build, packaging, or checksum generation fails.

## Supported release assets

Each published release must include these versioned archives:

- `gate-agent-vX.Y.Z-linux-x64.tar.gz`
- `gate-agent-vX.Y.Z-macos-arm64.tar.gz`
- `gate-agent-vX.Y.Z-sha256sums.txt`

Prerelease versions use the same shape with the prerelease suffix, for example `gate-agent-v1.2.3-beta-linux-x64.tar.gz`.

Each published stable release must also include stable latest aliases:

- `gate-agent-latest-linux-x64.tar.gz`
- `gate-agent-latest-macos-arm64.tar.gz`
- `gate-agent-latest-sha256sums.txt`

The stable latest aliases are uploaded to stable releases only. Prereleases are marked as GitHub prereleases and publish only versioned assets. Installers should use GitHub's `releases/latest/download` URLs when they want the newest stable release, and versioned `releases/download/vX.Y.Z` or `releases/download/vX.Y.Z-prerelease` URLs when they need a pinned version.

## Checksum contract

The versioned checksum file contains checksums for versioned archive filenames only.

Example:

```text
<sha256>  gate-agent-v1.2.3-linux-x64.tar.gz
<sha256>  gate-agent-v1.2.3-macos-arm64.tar.gz
```

The latest checksum file contains checksums for latest alias filenames only.

Example:

```text
<sha256>  gate-agent-latest-linux-x64.tar.gz
<sha256>  gate-agent-latest-macos-arm64.tar.gz
```

This keeps `sha256sum --check` and `shasum -a 256 -c` compatible without renaming files locally.

## Prepare release workflow

Maintainers prepare a release through GitHub Actions workflow `prepare release`.

Inputs:

- `version`: semantic version without `v`, for example `1.2.3` or `1.2.3-beta`
- `ref`: source ref to release, default `master`
- `dry_run`: when `true`, validate only and do not push the version bump or create a tag

The workflow validates:

1. version matches `X.Y.Z` or `X.Y.Z-prerelease`
2. tag `vX.Y.Z` or `vX.Y.Z-prerelease` does not already exist
3. `Cargo.toml` can be bumped with `cargo set-version` and `Cargo.lock` can be refreshed with `cargo metadata`
4. source passes `cargo fmt --all --check`
5. source passes `cargo clippy --all-targets --all-features -- -D warnings`
6. source passes `cargo test --all-targets --all-features`

When `dry_run=false`, the workflow commits the `Cargo.toml` and `Cargo.lock` version bump to the selected branch, creates annotated tag `vX.Y.Z` or `vX.Y.Z-prerelease` at that commit, pushes both, and dispatches the release workflow for the tag. Non-dry runs require `ref` to be a branch that can receive the version bump.

## Release workflow

The release workflow runs on pushed tags matching `v*.*.*` and through manual dispatch. The prepare release workflow uses manual dispatch after it pushes a tag, because GitHub does not start push-triggered workflows from tags pushed with the workflow `GITHUB_TOKEN`.

For a real tag release, the workflow:

1. checks out the tagged commit
2. verifies tag format and `Cargo.toml` version
3. runs formatting, clippy, and tests
4. builds optimized Linux x64 and macOS ARM64 binaries
5. creates versioned archives and stable latest alias archives
6. creates versioned and latest checksum manifests
7. creates or reuses the GitHub release for the tag, marking tags with a prerelease suffix as GitHub prereleases
8. uploads versioned artifacts for all releases and stable latest alias artifacts for stable releases only, using `--clobber` so retries replace partial uploads

## Failure and recovery

Validation, build, and packaging failures happen before publish and are safe to fix in repository code before creating a new tag.

Publish failures may leave a release record or partial assets. Re-run the failed workflow for the same tag first. Because uploads use `--clobber`, retry is safe for transient GitHub or network failures. If incorrect artifacts were already consumed, create a corrective version tag rather than rewriting public history.

## Manual verification

After a release publishes:

```sh
gh release view vX.Y.Z --json tagName,targetCommitish,assets
curl -fsSLO https://github.com/CrazyEggInc/gate-agent/releases/latest/download/gate-agent-latest-sha256sums.txt
curl -fsSLO https://github.com/CrazyEggInc/gate-agent/releases/latest/download/gate-agent-latest-linux-x64.tar.gz
grep ' gate-agent-latest-linux-x64.tar.gz$' gate-agent-latest-sha256sums.txt | sha256sum --check -
tar -xzf gate-agent-latest-linux-x64.tar.gz
./gate-agent version
```
