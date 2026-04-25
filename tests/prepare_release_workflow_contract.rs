use std::fs;

#[test]
fn prepare_release_workflow_is_manual_and_writes_version_bump_only_after_validation() {
    let workflow = fs::read_to_string(".github/workflows/prepare-release.yml")
        .expect("prepare release workflow should be readable");

    assert!(workflow.contains("workflow_dispatch:"));
    assert!(workflow.contains("version:"));
    assert!(workflow.contains("dry_run:"));
    assert!(workflow.contains("permissions:\n  contents: write\n  actions: write"));
    assert!(workflow.contains("cargo install cargo-edit --locked"));
    assert!(workflow.contains("cargo fmt --all --check"));
    assert!(workflow.contains("cargo clippy --all-targets --all-features -- -D warnings"));
    assert!(workflow.contains("cargo test --all-targets --all-features"));
    assert!(workflow.contains("if: ${{ !inputs.dry_run }}"));
    assert!(workflow.contains("tag -a \"${release_tag}\" -m \"Release ${release_tag}\""));
    assert!(workflow.contains(
        "git push --atomic origin \"HEAD:refs/heads/${release_branch}\" \"refs/tags/${release_tag}\""
    ));
}

#[test]
fn prepare_release_workflow_checks_version_shape_bumps_cargo_metadata_and_existing_tag() {
    let workflow = fs::read_to_string(".github/workflows/prepare-release.yml")
        .expect("prepare release workflow should be readable");

    assert!(workflow.contains("^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"));
    assert!(workflow.contains("release version must match X.Y.Z or X.Y.Z-prerelease"));
    assert!(workflow.contains("Bump package version"));
    assert!(workflow.contains("cargo metadata --format-version 1 --no-deps"));
    assert!(workflow.contains("cargo set-version \"${RELEASE_VERSION}\""));
    assert!(workflow.contains("cargo metadata --format-version 1 >/dev/null"));
    assert!(workflow.contains("select(.name == \"gate-agent\") | .version"));
    assert!(workflow.contains("git rev-parse -q --verify \"refs/tags/${release_tag}\""));
    assert!(workflow.contains("release tag already exists: ${release_tag}"));
}

#[test]
fn prepare_release_workflow_commits_bump_before_tagging_non_dry_releases() {
    let workflow = fs::read_to_string(".github/workflows/prepare-release.yml")
        .expect("prepare release workflow should be readable");

    assert!(workflow.contains("Commit version bump and create release tag"));
    assert!(workflow.contains("release_branch=\"${RELEASE_REF#refs/heads/}\""));
    assert!(
        workflow.contains("non-dry release ref must be a branch that can receive the version bump")
    );
    assert!(workflow.contains("add Cargo.toml Cargo.lock"));
    assert!(workflow.contains("commit -m \"chore(release): prepare ${release_tag}\""));
    assert!(workflow.contains("tag -a \"${release_tag}\" -m \"Release ${release_tag}\""));
    assert!(workflow.contains(
        "git push --atomic origin \"HEAD:refs/heads/${release_branch}\" \"refs/tags/${release_tag}\""
    ));
    assert!(workflow.contains("gh workflow run release.yml"));
    assert!(workflow.contains("--ref \"${release_branch}\""));
    assert!(workflow.contains("-f ref=\"${release_tag}\""));
    assert!(workflow.contains("-f version=\"${release_tag}\""));
    assert!(workflow.contains("-f publish=true"));
}
