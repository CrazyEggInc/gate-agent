use std::fs;

#[test]
fn release_workflow_validates_before_building_or_publishing() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("validate:"));
    assert!(workflow.contains("cargo fmt --all --check"));
    assert!(workflow.contains("cargo clippy --all-targets --all-features -- -D warnings"));
    assert!(workflow.contains("cargo test --all-targets --all-features"));
    assert!(workflow.contains("needs:\n      - prepare\n      - validate"));
    assert!(workflow.contains("needs:\n      - prepare\n      - build"));
}

#[test]
fn release_workflow_enforces_tag_and_cargo_version_match() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("^v[0-9]+\\.[0-9]+\\.[0-9]+$"));
    assert!(workflow.contains("expected_version=\"${release_tag#v}\""));
    assert!(
        workflow.contains(
            "Cargo.toml version ${cargo_version} does not match release tag ${release_tag}"
        )
    );
}

#[test]
fn release_workflow_uploads_versioned_assets_and_stable_latest_aliases() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-${{ matrix.asset_name }}.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-${{ matrix.asset_name }}.tar.gz"));
    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-linux-x64.tar.gz"));
    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-macos-arm64.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-linux-x64.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-macos-arm64.tar.gz"));
    assert!(workflow.contains("--clobber"));
}

#[test]
fn release_workflow_generates_separate_checksum_manifests() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("sha256sum \"gate-agent-${RELEASE_TAG}\"-*.tar.gz > \"gate-agent-${RELEASE_TAG}-sha256sums.txt\""));
    assert!(
        workflow
            .contains("sha256sum gate-agent-latest-*.tar.gz > gate-agent-latest-sha256sums.txt")
    );
    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-sha256sums.txt"));
    assert!(workflow.contains("gate-agent-latest-sha256sums.txt"));
}
