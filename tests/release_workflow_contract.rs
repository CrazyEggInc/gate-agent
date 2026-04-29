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

    assert!(workflow.contains("^v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"));
    assert!(workflow.contains("release tag must match vX.Y.Z or vX.Y.Z-prerelease"));
    assert!(workflow.contains("expected_version=\"${release_tag#v}\""));
    assert!(
        workflow.contains(
            "Cargo.toml version ${cargo_version} does not match release tag ${release_tag}"
        )
    );
}

#[test]
fn release_workflow_builds_gnu_linux_musl_linux_and_macos_assets() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("target: x86_64-unknown-linux-gnu"));
    assert!(workflow.contains("asset_name: linux-x64"));
    assert!(workflow.contains("target: x86_64-unknown-linux-musl"));
    assert!(workflow.contains("asset_name: linux-x64-musl"));
    assert!(workflow.contains("target: aarch64-apple-darwin"));
    assert!(workflow.contains("asset_name: macos-arm64"));
}

#[test]
fn release_workflow_installs_matrix_rust_targets() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("uses: dtolnay/rust-toolchain@stable"));
    assert!(workflow.contains("targets: ${{ matrix.target }}"));
    assert!(
        workflow.contains(
            "cargo build --release --locked --bin gate-agent --target ${{ matrix.target }}"
        )
    );
}

#[test]
fn release_workflow_installs_musl_dependencies_only_for_musl_target() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("Install Linux musl build dependencies"));
    assert!(workflow.contains("if: matrix.target == 'x86_64-unknown-linux-musl'"));
    assert!(workflow.contains("sudo apt-get update"));
    assert!(workflow.contains("sudo apt-get install -y musl-tools"));
}

#[test]
fn release_workflow_uploads_versioned_assets_and_stable_latest_aliases() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-${{ matrix.asset_name }}.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-${{ matrix.asset_name }}.tar.gz"));
    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-linux-x64.tar.gz"));
    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-linux-x64-musl.tar.gz"));
    assert!(workflow.contains("gate-agent-${RELEASE_TAG}-macos-arm64.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-linux-x64.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-linux-x64-musl.tar.gz"));
    assert!(workflow.contains("gate-agent-latest-macos-arm64.tar.gz"));
    assert!(workflow.contains("if [[ \"${RELEASE_TAG}\" != *-* ]]; then"));
    assert!(workflow.contains("--clobber"));
}

#[test]
fn release_workflow_marks_prerelease_tags_as_github_prereleases() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("if [[ \"${RELEASE_TAG}\" == *-* ]]; then"));
    assert!(workflow.contains("prerelease_args=(--prerelease)"));
    assert!(workflow.contains("\"${prerelease_args[@]}\""));
}

#[test]
fn release_workflow_keeps_prereleases_out_of_latest_pointer() {
    let workflow = fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow should be readable");

    assert!(workflow.contains("latest_args=(--latest)"));
    assert!(workflow.contains("latest_args=(--latest=false)"));
    assert!(workflow.contains("\"${latest_args[@]}\""));
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
