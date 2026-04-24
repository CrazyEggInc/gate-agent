use std::fs;

#[test]
fn prepare_release_workflow_is_manual_and_writes_tags_only_after_validation() {
    let workflow = fs::read_to_string(".github/workflows/prepare-release.yml")
        .expect("prepare release workflow should be readable");

    assert!(workflow.contains("workflow_dispatch:"));
    assert!(workflow.contains("version:"));
    assert!(workflow.contains("dry_run:"));
    assert!(workflow.contains("permissions:\n  contents: write"));
    assert!(workflow.contains("cargo fmt --all --check"));
    assert!(workflow.contains("cargo clippy --all-targets --all-features -- -D warnings"));
    assert!(workflow.contains("cargo test --all-targets --all-features"));
    assert!(workflow.contains("if: ${{ !inputs.dry_run }}"));
    assert!(workflow.contains("tag -a \"${release_tag}\" -m \"Release ${release_tag}\""));
    assert!(workflow.contains("git push origin \"refs/tags/${release_tag}\""));
}

#[test]
fn prepare_release_workflow_checks_version_shape_cargo_version_and_existing_tag() {
    let workflow = fs::read_to_string(".github/workflows/prepare-release.yml")
        .expect("prepare release workflow should be readable");

    assert!(workflow.contains("^[0-9]+\\.[0-9]+\\.[0-9]+$"));
    assert!(workflow.contains(
        "Cargo.toml version ${cargo_version} does not match release version ${RELEASE_VERSION}"
    ));
    assert!(workflow.contains("git rev-parse -q --verify \"refs/tags/${release_tag}\""));
    assert!(workflow.contains("release tag already exists: ${release_tag}"));
}
