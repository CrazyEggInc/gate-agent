use std::fs;

#[test]
fn readme_documents_latest_install_with_stable_assets_and_checksum_verification() {
    let readme = fs::read_to_string("README.md").expect("README should be readable");

    assert!(readme.contains("gate-agent-latest-${TARGET}.tar.gz"));
    assert!(readme.contains("gate-agent-latest-sha256sums.txt"));
    assert!(readme.contains("https://github.com/CrazyEggInc/gate-agent/releases/latest/download"));
    assert!(readme.contains("grep \" ${ARCHIVE}\\$\" \"${CHECKSUMS}\" | shasum -a 256 -c -"));
    assert!(readme.contains("grep \" ${ARCHIVE}\\$\" \"${CHECKSUMS}\" | sha256sum --check -"));
}

#[test]
fn readme_documents_pinned_install_with_versioned_assets() {
    let readme = fs::read_to_string("README.md").expect("README should be readable");

    assert!(readme.contains("VERSION=1.2.3"));
    assert!(readme.contains("gate-agent-v${VERSION}-${TARGET}.tar.gz"));
    assert!(readme.contains("gate-agent-v${VERSION}-sha256sums.txt"));
    assert!(
        readme.contains("https://github.com/CrazyEggInc/gate-agent/releases/download/v${VERSION}")
    );
}

#[test]
fn readme_points_maintainers_to_prepare_release_and_release_docs() {
    let readme = fs::read_to_string("README.md").expect("README should be readable");

    assert!(readme.contains("run GitHub Actions workflow `prepare release` with `dry_run=true`"));
    assert!(
        readme.contains("re-run `prepare release` with `dry_run=false` to create tag `vX.Y.Z`")
    );
    assert!(readme.contains("See `docs/release.md`"));
}
