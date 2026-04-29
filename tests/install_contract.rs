use std::fs;

#[test]
fn installer_stays_posix_sh() {
    let installer = fs::read_to_string("install.sh").expect("installer should be readable");

    assert!(installer.starts_with("#!/usr/bin/env sh\n"));
    assert!(installer.contains("set -eu"));
}

#[test]
fn installer_detects_musl_linux_x64_as_musl_asset() {
    let installer = fs::read_to_string("install.sh").expect("installer should be readable");

    assert!(installer.contains("detect_linux_libc()"));
    assert!(installer.contains("linux_libc=\"$(detect_linux_libc)\""));
    assert!(installer.contains("if [ \"$linux_libc\" = \"musl\" ]; then"));
    assert!(installer.contains("TARGET=\"linux-x64-musl\""));
}

#[test]
fn installer_preserves_gnu_or_unknown_linux_x64_default_asset() {
    let installer = fs::read_to_string("install.sh").expect("installer should be readable");

    assert!(installer.contains("TARGET=\"linux-x64\""));
    assert!(installer.contains("linux_libc=\"$(detect_linux_libc)\""));
    assert!(installer.contains("case \"$linux_libc\" in"));
    assert!(installer.contains("glibc|unknown)"));
    assert!(installer.contains("print_status \"Platform: $TARGET\""));
}

#[test]
fn installer_uses_safe_positive_musl_detection() {
    let installer = fs::read_to_string("install.sh").expect("installer should be readable");

    assert!(installer.contains("getconf GNU_LIBC_VERSION"));
    assert!(installer.contains("ldd --version"));
    assert!(installer.contains("*musl*)"));
    assert!(installer.contains("printf '%s\\n' musl"));
    assert!(installer.contains("printf '%s\\n' unknown"));
}

#[test]
fn installer_builds_archive_names_from_selected_target() {
    let installer = fs::read_to_string("install.sh").expect("installer should be readable");

    assert!(installer.contains("ARCHIVE=\"gate-agent-latest-$TARGET.tar.gz\""));
    assert!(installer.contains("ARCHIVE=\"gate-agent-v$VERSION-$TARGET.tar.gz\""));
}
