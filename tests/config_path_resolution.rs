// Integration tests for shared config path resolution.
// Exercises precedence and fail-fast fallback behavior.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use gate_agent::config::path::{
    ConfigPathSource, resolve_config_path_for_update_with, resolve_config_path_with,
};
use tempfile::tempdir;

fn create_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(path.parent().expect("file parent"))?;
    std::fs::write(path, "[clients.default]\n")?;
    Ok(())
}

#[test]
fn cli_override_wins_over_env_and_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    create_file(&current_dir.path().join(".secrets"))?;

    let home_dir = tempdir()?;
    create_file(&home_dir.path().join(".config/gate-agent/secrets"))?;

    let cli_path = PathBuf::from("/tmp/cli-config.toml");
    let env_path = OsString::from("/tmp/env-config.toml");

    let resolved = resolve_config_path_with(
        Some(cli_path.as_path()),
        Some(env_path.as_os_str()),
        current_dir.path(),
        Some(home_dir.path()),
    )?;

    assert_eq!(resolved.path, cli_path);
    assert_eq!(resolved.source, ConfigPathSource::Cli);

    Ok(())
}

#[test]
fn env_override_wins_over_default_locations() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    create_file(&current_dir.path().join(".secrets"))?;

    let home_dir = tempdir()?;
    create_file(&home_dir.path().join(".config/gate-agent/secrets"))?;

    let env_path = OsString::from("/tmp/env-config.toml");

    let resolved = resolve_config_path_with(
        None,
        Some(env_path.as_os_str()),
        current_dir.path(),
        Some(home_dir.path()),
    )?;

    assert_eq!(resolved.path, PathBuf::from("/tmp/env-config.toml"));
    assert_eq!(resolved.source, ConfigPathSource::Env);

    Ok(())
}

#[test]
fn current_directory_default_wins_over_home_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let cwd_path = current_dir.path().join(".secrets");
    create_file(&cwd_path)?;

    let home_dir = tempdir()?;
    create_file(&home_dir.path().join(".config/gate-agent/secrets"))?;

    let resolved = resolve_config_path_with(None, None, current_dir.path(), Some(home_dir.path()))?;

    assert_eq!(resolved.path, cwd_path);
    assert_eq!(resolved.source, ConfigPathSource::CurrentDirectory);

    Ok(())
}

#[test]
fn home_fallback_is_used_when_current_directory_file_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;
    let home_path = home_dir.path().join(".config/gate-agent/secrets");
    create_file(&home_path)?;

    let resolved = resolve_config_path_with(None, None, current_dir.path(), Some(home_dir.path()))?;

    assert_eq!(resolved.path, home_path);
    assert_eq!(resolved.source, ConfigPathSource::Home);

    Ok(())
}

#[test]
fn config_update_uses_existing_home_file_when_local_file_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;
    let home_path = home_dir.path().join(".config/gate-agent/secrets");
    create_file(&home_path)?;

    let resolved =
        resolve_config_path_for_update_with(None, None, current_dir.path(), Some(home_dir.path()))?;

    assert_eq!(resolved.path, home_path);
    assert_eq!(resolved.source, ConfigPathSource::Home);
    assert!(resolved.exists);

    Ok(())
}

#[test]
fn blank_env_override_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;
    let blank_env = OsString::from("   ");

    let error = resolve_config_path_with(
        None,
        Some(blank_env.as_os_str()),
        current_dir.path(),
        Some(home_dir.path()),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "GATE_AGENT_CONFIG cannot be empty");

    Ok(())
}

#[test]
fn empty_cli_override_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;

    let error = resolve_config_path_with(
        Some(Path::new("")),
        None,
        current_dir.path(),
        Some(home_dir.path()),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "--config path cannot be empty");

    Ok(())
}

#[test]
fn whitespace_cli_override_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;

    let error = resolve_config_path_with(
        Some(Path::new("   ")),
        None,
        current_dir.path(),
        Some(home_dir.path()),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "--config path cannot be empty");

    Ok(())
}

#[test]
fn missing_defaults_reports_checked_locations() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;
    let cwd_candidate = current_dir.path().join(".secrets");
    let home_candidate = home_dir.path().join(".config/gate-agent/secrets");

    let error = resolve_config_path_with(None, None, current_dir.path(), Some(home_dir.path()))
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        format!(
            "no config file found; tried '{}' and '{}'",
            cwd_candidate.display(),
            home_candidate.display()
        )
    );

    Ok(())
}

#[test]
fn missing_home_is_reported_when_home_fallback_is_needed() -> Result<(), Box<dyn std::error::Error>>
{
    let current_dir = tempdir()?;
    let cwd_candidate = current_dir.path().join(".secrets");

    let error = resolve_config_path_with(None, None, current_dir.path(), None).unwrap_err();

    assert_eq!(
        error.to_string(),
        format!(
            "no config file found; tried '{}'; HOME is not set so ~/.config/gate-agent/secrets is unavailable",
            cwd_candidate.display()
        )
    );

    Ok(())
}

#[test]
fn config_update_uses_home_new_file_target_when_neither_location_exists_and_home_is_available()
-> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let home_dir = tempdir()?;
    let home_candidate = home_dir.path().join(".config/gate-agent/secrets");

    let resolved =
        resolve_config_path_for_update_with(None, None, current_dir.path(), Some(home_dir.path()))?;

    assert_eq!(resolved.path, home_candidate);
    assert_eq!(resolved.source, ConfigPathSource::Home);
    assert!(!resolved.exists);

    Ok(())
}

#[test]
fn config_update_uses_local_new_file_target_when_home_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let current_dir = tempdir()?;
    let local_candidate = current_dir.path().join(".secrets");

    let resolved = resolve_config_path_for_update_with(None, None, current_dir.path(), None)?;

    assert_eq!(resolved.path, local_candidate);
    assert_eq!(resolved.source, ConfigPathSource::CurrentDirectory);
    assert!(!resolved.exists);

    Ok(())
}
