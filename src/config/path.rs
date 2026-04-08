use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::ConfigError;

pub const CONFIG_ENV_VAR: &str = "GATE_AGENT_CONFIG";
pub const LOCAL_CONFIG_FILE: &str = ".secrets";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigPathSource {
    Cli,
    Env,
    CurrentDirectory,
    Home,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfigPath {
    pub path: PathBuf,
    pub source: ConfigPathSource,
    pub exists: bool,
}

pub fn resolve_config_path(cli_override: Option<&Path>) -> Result<ResolvedConfigPath, ConfigError> {
    resolve_config_path_with_mode(cli_override, ResolveMode::ReadExisting)
}

pub fn resolve_config_path_for_update(
    cli_override: Option<&Path>,
) -> Result<ResolvedConfigPath, ConfigError> {
    resolve_config_path_with_mode(cli_override, ResolveMode::WriteTarget)
}

fn resolve_config_path_with_mode(
    cli_override: Option<&Path>,
    mode: ResolveMode,
) -> Result<ResolvedConfigPath, ConfigError> {
    let current_dir = env::current_dir().map_err(|error| {
        ConfigError::new(format!("failed to resolve current directory: {error}"))
    })?;
    let home_dir = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    resolve_config_path_with_mode_and_inputs(
        cli_override,
        env::var_os(CONFIG_ENV_VAR).as_deref(),
        &current_dir,
        home_dir.as_deref(),
        mode,
    )
}

pub fn resolve_config_path_with(
    cli_override: Option<&Path>,
    env_override: Option<&OsStr>,
    current_dir: &Path,
    home_dir: Option<&Path>,
) -> Result<ResolvedConfigPath, ConfigError> {
    resolve_config_path_with_mode_and_inputs(
        cli_override,
        env_override,
        current_dir,
        home_dir,
        ResolveMode::ReadExisting,
    )
}

pub fn resolve_config_path_for_update_with(
    cli_override: Option<&Path>,
    env_override: Option<&OsStr>,
    current_dir: &Path,
    home_dir: Option<&Path>,
) -> Result<ResolvedConfigPath, ConfigError> {
    resolve_config_path_with_mode_and_inputs(
        cli_override,
        env_override,
        current_dir,
        home_dir,
        ResolveMode::WriteTarget,
    )
}

fn resolve_config_path_with_mode_and_inputs(
    cli_override: Option<&Path>,
    env_override: Option<&OsStr>,
    current_dir: &Path,
    home_dir: Option<&Path>,
    mode: ResolveMode,
) -> Result<ResolvedConfigPath, ConfigError> {
    if let Some(path) = cli_override {
        if path.to_string_lossy().trim().is_empty() {
            return Err(ConfigError::new("--config path cannot be empty"));
        }

        return Ok(ResolvedConfigPath {
            path: path.to_path_buf(),
            source: ConfigPathSource::Cli,
            exists: path.is_file(),
        });
    }

    if let Some(path) = env_override {
        if path.to_string_lossy().trim().is_empty() {
            return Err(ConfigError::new("GATE_AGENT_CONFIG cannot be empty"));
        }

        return Ok(ResolvedConfigPath {
            path: PathBuf::from(path),
            source: ConfigPathSource::Env,
            exists: PathBuf::from(path).is_file(),
        });
    }

    let current_directory_path = current_dir.join(LOCAL_CONFIG_FILE);
    if current_directory_path.is_file() {
        return Ok(ResolvedConfigPath {
            path: current_directory_path,
            source: ConfigPathSource::CurrentDirectory,
            exists: true,
        });
    }

    let home_config_path = home_dir.map(home_config_path);
    if let Some(path) = home_config_path.as_ref().filter(|path| path.is_file()) {
        return Ok(ResolvedConfigPath {
            path: path.clone(),
            source: ConfigPathSource::Home,
            exists: true,
        });
    }

    if matches!(mode, ResolveMode::WriteTarget) {
        return Ok(ResolvedConfigPath {
            path: current_directory_path,
            source: ConfigPathSource::CurrentDirectory,
            exists: false,
        });
    }

    Err(not_found_error(
        &current_directory_path,
        home_config_path.as_deref(),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolveMode {
    ReadExisting,
    WriteTarget,
}

fn home_config_path(home_dir: &Path) -> PathBuf {
    home_dir.join(".config/gate-agent/secrets")
}

fn not_found_error(current_directory_path: &Path, home_config_path: Option<&Path>) -> ConfigError {
    match home_config_path {
        Some(home_config_path) => ConfigError::new(format!(
            "no config file found; tried '{}' and '{}'",
            current_directory_path.display(),
            home_config_path.display()
        )),
        None => ConfigError::new(format!(
            "no config file found; tried '{}'; HOME is not set so ~/.config/gate-agent/secrets is unavailable",
            current_directory_path.display()
        )),
    }
}
