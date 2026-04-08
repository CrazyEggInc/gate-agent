use std::net::SocketAddr;
use std::path::PathBuf;

use crate::cli::StartArgs;

use super::ConfigError;
use super::path::{LOCAL_CONFIG_FILE, resolve_config_path};
use super::secrets::SecretsConfig;

pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const DEFAULT_CONFIG_FILE: &str = LOCAL_CONFIG_FILE;
pub const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub log_level: String,
    pub config_file: PathBuf,
    pub secrets: SecretsConfig,
}

impl AppConfig {
    pub fn from_start_args(args: &StartArgs) -> Result<Self, ConfigError> {
        let log_level = args.log_level.trim();

        if log_level.is_empty() {
            return Err(ConfigError::new("log level cannot be empty"));
        }

        let config_path = resolve_config_path(args.config.as_deref())?.path;
        let secrets = SecretsConfig::load_from_file(&config_path)?;

        Ok(Self {
            bind: args.bind,
            log_level: log_level.to_owned(),
            config_file: config_path,
            secrets,
        })
    }
}
