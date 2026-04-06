use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use reqwest::{Client, redirect};

use crate::config::app_config::AppConfig;
use crate::config::secrets::{ApiConfig, SecretsConfig};
use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct StartupSettings {
    pub bind: SocketAddr,
    pub log_level: String,
    pub secrets_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct AppState {
    secrets: Arc<SecretsConfig>,
    client: Client,
    startup: StartupSettings,
}

impl AppState {
    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|error| AppError::Internal(format!("failed to build http client: {error}")))?;

        Ok(Self {
            secrets: Arc::new(config.secrets.clone()),
            client,
            startup: StartupSettings::from(config),
        })
    }

    pub fn secrets(&self) -> &SecretsConfig {
        self.secrets.as_ref()
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn startup(&self) -> &StartupSettings {
        &self.startup
    }

    pub fn api_config(&self, api: &str) -> Result<&ApiConfig, AppError> {
        self.secrets()
            .apis
            .get(api)
            .ok_or_else(|| AppError::ForbiddenApi {
                api: api.to_owned(),
            })
    }
}

impl From<&AppConfig> for StartupSettings {
    fn from(config: &AppConfig) -> Self {
        Self {
            bind: config.bind,
            log_level: config.log_level.clone(),
            secrets_file: config.secrets_file.clone(),
        }
    }
}
