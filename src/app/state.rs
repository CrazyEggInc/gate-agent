use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::{Client, redirect};
use secrecy::ExposeSecret;

use crate::config::ConfigSource;
use crate::config::app_config::AppConfig;
use crate::config::secrets::{ApiConfig, AuthConfig, ClientConfig, SecretsConfig};
use crate::error::AppError;
use crate::time::unix_timestamp_secs_i64;

#[derive(Clone, Debug)]
pub struct StartupSettings {
    pub bind: SocketAddr,
    pub log_level: String,
    pub config_source: ConfigSource,
}

#[derive(Clone, Debug)]
pub struct AppState {
    secrets: Arc<SecretsConfig>,
    client_slugs_by_api_key: Arc<BTreeMap<String, String>>,
    client: Client,
    startup: StartupSettings,
}

impl AppState {
    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        let client_slugs_by_api_key = index_client_api_keys(config.secrets())?;
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|error| AppError::Internal(format!("failed to build http client: {error}")))?;

        Ok(Self {
            secrets: Arc::new(config.secrets().clone()),
            client_slugs_by_api_key: Arc::new(client_slugs_by_api_key),
            client,
            startup: StartupSettings::from(config),
        })
    }

    pub fn secrets(&self) -> &SecretsConfig {
        self.secrets.as_ref()
    }

    pub fn auth_config(&self) -> &AuthConfig {
        &self.secrets().auth
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn startup(&self) -> &StartupSettings {
        &self.startup
    }

    pub fn client_for_api_key(&self, api_key: &str) -> Result<&ClientConfig, AppError> {
        if api_key.trim().is_empty() {
            return Err(AppError::InvalidToken);
        }

        let current_timestamp = unix_timestamp_secs_i64()?;
        let client_slug = self
            .client_slugs_by_api_key
            .get(api_key)
            .ok_or(AppError::InvalidToken)?;
        let client = self.secrets().clients.get(client_slug).ok_or_else(|| {
            AppError::Internal(format!("missing client config for '{client_slug}'"))
        })?;

        if client.api_key_expires_at.unix_timestamp() <= current_timestamp {
            return Err(AppError::InvalidToken);
        }

        Ok(client)
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

fn index_client_api_keys(secrets: &SecretsConfig) -> Result<BTreeMap<String, String>, AppError> {
    let mut client_slugs_by_api_key = BTreeMap::new();

    for client in secrets.clients.values() {
        let api_key = client.api_key.expose_secret().to_owned();

        if let Some(existing_client_slug) =
            client_slugs_by_api_key.insert(api_key, client.slug.clone())
        {
            return Err(AppError::Internal(format!(
                "duplicate client api_key for '{}' and '{}'",
                existing_client_slug, client.slug,
            )));
        }
    }

    Ok(client_slugs_by_api_key)
}

impl From<&AppConfig> for StartupSettings {
    fn from(config: &AppConfig) -> Self {
        Self {
            bind: config.bind(),
            log_level: config.log_level().to_owned(),
            config_source: config.config_source().clone(),
        }
    }
}
