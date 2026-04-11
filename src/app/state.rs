use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::{Client, redirect};

use crate::config::ConfigSource;
use crate::config::app_config::AppConfig;
use crate::config::secrets::{AccessLevel, ApiConfig, ClientConfig, SecretsConfig};
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
    client_slugs_by_bearer_token_id: Arc<BTreeMap<String, String>>,
    client: Client,
    startup: StartupSettings,
}

impl AppState {
    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        let client_slugs_by_bearer_token_id = index_client_bearer_token_ids(config.secrets())?;
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|error| AppError::Internal(format!("failed to build http client: {error}")))?;

        Ok(Self {
            secrets: Arc::new(config.secrets().clone()),
            client_slugs_by_bearer_token_id: Arc::new(client_slugs_by_bearer_token_id),
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

    pub fn client_for_bearer_token(&self, token: &str) -> Result<&ClientConfig, AppError> {
        if token.trim().is_empty() {
            return Err(AppError::InvalidToken);
        }

        let bearer_token_id = parse_bearer_token_id(token)?;
        let current_timestamp = unix_timestamp_secs_i64()?;
        let client_slug = self
            .client_slugs_by_bearer_token_id
            .get(bearer_token_id)
            .ok_or(AppError::InvalidToken)?;
        let client = self.secrets().clients.get(client_slug).ok_or_else(|| {
            AppError::Internal(format!("missing client config for '{client_slug}'"))
        })?;

        if client.bearer_token_expires_at.unix_timestamp() <= current_timestamp {
            return Err(AppError::InvalidToken);
        }

        if !client.bearer_token_hash.matches_token(token) {
            return Err(AppError::InvalidToken);
        }

        Ok(client)
    }

    pub fn client_api_access(
        &self,
        client: &ClientConfig,
        api: &str,
    ) -> Result<AccessLevel, AppError> {
        if !self.secrets().apis.contains_key(api) {
            return Err(AppError::ForbiddenApi {
                api: api.to_owned(),
            });
        }

        client
            .api_access
            .get(api)
            .copied()
            .ok_or_else(|| AppError::ForbiddenApi {
                api: api.to_owned(),
            })
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

fn index_client_bearer_token_ids(
    secrets: &SecretsConfig,
) -> Result<BTreeMap<String, String>, AppError> {
    let mut client_slugs_by_bearer_token_id = BTreeMap::new();

    for client in secrets.clients.values() {
        let client_slug = secrets.client_slug(client).ok_or_else(|| {
            AppError::Internal("missing client slug for configured bearer token".to_owned())
        })?;

        if let Some(existing_client_slug) = client_slugs_by_bearer_token_id
            .insert(client.bearer_token_id.clone(), client_slug.to_owned())
        {
            return Err(AppError::Internal(format!(
                "duplicate client bearer token id for '{}' and '{}'",
                existing_client_slug, client_slug,
            )));
        }
    }

    Ok(client_slugs_by_bearer_token_id)
}

fn parse_bearer_token_id(token: &str) -> Result<&str, AppError> {
    let (token_id, secret) = token.split_once('.').ok_or(AppError::InvalidToken)?;

    if token_id.is_empty() || secret.is_empty() || secret.contains('.') {
        return Err(AppError::InvalidToken);
    }

    Ok(token_id)
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
