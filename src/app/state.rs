use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::{Client, redirect};

use crate::auth::bearer::validate_token;
use crate::config::ConfigSource;
use crate::config::app_config::AppConfig;
use crate::config::secrets::{AccessLevel, ApiConfig, ClientConfig, SecretsConfig};
use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct StartupSettings {
    pub bind: SocketAddr,
    pub log_level: String,
    pub config_source: ConfigSource,
}

#[derive(Clone, Debug)]
pub struct AppState {
    secrets: Arc<SecretsConfig>,
    client: Client,
    startup: StartupSettings,
}

#[derive(Clone, Copy, Debug)]
pub struct ClientApiAccessEntry<'a> {
    pub access_level: AccessLevel,
    pub api_config: &'a ApiConfig,
}

impl AppState {
    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        let client = Client::builder()
            .redirect(redirect::Policy::limited(10))
            .build()
            .map_err(|error| AppError::Internal(format!("failed to build http client: {error}")))?;

        Ok(Self {
            secrets: Arc::new(config.secrets().clone()),
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
        let authorized_request = validate_token(token, self.secrets())?;
        let client_slug = &authorized_request.client_slug;
        let client = self.secrets().clients.get(client_slug).ok_or_else(|| {
            AppError::Internal(format!("missing client config for '{client_slug}'"))
        })?;

        Ok(client)
    }

    pub fn client_api_access(
        &self,
        client: &ClientConfig,
        api: &str,
    ) -> Result<AccessLevel, AppError> {
        Ok(self.client_api_access_entry(client, api)?.access_level)
    }

    pub fn client_api_access_entry<'a>(
        &'a self,
        client: &ClientConfig,
        api: &str,
    ) -> Result<ClientApiAccessEntry<'a>, AppError> {
        let api_config = self.api_config(api)?;
        let access_level =
            client
                .api_access
                .get(api)
                .copied()
                .ok_or_else(|| AppError::ForbiddenApi {
                    api: api.to_owned(),
                })?;

        Ok(ClientApiAccessEntry {
            access_level,
            api_config,
        })
    }

    pub fn client_api_access_entries<'a>(
        &'a self,
        client: &ClientConfig,
    ) -> Result<Vec<ClientApiAccessEntry<'a>>, AppError> {
        client
            .api_access
            .iter()
            .map(|(api, access_level)| {
                Ok(ClientApiAccessEntry {
                    access_level: *access_level,
                    api_config: self.api_config(api)?,
                })
            })
            .collect()
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
            bind: config.bind(),
            log_level: config.log_level().to_owned(),
            config_source: config.config_source().clone(),
        }
    }
}
