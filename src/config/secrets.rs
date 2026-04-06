use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use http::header::HeaderName;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use super::ConfigError;

#[derive(Clone, Debug)]
pub struct SecretsConfig {
    pub jwt: JwtConfig,
    pub apis: BTreeMap<String, ApiConfig>,
}

#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub algorithm: JwtAlgorithm,
    pub issuer: String,
    pub audience: String,
    pub shared_secret: SecretString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JwtAlgorithm {
    Hs256,
}

#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub slug: String,
    pub base_url: Url,
    pub auth_header: HeaderName,
    pub auth_scheme: Option<String>,
    pub auth_value: SecretString,
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretsConfig {
    jwt: Option<RawJwtConfig>,
    #[serde(default)]
    apis: BTreeMap<String, RawApiConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJwtConfig {
    algorithm: String,
    issuer: String,
    audience: String,
    shared_secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApiConfig {
    base_url: String,
    auth_header: String,
    auth_scheme: Option<String>,
    auth_value: String,
    timeout_ms: u64,
}

impl SecretsConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|error| {
            ConfigError::new(format!(
                "failed to read secrets file '{}': {error}",
                path.display()
            ))
        })?;

        let raw_config: RawSecretsConfig = toml::from_str(&contents).map_err(|error| {
            ConfigError::new(format!(
                "failed to parse secrets file '{}': {error}",
                path.display()
            ))
        })?;

        Self::try_from_raw(raw_config)
    }

    fn try_from_raw(raw_config: RawSecretsConfig) -> Result<Self, ConfigError> {
        let jwt = JwtConfig::try_from_raw(
            raw_config
                .jwt
                .ok_or_else(|| ConfigError::new("missing [jwt] section"))?,
        )?;

        if raw_config.apis.is_empty() {
            return Err(ConfigError::new("at least one [apis.*] entry is required"));
        }

        let mut apis = BTreeMap::new();

        for (slug, raw_api) in raw_config.apis {
            let api = ApiConfig::try_from_raw(&slug, raw_api)?;
            apis.insert(slug, api);
        }

        Ok(Self { jwt, apis })
    }
}

impl JwtConfig {
    fn try_from_raw(raw_config: RawJwtConfig) -> Result<Self, ConfigError> {
        let algorithm = match raw_config.algorithm.trim() {
            "HS256" => JwtAlgorithm::Hs256,
            algorithm => {
                return Err(ConfigError::new(format!(
                    "jwt.algorithm must be HS256, got '{algorithm}'"
                )));
            }
        };

        let issuer = required_string("jwt.issuer", raw_config.issuer)?;
        let audience = required_string("jwt.audience", raw_config.audience)?;
        let shared_secret = SecretString::from(required_string(
            "jwt.shared_secret",
            raw_config.shared_secret,
        )?);

        Ok(Self {
            algorithm,
            issuer,
            audience,
            shared_secret,
        })
    }
}

impl ApiConfig {
    fn try_from_raw(slug: &str, raw_config: RawApiConfig) -> Result<Self, ConfigError> {
        if slug.trim().is_empty() {
            return Err(ConfigError::new("api slug cannot be empty"));
        }

        if slug != slug.to_ascii_lowercase() {
            return Err(ConfigError::new(format!(
                "api slug '{slug}' must be lowercase"
            )));
        }

        let base_url = Url::parse(&required_string(
            &format!("apis.{slug}.base_url"),
            raw_config.base_url,
        )?)
        .map_err(|error| ConfigError::new(format!("apis.{slug}.base_url is invalid: {error}")))?;

        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(ConfigError::new(format!(
                "apis.{slug}.base_url must use http or https"
            )));
        }

        let auth_header = HeaderName::from_bytes(
            required_string(&format!("apis.{slug}.auth_header"), raw_config.auth_header)?
                .as_bytes(),
        )
        .map_err(|error| {
            ConfigError::new(format!("apis.{slug}.auth_header is invalid: {error}"))
        })?;

        let auth_scheme =
            optional_string(&format!("apis.{slug}.auth_scheme"), raw_config.auth_scheme)?;
        let auth_value = SecretString::from(required_string(
            &format!("apis.{slug}.auth_value"),
            raw_config.auth_value,
        )?);

        if raw_config.timeout_ms == 0 {
            return Err(ConfigError::new(format!(
                "apis.{slug}.timeout_ms must be greater than 0"
            )));
        }

        Ok(Self {
            slug: slug.to_owned(),
            base_url,
            auth_header,
            auth_scheme,
            auth_value,
            timeout_ms: raw_config.timeout_ms,
        })
    }
}

fn required_string(field: &str, value: String) -> Result<String, ConfigError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ConfigError::new(format!("{field} cannot be empty")));
    }

    Ok(trimmed.to_owned())
}

fn optional_string(field: &str, value: Option<String>) -> Result<Option<String>, ConfigError> {
    value.map(|value| required_string(field, value)).transpose()
}
