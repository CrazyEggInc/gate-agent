use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use http::header::HeaderName;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use super::ConfigError;
use super::crypto::load_config_text;
use super::password::{
    PasswordArgs, PasswordSource, forget_keyring_password_if_present, remember_password_if_needed,
    resolve_for_encrypted_read_with_source,
};

pub const DEFAULT_API_TIMEOUT_MS: u64 = 5_000;
pub(crate) fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Debug)]
pub struct SecretsConfig {
    pub clients: BTreeMap<String, ClientConfig>,
    pub apis: BTreeMap<String, ApiConfig>,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub bearer_token_id: String,
    pub bearer_token_hash: BearerTokenHash,
    pub bearer_token_expires_at: UtcTimestamp,
    pub api_access: BTreeMap<String, AccessLevel>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerTokenHash(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    Read,
    Write,
}

impl AccessLevel {
    pub fn allows(self, required: Self) -> bool {
        self >= required
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtcTimestamp {
    raw: String,
    unix_timestamp: i64,
    nanosecond: u32,
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
    #[serde(default)]
    clients: BTreeMap<String, RawClientConfig>,
    #[serde(default)]
    groups: BTreeMap<String, RawGroupConfig>,
    #[serde(default)]
    apis: BTreeMap<String, RawApiConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientConfig {
    bearer_token_id: String,
    bearer_token_hash: String,
    bearer_token_expires_at: String,
    group: Option<String>,
    api_access: Option<BTreeMap<String, AccessLevel>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroupConfig {
    api_access: BTreeMap<String, AccessLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApiConfig {
    base_url: String,
    auth_header: String,
    auth_scheme: Option<String>,
    auth_value: String,
    #[serde(default = "default_api_timeout_ms")]
    timeout_ms: u64,
}

fn default_api_timeout_ms() -> u64 {
    DEFAULT_API_TIMEOUT_MS
}

impl SecretsConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        Self::load_from_file_with_password_args(path, &PasswordArgs { password: None })
    }

    pub fn load_from_file_with_password_args(
        path: &Path,
        password_args: &PasswordArgs,
    ) -> Result<Self, ConfigError> {
        let raw_contents = std::fs::read_to_string(path).map_err(|error| {
            ConfigError::new(format!(
                "failed to read config file '{}': {error}",
                path.display()
            ))
        })?;

        if super::crypto::detect_format(&raw_contents)
            == super::crypto::ConfigFileFormat::AgeEncryptedToml
        {
            let resolved = resolve_for_encrypted_read_with_source(password_args, path)?;

            match load_config_text(path, Some(&resolved.password)) {
                Ok(loaded) => {
                    remember_password_if_needed(path, &resolved);
                    return Self::parse_from_str(&loaded.toml, path);
                }
                Err(error) => {
                    if matches!(resolved.source, PasswordSource::Keyring)
                        && error.to_string().contains(&format!(
                            "invalid password for config file '{}'",
                            path.display()
                        ))
                    {
                        forget_keyring_password_if_present(path);
                    }

                    return Err(error);
                }
            }
        }

        let loaded = load_config_text(path, None)?;
        Self::parse_from_str(&loaded.toml, path)
    }

    pub fn parse(contents: &str, source_label: &str) -> Result<Self, ConfigError> {
        let raw_config: RawSecretsConfig = toml::from_str(contents).map_err(|error| {
            ConfigError::new(format!("failed to parse config {source_label}: {error}"))
        })?;

        Self::try_from_raw(raw_config)
    }

    pub fn parse_from_str(contents: &str, path: &Path) -> Result<Self, ConfigError> {
        let raw_config: RawSecretsConfig = toml::from_str(contents).map_err(|error| {
            ConfigError::new(format!(
                "failed to parse config file '{}': {error}",
                path.display()
            ))
        })?;

        Self::try_from_raw(raw_config)
    }

    fn try_from_raw(raw_config: RawSecretsConfig) -> Result<Self, ConfigError> {
        if raw_config.clients.is_empty() {
            return Err(ConfigError::new(
                "at least one [clients.*] entry is required",
            ));
        }

        let mut apis = BTreeMap::new();

        for (slug, raw_api) in raw_config.apis {
            let api = ApiConfig::try_from_raw(&slug, raw_api)?;
            apis.insert(slug, api);
        }

        let mut groups = BTreeMap::new();

        for (slug, raw_group) in raw_config.groups {
            validate_slug("group", &slug)?;
            let api_access = validate_api_access_map(
                &format!("groups.{slug}.api_access"),
                raw_group.api_access,
                &apis,
            )?;
            groups.insert(slug, api_access);
        }

        let mut clients = BTreeMap::new();
        let mut bearer_token_ids = BTreeSet::new();
        let mut bearer_token_hashes = BTreeSet::new();

        for (slug, raw_client) in raw_config.clients {
            let client = ClientConfig::try_from_raw(&slug, raw_client, &groups, &apis)?;

            if !bearer_token_ids.insert(client.bearer_token_id.clone()) {
                return Err(ConfigError::new(format!(
                    "clients.{slug}.bearer_token_id duplicates another configured client bearer_token_id"
                )));
            }

            if !bearer_token_hashes.insert(client.bearer_token_hash.as_str().to_owned()) {
                return Err(ConfigError::new(format!(
                    "clients.{slug}.bearer_token_hash duplicates another configured client bearer_token_hash"
                )));
            }

            clients.insert(slug, client);
        }

        Ok(Self { clients, apis })
    }

    pub fn default_client(&self) -> Result<&ClientConfig, ConfigError> {
        self.clients
            .get("default")
            .ok_or_else(|| ConfigError::new("missing required [clients.default] entry"))
    }

    pub fn client_by_bearer_token_id(&self, bearer_token_id: &str) -> Option<&ClientConfig> {
        self.clients
            .values()
            .find(|client| client.bearer_token_id == bearer_token_id)
    }

    pub fn client_slug_by_bearer_token_id(&self, bearer_token_id: &str) -> Option<&str> {
        self.clients
            .iter()
            .find(|(_, client)| client.bearer_token_id == bearer_token_id)
            .map(|(slug, _)| slug.as_str())
    }

    pub fn client_slug(&self, client: &ClientConfig) -> Option<&str> {
        self.client_slug_by_bearer_token_id(&client.bearer_token_id)
    }
}

impl ClientConfig {
    fn try_from_raw(
        slug: &str,
        raw_config: RawClientConfig,
        groups: &BTreeMap<String, BTreeMap<String, AccessLevel>>,
        apis: &BTreeMap<String, ApiConfig>,
    ) -> Result<Self, ConfigError> {
        validate_slug("client", slug)?;

        let bearer_token_id = required_string(
            &format!("clients.{slug}.bearer_token_id"),
            raw_config.bearer_token_id,
        )?;
        let bearer_token_hash = BearerTokenHash::parse(
            &format!("clients.{slug}.bearer_token_hash"),
            raw_config.bearer_token_hash,
        )?;
        let bearer_token_expires_at = UtcTimestamp::parse(
            &format!("clients.{slug}.bearer_token_expires_at"),
            raw_config.bearer_token_expires_at,
        )?;

        let api_access = match (raw_config.group, raw_config.api_access) {
            (Some(_group), Some(_)) => {
                return Err(ConfigError::new(format!(
                    "clients.{slug} must specify exactly one of group or api_access"
                )));
            }
            (None, None) => {
                return Err(ConfigError::new(format!(
                    "clients.{slug} must specify exactly one of group or api_access"
                )));
            }
            (Some(group), None) => {
                let group = required_string(&format!("clients.{slug}.group"), group)?;
                validate_slug("group", &group)?;
                groups.get(&group).cloned().ok_or_else(|| {
                    ConfigError::new(format!(
                        "clients.{slug}.group references unknown group '{group}'"
                    ))
                })?
            }
            (None, Some(api_access)) => {
                validate_api_access_map(&format!("clients.{slug}.api_access"), api_access, apis)?
            }
        };

        Ok(Self {
            bearer_token_id,
            bearer_token_hash,
            bearer_token_expires_at,
            api_access,
        })
    }
}

impl BearerTokenHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_token(token: &str) -> Self {
        let digest = Sha256::digest(token.as_bytes());
        Self(hex_lower(&digest))
    }

    pub fn matches_token(&self, token: &str) -> bool {
        let digest = Sha256::digest(token.as_bytes());
        decode_hex_32(&self.0)
            .as_slice()
            .ct_eq(digest.as_slice())
            .into()
    }

    fn parse(field: &str, value: String) -> Result<Self, ConfigError> {
        let value = required_string(field, value)?;

        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::new(format!(
                "{field} must be a 64-character lowercase SHA-256 hex digest"
            )));
        }

        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ConfigError::new(format!(
                "{field} must be a 64-character lowercase SHA-256 hex digest"
            )));
        }

        Ok(Self(value))
    }
}

impl UtcTimestamp {
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn unix_timestamp(&self) -> i64 {
        self.unix_timestamp
    }

    pub fn nanosecond(&self) -> u32 {
        self.nanosecond
    }

    fn parse(field: &str, value: String) -> Result<Self, ConfigError> {
        let raw = required_string(field, value)?;

        if !raw.contains('T') || !raw.ends_with('Z') {
            return Err(ConfigError::new(format!(
                "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
            )));
        }

        let parsed = toml::value::Datetime::from_str(&raw).map_err(|_| {
            ConfigError::new(format!(
                "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
            ))
        })?;

        let Some(date) = parsed.date else {
            return Err(ConfigError::new(format!(
                "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
            )));
        };
        let Some(time) = parsed.time else {
            return Err(ConfigError::new(format!(
                "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
            )));
        };

        match parsed.offset {
            Some(toml::value::Offset::Z) => {}
            _ => {
                return Err(ConfigError::new(format!(
                    "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
                )));
            }
        }

        validate_date(field, date.year as i32, date.month, date.day)?;

        let unix_timestamp = unix_timestamp_from_utc(
            field,
            date.year as i32,
            date.month,
            date.day,
            time.hour,
            time.minute,
            time.second,
        )?;

        Ok(Self {
            raw,
            unix_timestamp,
            nanosecond: time.nanosecond,
        })
    }
}

impl ApiConfig {
    fn try_from_raw(slug: &str, raw_config: RawApiConfig) -> Result<Self, ConfigError> {
        validate_slug("api", slug)?;

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

fn validate_slug(kind: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::new(format!("{kind} slug cannot be empty")));
    }

    if value != value.to_ascii_lowercase() {
        return Err(ConfigError::new(format!(
            "{kind} slug '{value}' must be lowercase"
        )));
    }

    if !is_valid_slug(value) {
        return Err(ConfigError::new(format!(
            "{kind} slug '{value}' must contain only lowercase letters, digits, or hyphen"
        )));
    }

    Ok(())
}

fn validate_api_access_map(
    field: &str,
    api_access: BTreeMap<String, AccessLevel>,
    apis: &BTreeMap<String, ApiConfig>,
) -> Result<BTreeMap<String, AccessLevel>, ConfigError> {
    let mut validated = BTreeMap::new();

    for (api_slug, access_level) in api_access {
        if !is_valid_slug(&api_slug) {
            return Err(ConfigError::new(format!(
                "{field} contains invalid api slug '{api_slug}'"
            )));
        }

        if !apis.contains_key(&api_slug) {
            return Err(ConfigError::new(format!(
                "{field} contains unknown api '{api_slug}'"
            )));
        }

        validated.insert(api_slug, access_level);
    }

    Ok(validated)
}

fn validate_date(field: &str, year: i32, month: u8, day: u8) -> Result<(), ConfigError> {
    if !(1..=12).contains(&month) {
        return Err(ConfigError::new(format!(
            "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
        )));
    }

    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => unreachable!(),
    };

    if day == 0 || day > max_day {
        return Err(ConfigError::new(format!(
            "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
        )));
    }

    Ok(())
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn unix_timestamp_from_utc(
    field: &str,
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Result<i64, ConfigError> {
    if hour > 23 || minute > 59 || second > 59 {
        return Err(ConfigError::new(format!(
            "{field} must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
        )));
    }

    let year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    let hour = i64::from(hour);
    let minute = i64::from(minute);
    let second = i64::from(second);

    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146_097 + day_of_era - 719_468;

    Ok(days_since_epoch * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }

    output
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];

    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }

    output
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hex digest"),
    }
}
