use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::cli::StartArgs;
use crate::config::app_config::{AppConfig, DEFAULT_BIND};
use crate::config::path::resolve_config_path_for_update;
use crate::config::write::{self, ApiUpsert, ClientUpsert, WriteConfigError};

#[derive(Debug)]
pub struct ConfigCommandError {
    message: String,
}

impl ConfigCommandError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn json_message(message: impl Into<String>) -> Self {
        Self::new(serialize_json_error(message.into()))
    }
}

impl Display for ConfigCommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigCommandError {}

impl From<WriteConfigError> for ConfigCommandError {
    fn from(error: WriteConfigError) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Debug, Serialize)]
struct ValidateErrorPayload {
    errors: Vec<ValidateErrorMessage>,
}

#[derive(Debug, Serialize)]
struct ValidateErrorMessage {
    message: String,
}

fn serialize_json_error(message: String) -> String {
    serde_json::to_string(&ValidateErrorPayload {
        errors: vec![ValidateErrorMessage { message }],
    })
    .expect("validate error payload should serialize")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigInitArgs {
    pub config: Option<PathBuf>,
    pub log_level: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigValidateArgs {
    pub config: Option<PathBuf>,
    pub log_level: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigAddApiArgs {
    pub config: Option<PathBuf>,
    pub log_level: String,
    pub name: String,
    pub base_url: String,
    pub auth_header: String,
    pub auth_scheme: Option<String>,
    pub auth_value: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigAddClientArgs {
    pub config: Option<PathBuf>,
    pub log_level: String,
    pub name: String,
    pub api_key: Option<String>,
    pub api_key_expires_at: Option<String>,
    pub allowed_apis: Vec<String>,
}

pub fn init(args: ConfigInitArgs) -> Result<PathBuf, ConfigCommandError> {
    let path = resolve_target_path(args.config.as_deref())?;
    write::init_config(&path)?;
    Ok(path)
}

pub fn validate(args: ConfigValidateArgs) -> Result<String, ConfigCommandError> {
    let start_args = StartArgs {
        bind: DEFAULT_BIND
            .parse()
            .expect("default bind address should parse"),
        config: args.config,
        log_level: args.log_level,
    };

    AppConfig::from_start_args(&start_args)
        .map(|_| "config is valid".to_owned())
        .map_err(|error| ConfigCommandError::json_message(error.to_string()))
}

pub fn add_api(args: ConfigAddApiArgs) -> Result<PathBuf, ConfigCommandError> {
    ensure_slug("api", &args.name)?;

    let base_url = trimmed_required("base_url", &args.base_url)?;
    validate_base_url(&base_url, &args.name)?;
    let auth_header = trimmed_required("auth_header", &args.auth_header)?;
    validate_header_name(&auth_header, &args.name)?;
    let auth_value = trimmed_required("auth_value", &args.auth_value)?;

    if args.timeout_ms == 0 {
        return Err(ConfigCommandError::new(format!(
            "apis.{}.timeout_ms must be greater than 0",
            args.name
        )));
    }

    let auth_scheme = match args.auth_scheme {
        Some(value) => Some(trimmed_required("auth_scheme", &value)?),
        None => None,
    };

    let path = resolve_target_path(args.config.as_deref())?;
    ensure_config_exists(&path)?;
    write::upsert_api(
        &path,
        &ApiUpsert {
            name: args.name,
            base_url,
            auth_header,
            auth_scheme,
            auth_value,
            timeout_ms: args.timeout_ms,
        },
    )?;

    Ok(path)
}

pub fn add_client(args: ConfigAddClientArgs) -> Result<PathBuf, ConfigCommandError> {
    ensure_slug("client", &args.name)?;

    let api_key = args
        .api_key
        .as_deref()
        .map(|value| trimmed_required("api_key", value))
        .transpose()?;

    let api_key_expires_at = args
        .api_key_expires_at
        .as_deref()
        .map(|value| {
            let value = trimmed_required("api_key_expires_at", value)?;
            validate_timestamp(&value)?;
            Ok::<String, ConfigCommandError>(value)
        })
        .transpose()?;

    let mut allowed_apis = args.allowed_apis;
    allowed_apis.sort();
    allowed_apis.dedup();

    for api in &allowed_apis {
        ensure_slug("allowed api", api)?;
    }

    let path = resolve_target_path(args.config.as_deref())?;
    ensure_config_exists(&path)?;
    write::upsert_client(
        &path,
        &ClientUpsert {
            name: args.name,
            api_key,
            api_key_expires_at,
            allowed_apis,
        },
    )?;

    Ok(path)
}

fn resolve_target_path(
    cli_override: Option<&std::path::Path>,
) -> Result<PathBuf, ConfigCommandError> {
    let resolved = resolve_config_path_for_update(cli_override)
        .map_err(|error| ConfigCommandError::new(error.to_string()))?;

    Ok(resolved.path)
}

fn ensure_config_exists(path: &std::path::Path) -> Result<(), ConfigCommandError> {
    if path.exists() {
        return Ok(());
    }

    write::init_config(path)?;
    Ok(())
}

fn trimmed_required(field: &str, value: &str) -> Result<String, ConfigCommandError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ConfigCommandError::new(format!("{field} cannot be empty")));
    }

    Ok(trimmed.to_owned())
}

fn ensure_slug(kind: &str, value: &str) -> Result<(), ConfigCommandError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ConfigCommandError::new(format!(
            "{kind} slug cannot be empty"
        )));
    }

    if trimmed != value {
        return Err(ConfigCommandError::new(format!(
            "{kind} slug cannot contain surrounding whitespace"
        )));
    }

    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ConfigCommandError::new(format!(
            "{kind} slug '{trimmed}' must contain only lowercase letters, digits, or hyphen"
        )));
    }

    Ok(())
}

fn validate_base_url(base_url: &str, slug: &str) -> Result<(), ConfigCommandError> {
    let parsed = reqwest::Url::parse(base_url).map_err(|error| {
        ConfigCommandError::new(format!("apis.{slug}.base_url is invalid: {error}"))
    })?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ConfigCommandError::new(format!(
            "apis.{slug}.base_url must use http or https"
        )));
    }

    Ok(())
}

fn validate_header_name(header: &str, slug: &str) -> Result<(), ConfigCommandError> {
    http::header::HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
        ConfigCommandError::new(format!("apis.{slug}.auth_header is invalid: {error}"))
    })?;

    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), ConfigCommandError> {
    parse_rfc3339_utc(value)
        .map(|_| ())
        .map_err(|error| ConfigCommandError::new(format!("invalid api_key_expires_at: {error}")))
}

fn parse_rfc3339_utc(value: &str) -> Result<SystemTime, &'static str> {
    if value.len() != 20 {
        return Err("timestamp must look like 2030-01-02T03:04:05Z");
    }

    if &value[4..5] != "-"
        || &value[7..8] != "-"
        || &value[10..11] != "T"
        || &value[13..14] != ":"
        || &value[16..17] != ":"
        || &value[19..20] != "Z"
    {
        return Err("timestamp must look like 2030-01-02T03:04:05Z");
    }

    let year: i32 = value[0..4].parse().map_err(|_| "invalid year")?;
    let month: u32 = value[5..7].parse().map_err(|_| "invalid month")?;
    let day: u32 = value[8..10].parse().map_err(|_| "invalid day")?;
    let hour: u64 = value[11..13].parse().map_err(|_| "invalid hour")?;
    let minute: u64 = value[14..16].parse().map_err(|_| "invalid minute")?;
    let second: u64 = value[17..19].parse().map_err(|_| "invalid second")?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err("timestamp contains out-of-range values");
    }

    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_index = month as i32;
    let day_index = day as i32;
    let day_of_year =
        (153 * (month_index + if month_index > 2 { -3 } else { 9 }) + 2) / 5 + day_index - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era as i64 * 146_097 + day_of_era as i64 - 719_468;

    let (parsed_year, parsed_month, parsed_day) = civil_from_days(days);
    if parsed_year != i64::from(year)
        || parsed_month != i64::from(month)
        || parsed_day != i64::from(day)
    {
        return Err("invalid calendar date");
    }

    if days < 0 {
        return Err("timestamp predates unix epoch");
    }

    Ok(
        UNIX_EPOCH
            + Duration::from_secs(days as u64 * 86_400 + hour * 3_600 + minute * 60 + second),
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_param = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_param + 2) / 5 + 1;
    let month = month_param + if month_param < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year, month, day)
}
