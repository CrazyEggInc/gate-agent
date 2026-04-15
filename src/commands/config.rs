use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Display, Formatter};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use toml_edit::{DocumentMut, Table};

use crate::cli::StartArgs;
use crate::config::ConfigError;
use crate::config::app_config::AppConfig;
use crate::config::password::{
    PasswordArgs, PasswordSource, forget_keyring_password_if_present, remember_password_if_needed,
    resolve_for_encrypted_create, resolve_for_encrypted_read,
    resolve_for_encrypted_read_with_source,
};
use crate::config::path::{resolve_config_path, resolve_config_path_for_update};
use crate::config::secrets::SecretsConfig;
use crate::config::secrets::{AccessLevel, is_valid_slug};
use crate::config::write::{
    self, ApiUpsert, ClientAccessUpsert, ClientUpsert, GroupUpsert, WriteConfigError,
};

const TEST_PROMPT_INPUTS_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_INPUTS";
pub(crate) const DISABLE_INTERACTIVE_ENV_VAR: &str = "GATE_AGENT_DISABLE_INTERACTIVE";

static TEST_PROMPT_STATE: OnceLock<Mutex<TestPromptState>> = OnceLock::new();

#[derive(Debug, Default)]
struct TestPromptState {
    raw: Option<String>,
    values: VecDeque<String>,
}

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

impl From<ConfigError> for ConfigCommandError {
    fn from(error: ConfigError) -> Self {
        Self::new(error.to_string())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigInitArgs {
    pub config: Option<PathBuf>,
    pub encrypted: bool,
    pub password: Option<String>,
    pub log_level: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigShowArgs {
    pub config: Option<PathBuf>,
    pub password: Option<String>,
    pub log_level: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigEditArgs {
    pub config: Option<PathBuf>,
    pub password: Option<String>,
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
    pub password: Option<String>,
    pub log_level: String,
    pub name: String,
    pub base_url: String,
    pub auth_header: Option<String>,
    pub auth_value: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigAddClientArgs {
    pub config: Option<PathBuf>,
    pub password: Option<String>,
    pub log_level: String,
    pub name: String,
    pub bearer_token_expires_at: Option<String>,
    pub group: Option<String>,
    pub api_access: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigAddGroupArgs {
    pub config: Option<PathBuf>,
    pub password: Option<String>,
    pub log_level: String,
    pub name: String,
    pub api_access: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddClientOutcome {
    pub path: PathBuf,
    pub generated_bearer_token: Option<String>,
    pub bearer_token_expires_at: String,
}

pub fn init(args: ConfigInitArgs) -> Result<PathBuf, ConfigCommandError> {
    init_with_server(
        args,
        crate::config::secrets::DEFAULT_SERVER_BIND,
        crate::config::secrets::DEFAULT_SERVER_PORT,
    )
}

pub fn init_with_server(
    args: ConfigInitArgs,
    server_bind: &str,
    server_port: u16,
) -> Result<PathBuf, ConfigCommandError> {
    let path = resolve_target_path(args.config.as_deref())?;

    if path.exists() {
        return Err(ConfigCommandError::new(format!(
            "config file '{}' already exists",
            path.display()
        )));
    }

    let password_args = PasswordArgs {
        password: args.password,
    };
    let password = if args.encrypted {
        Some(resolve_for_encrypted_create(&password_args, &path)?.password)
    } else {
        None
    };

    let default_bearer_token = write::init_config_with_default_bearer_token_and_server(
        &path,
        args.encrypted,
        password.as_ref(),
        server_bind,
        server_port,
    )?;

    if args.encrypted {
        forget_keyring_password_if_present(&path);
    }

    print_generated_bearer_token("default", &default_bearer_token);

    Ok(path)
}

pub(crate) fn default_init_config_path() -> Result<PathBuf, ConfigCommandError> {
    resolve_target_path(None)
}

pub fn show(args: ConfigShowArgs) -> Result<String, ConfigCommandError> {
    let path = resolve_existing_path(args.config.as_deref())?;
    let password_args = PasswordArgs {
        password: args.password,
    };
    let raw_contents = std::fs::read_to_string(&path).map_err(|error| {
        ConfigCommandError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })?;
    let password = if crate::config::crypto::detect_format(&raw_contents)
        == crate::config::crypto::ConfigFileFormat::AgeEncryptedToml
    {
        let resolved = resolve_for_encrypted_read_with_source(&password_args, &path)?;

        match write::load_display_text(&path, Some(&resolved.password)) {
            Ok(loaded) => {
                remember_password_if_needed(&path, &resolved);
                return Ok(loaded.toml);
            }
            Err(error) => {
                if matches!(resolved.source, PasswordSource::Keyring)
                    && error.to_string().contains(&format!(
                        "invalid password for config file '{}'",
                        path.display()
                    ))
                {
                    forget_keyring_password_if_present(&path);
                }

                return Err(error.into());
            }
        }
    } else {
        None
    };

    let loaded = write::load_display_text(&path, password.as_ref())?;
    Ok(loaded.toml)
}

pub fn edit(args: ConfigEditArgs) -> Result<PathBuf, ConfigCommandError> {
    let path = resolve_existing_path(args.config.as_deref())?;
    let password_args = PasswordArgs {
        password: args.password,
    };
    let raw_contents = std::fs::read_to_string(&path).map_err(|error| {
        ConfigCommandError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })?;
    let encrypted = crate::config::crypto::detect_format(&raw_contents)
        == crate::config::crypto::ConfigFileFormat::AgeEncryptedToml;
    if encrypted {
        let resolved = resolve_for_encrypted_read_with_source(&password_args, &path)?;

        match write::load_display_text(&path, Some(&resolved.password)) {
            Ok(loaded) => {
                remember_password_if_needed(&path, &resolved);

                let mut temp_file = tempfile::NamedTempFile::new().map_err(|error| {
                    ConfigCommandError::new(format!(
                        "failed to create temporary edit file: {error}"
                    ))
                })?;
                std::io::Write::write_all(&mut temp_file, loaded.toml.as_bytes()).map_err(
                    |error| {
                        ConfigCommandError::new(format!(
                            "failed to write temporary edit file: {error}"
                        ))
                    },
                )?;

                open_in_editor(temp_file.path())?;

                let edited = std::fs::read_to_string(temp_file.path()).map_err(|error| {
                    ConfigCommandError::new(format!(
                        "failed to read edited temporary config: {error}"
                    ))
                })?;
                SecretsConfig::parse_from_str(&edited, &path)?;
                write::replace_config_contents(&path, &edited, Some(&resolved.password))?;

                return Ok(path);
            }
            Err(error) => {
                if matches!(resolved.source, PasswordSource::Keyring)
                    && error.to_string().contains(&format!(
                        "invalid password for config file '{}'",
                        path.display()
                    ))
                {
                    forget_keyring_password_if_present(&path);
                }

                return Err(error.into());
            }
        }
    }

    if !encrypted {
        open_in_editor(&path)?;
        SecretsConfig::parse_from_str(
            &std::fs::read_to_string(&path).map_err(|error| {
                ConfigCommandError::new(format!(
                    "failed to read edited config file '{}': {error}",
                    path.display()
                ))
            })?,
            &path,
        )?;
        return Ok(path);
    }
    unreachable!("encrypted edit path returns earlier")
}

pub fn validate(args: ConfigValidateArgs) -> Result<String, ConfigCommandError> {
    let start_args = StartArgs {
        bind: None,
        config: args.config,
        password: None,
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
    let auth_header = args
        .auth_header
        .as_deref()
        .map(|value| trimmed_required("auth_header", value))
        .transpose()?;
    if let Some(auth_header) = auth_header.as_deref() {
        validate_header_name(auth_header, &args.name)?;
    }
    let auth_value = args
        .auth_value
        .as_deref()
        .map(|value| trimmed_required("auth_value", value))
        .transpose()?;

    match (&auth_header, &auth_value) {
        (None, Some(_)) => {
            return Err(ConfigCommandError::new(
                "auth_value cannot be set without auth_header",
            ));
        }
        (Some(_), None) => {
            return Err(ConfigCommandError::new(
                "auth_value is required when auth_header is configured",
            ));
        }
        _ => {}
    }

    if args.timeout_ms == 0 {
        return Err(ConfigCommandError::new(format!(
            "apis.{}.timeout_ms must be greater than 0",
            args.name
        )));
    }

    let path = resolve_target_path(args.config.as_deref())?;
    let generated_default_bearer_token = ensure_config_exists(&path, args.password.as_deref())?;
    let password = password_for_existing_encrypted_file(&path, args.password)?;
    write::upsert_api(
        &path,
        &ApiUpsert {
            name: args.name,
            base_url,
            auth_header,
            auth_value,
            timeout_ms: args.timeout_ms,
        },
        password.as_ref(),
    )?;

    if let Some(token) = generated_default_bearer_token.as_deref() {
        print_generated_bearer_token("default", token);
    }

    Ok(path)
}

pub fn add_client(args: ConfigAddClientArgs) -> Result<PathBuf, ConfigCommandError> {
    Ok(add_client_with_result(args)?.path)
}

pub fn add_client_with_result(
    args: ConfigAddClientArgs,
) -> Result<AddClientOutcome, ConfigCommandError> {
    ensure_slug("client", &args.name)?;

    let bearer_token_expires_at = args
        .bearer_token_expires_at
        .as_deref()
        .map(|value| {
            let value = trimmed_required("bearer_token_expires_at", value)?;
            validate_timestamp("bearer_token_expires_at", &value)?;
            Ok::<String, ConfigCommandError>(value)
        })
        .transpose()?;

    let group = args
        .group
        .as_deref()
        .map(|value| {
            let value = trimmed_required("group", value)?;
            ensure_slug("group", &value)?;
            Ok::<String, ConfigCommandError>(value)
        })
        .transpose()?;

    let api_access = parse_api_access_args(&args.api_access)?;

    let path = resolve_target_path(args.config.as_deref())?;
    let generated_default_bearer_token = ensure_config_exists(&path, args.password.as_deref())?;
    let password = password_for_existing_encrypted_file(&path, args.password)?;
    let existing = load_existing_client_bearer_metadata(&path, password.as_ref(), &args.name)?;
    let resolved = resolve_bearer_token_metadata(bearer_token_expires_at, existing)?;

    write::upsert_client(
        &path,
        &ClientUpsert {
            name: args.name.clone(),
            bearer_token: resolved.bearer_token.clone(),
            bearer_token_expires_at: Some(resolved.expires_at.clone()),
            access: match group {
                Some(group) => ClientAccessUpsert::Group(group),
                None => ClientAccessUpsert::ApiAccess(api_access),
            },
        },
        password.as_ref(),
    )?;

    if let Some(token) = generated_default_bearer_token.as_deref() {
        print_generated_bearer_token("default", token);
    }

    if let Some(token) = resolved.generated_token.as_deref() {
        print_generated_bearer_token(&args.name, token);
    }

    Ok(AddClientOutcome {
        path,
        generated_bearer_token: resolved.generated_token,
        bearer_token_expires_at: resolved.expires_at,
    })
}

pub fn add_group(args: ConfigAddGroupArgs) -> Result<PathBuf, ConfigCommandError> {
    ensure_slug("group", &args.name)?;

    let api_access = parse_api_access_args(&args.api_access)?;

    if api_access.is_empty() {
        return Err(ConfigCommandError::new(
            "api_access entries are required for groups",
        ));
    }

    let path = resolve_target_path(args.config.as_deref())?;
    let generated_default_bearer_token = ensure_config_exists(&path, args.password.as_deref())?;
    let password = password_for_existing_encrypted_file(&path, args.password)?;
    write::upsert_group(
        &path,
        &GroupUpsert {
            name: args.name,
            api_access,
        },
        password.as_ref(),
    )?;

    if let Some(token) = generated_default_bearer_token.as_deref() {
        print_generated_bearer_token("default", token);
    }

    Ok(path)
}

#[derive(Clone, Debug)]
struct ExistingBearerMetadata {
    expires_at: String,
}

#[derive(Clone, Debug)]
struct ResolvedBearerMetadata {
    expires_at: String,
    bearer_token: Option<String>,
    generated_token: Option<String>,
}

pub(crate) fn list_group_slugs(
    cli_override: Option<&Path>,
    password: Option<String>,
) -> Result<Vec<String>, ConfigCommandError> {
    let path = resolve_target_path(cli_override)?;

    if !path.exists() {
        return Ok(Vec::new());
    }

    let password = password_for_existing_encrypted_file(&path, password)?;
    let loaded = write::load_display_text(&path, password.as_ref())?;
    let parsed: toml::Value = loaded.toml.parse().map_err(|error| {
        ConfigCommandError::new(format!(
            "failed to parse config file '{}': {error}",
            path.display()
        ))
    })?;

    let mut groups = parsed
        .get("groups")
        .and_then(toml::Value::as_table)
        .map(|table| table.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    groups.sort();

    Ok(groups)
}

pub(crate) fn prompt_required_text(
    prompt: &str,
    default: Option<&str>,
    non_interactive_message: &str,
) -> Result<String, ConfigCommandError> {
    let response = prompt_text(prompt, default, non_interactive_message)?;

    trimmed_required(prompt_field_name(prompt), &response)
}

pub(crate) fn prompt_optional_text(
    prompt: &str,
    default: Option<&str>,
    non_interactive_message: &str,
) -> Result<Option<String>, ConfigCommandError> {
    let response = prompt_text(prompt, default, non_interactive_message)?;
    let trimmed = response.trim();

    if trimmed.is_empty() {
        return Ok(None);
    }

    Ok(Some(trimmed.to_owned()))
}

pub(crate) fn prompt_yes_no(
    prompt: &str,
    default: bool,
    non_interactive_message: &str,
) -> Result<bool, ConfigCommandError> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    let response = prompt_text(&format!("{prompt} {suffix}"), None, non_interactive_message)?;

    match response.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        value => Err(ConfigCommandError::new(format!(
            "invalid response '{value}'; expected yes or no"
        ))),
    }
}

pub(crate) fn reset_test_prompt_state_if_exhausted() -> Result<(), ConfigCommandError> {
    let Some(raw) = std::env::var(TEST_PROMPT_INPUTS_ENV_VAR).ok() else {
        return Ok(());
    };

    let state = TEST_PROMPT_STATE.get_or_init(|| Mutex::new(TestPromptState::default()));
    let mut state = state
        .lock()
        .map_err(|_| ConfigCommandError::new("failed to lock test prompt state"))?;

    if state.raw.as_deref() == Some(raw.as_str()) && state.values.is_empty() {
        state.raw = None;
        state.values.clear();
    }

    Ok(())
}

pub(crate) fn prompt_message(
    question: &str,
    detail: Option<&str>,
    default: Option<&str>,
    example: Option<&str>,
    options: Option<&str>,
    note: Option<&str>,
) -> String {
    let example = match (default, example) {
        (Some(default), _) if !default.trim().is_empty() => None,
        (_, Some(example)) if !example.trim().is_empty() => Some(example),
        _ => None,
    };

    let mut prompt = question.trim().to_owned();

    if let Some(detail) = detail.filter(|value| !value.trim().is_empty()) {
        prompt.push_str(" — ");
        prompt.push_str(detail.trim());
    }

    let mut metadata = Vec::new();

    if let Some(default) = default.filter(|value| !value.trim().is_empty()) {
        metadata.push(format!("default: {default}"));
    } else if let Some(example) = example {
        metadata.push(format!("example: {example}"));
    }

    if let Some(options) = options.filter(|value| !value.trim().is_empty()) {
        metadata.push(format!("options: {options}"));
    }

    if let Some(note) = note.filter(|value| !value.trim().is_empty()) {
        metadata.push(note.trim().to_owned());
    }

    if !metadata.is_empty() {
        prompt.push_str(" (");
        prompt.push_str(&metadata.join("; "));
        prompt.push(')');
    }

    prompt
}

fn resolve_target_path(
    cli_override: Option<&std::path::Path>,
) -> Result<PathBuf, ConfigCommandError> {
    let resolved = resolve_config_path_for_update(cli_override)
        .map_err(|error| ConfigCommandError::new(error.to_string()))?;

    Ok(resolved.path)
}

fn resolve_existing_path(
    cli_override: Option<&std::path::Path>,
) -> Result<PathBuf, ConfigCommandError> {
    resolve_config_path(cli_override)
        .map(|resolved| resolved.path)
        .map_err(|error| ConfigCommandError::new(error.to_string()))
}

fn ensure_config_exists(
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<Option<String>, ConfigCommandError> {
    if path.exists() {
        return Ok(None);
    }

    let encrypted = password.is_some();
    let resolved_password = match password {
        Some(password) => Some(
            resolve_for_encrypted_create(
                &PasswordArgs {
                    password: Some(password.to_owned()),
                },
                path,
            )?
            .password,
        ),
        None => None,
    };

    write::init_config_with_default_bearer_token(path, encrypted, resolved_password.as_ref())
        .map(Some)
        .map_err(ConfigCommandError::from)
}

fn print_generated_bearer_token(client_name: &str, token: &str) {
    println!("Generated token for client '{client_name}': {token}");
}

fn load_existing_client_bearer_metadata(
    path: &Path,
    password: Option<&secrecy::SecretString>,
    client_name: &str,
) -> Result<Option<ExistingBearerMetadata>, ConfigCommandError> {
    let loaded = write::load_display_text(path, password)?;
    let document = parse_config(path, &loaded.toml)?;
    let Some(client_table) = find_table(document.as_table(), &["clients", client_name]) else {
        return Ok(None);
    };

    let Some(_id) = find_string_value(client_table, "bearer_token_id") else {
        return Ok(None);
    };
    let Some(_hash) = find_string_value(client_table, "bearer_token_hash") else {
        return Ok(None);
    };
    let Some(expires_at) = find_string_value(client_table, "bearer_token_expires_at") else {
        return Ok(None);
    };

    Ok(Some(ExistingBearerMetadata { expires_at }))
}

fn resolve_bearer_token_metadata(
    bearer_token_expires_at: Option<String>,
    existing: Option<ExistingBearerMetadata>,
) -> Result<ResolvedBearerMetadata, ConfigCommandError> {
    match (bearer_token_expires_at, existing) {
        (Some(expires_at), Some(_existing)) => Ok(ResolvedBearerMetadata {
            expires_at,
            bearer_token: None,
            generated_token: None,
        }),
        (None, Some(existing)) => Ok(ResolvedBearerMetadata {
            expires_at: existing.expires_at,
            bearer_token: None,
            generated_token: None,
        }),
        (expires_at, None) => {
            let token = write::generate_bearer_token()?;
            compute_bearer_token_metadata(
                &token,
                expires_at.unwrap_or(default_bearer_token_expires_at()?),
                Some(token.clone()),
                Some(token.clone()),
            )
        }
    }
}

fn compute_bearer_token_metadata(
    _token: &str,
    expires_at: String,
    bearer_token: Option<String>,
    generated_token: Option<String>,
) -> Result<ResolvedBearerMetadata, ConfigCommandError> {
    Ok(ResolvedBearerMetadata {
        expires_at,
        bearer_token,
        generated_token,
    })
}

fn parse_config(path: &Path, contents: &str) -> Result<DocumentMut, ConfigCommandError> {
    contents.parse::<DocumentMut>().map_err(|error| {
        ConfigCommandError::new(format!(
            "failed to parse config file '{}': {error}",
            path.display()
        ))
    })
}

fn find_table<'a>(parent: &'a Table, path: &[&str]) -> Option<&'a Table> {
    let mut current = parent;

    for key in path {
        current = current.get(key)?.as_table()?;
    }

    Some(current)
}

fn find_string_value(table: &Table, key: &str) -> Option<String> {
    table.get(key)?.as_str().map(str::to_owned)
}

fn password_for_existing_encrypted_file(
    path: &Path,
    password: Option<String>,
) -> Result<Option<secrecy::SecretString>, ConfigCommandError> {
    let raw_contents = std::fs::read_to_string(path).map_err(|error| {
        ConfigCommandError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })?;
    if crate::config::crypto::detect_format(&raw_contents)
        != crate::config::crypto::ConfigFileFormat::AgeEncryptedToml
    {
        return Ok(None);
    }

    resolve_for_encrypted_read(&PasswordArgs { password }, path)
        .map(Some)
        .map_err(|error| ConfigCommandError::new(error.to_string()))
}

fn open_in_editor(path: &Path) -> Result<(), ConfigCommandError> {
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| {
            ConfigCommandError::new("config edit requires VISUAL or EDITOR to be set")
        })?;

    let status = Command::new(&editor).arg(path).status().map_err(|error| {
        ConfigCommandError::new(format!("failed to launch editor '{editor}': {error}"))
    })?;

    if !status.success() {
        return Err(ConfigCommandError::new(format!(
            "editor '{editor}' exited with status {status}"
        )));
    }

    Ok(())
}

fn prompt_text(
    prompt: &str,
    default: Option<&str>,
    non_interactive_message: &str,
) -> Result<String, ConfigCommandError> {
    if let Some(response) = take_test_prompt_input()? {
        return Ok(apply_prompt_default(response, default));
    }

    if interactive_prompts_disabled()
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        return Err(ConfigCommandError::new(non_interactive_message));
    }

    std::io::stderr()
        .write_all(format_prompt(prompt, default).as_bytes())
        .map_err(|error| ConfigCommandError::new(format!("failed to write prompt: {error}")))?;
    std::io::stderr()
        .flush()
        .map_err(|error| ConfigCommandError::new(format!("failed to flush prompt: {error}")))?;

    let mut response = String::new();
    std::io::stdin().read_line(&mut response).map_err(|error| {
        ConfigCommandError::new(format!("failed to read prompt response: {error}"))
    })?;

    Ok(apply_prompt_default(response, default))
}

pub(crate) fn interactive_prompts_disabled() -> bool {
    std::env::var_os(DISABLE_INTERACTIVE_ENV_VAR).is_some()
}

fn format_prompt(prompt: &str, default: Option<&str>) -> String {
    let _ = default;
    format!("{prompt}: ")
}

fn prompt_field_name(prompt: &str) -> &str {
    let first_segment = prompt
        .split_once(" (")
        .map(|(segment, _)| segment)
        .unwrap_or(prompt)
        .trim();

    first_segment
        .split_once('—')
        .map(|(field, _)| field.trim())
        .unwrap_or(first_segment)
}

fn apply_prompt_default(response: String, default: Option<&str>) -> String {
    let trimmed = response.trim();

    if trimmed.is_empty() {
        return default.unwrap_or_default().to_owned();
    }

    trimmed.to_owned()
}

fn take_test_prompt_input() -> Result<Option<String>, ConfigCommandError> {
    match take_test_prompt_input_state(true)? {
        TestPromptInput::Value(value) => Ok(Some(value)),
        TestPromptInput::Unavailable => Ok(None),
        TestPromptInput::Exhausted => Err(ConfigCommandError::new(format!(
            "{TEST_PROMPT_INPUTS_ENV_VAR} did not provide enough prompt answers"
        ))),
    }
}

enum TestPromptInput {
    Unavailable,
    Value(String),
    Exhausted,
}

fn take_test_prompt_input_state(
    reset_when_exhausted: bool,
) -> Result<TestPromptInput, ConfigCommandError> {
    let Some(raw) = std::env::var(TEST_PROMPT_INPUTS_ENV_VAR).ok() else {
        return Ok(TestPromptInput::Unavailable);
    };

    let state = TEST_PROMPT_STATE.get_or_init(|| Mutex::new(TestPromptState::default()));
    let mut state = state
        .lock()
        .map_err(|_| ConfigCommandError::new("failed to lock test prompt state"))?;

    if state.raw.as_deref() != Some(raw.as_str()) {
        let values: Vec<String> = serde_json::from_str(&raw).map_err(|error| {
            ConfigCommandError::new(format!(
                "{TEST_PROMPT_INPUTS_ENV_VAR} must be a JSON array of strings: {error}"
            ))
        })?;
        state.raw = Some(raw);
        state.values = values.into();
    }

    if let Some(value) = state.values.pop_front() {
        return Ok(TestPromptInput::Value(value));
    }

    if reset_when_exhausted {
        state.raw = None;
        state.values.clear();
    }

    Ok(TestPromptInput::Exhausted)
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

fn parse_api_access_args(
    api_access_args: &[String],
) -> Result<BTreeMap<String, AccessLevel>, ConfigCommandError> {
    let mut api_access = BTreeMap::new();

    for raw_arg in api_access_args {
        for raw_pair in raw_arg.split(',') {
            let raw_pair = raw_pair.trim();
            if raw_pair.is_empty() {
                return Err(ConfigCommandError::new(
                    "api_access entries cannot contain empty comma-separated segments".to_owned(),
                ));
            }

            let (api, level) = raw_pair.split_once('=').ok_or_else(|| {
                ConfigCommandError::new(format!(
                    "invalid api_access entry '{raw_pair}'; expected api=level"
                ))
            })?;

            let api = api.trim();
            let level = level.trim();

            if api.is_empty() {
                return Err(ConfigCommandError::new(
                    "api_access api slug cannot be empty".to_owned(),
                ));
            }

            if level.is_empty() {
                return Err(ConfigCommandError::new(format!(
                    "api_access level cannot be empty for api '{api}'"
                )));
            }

            if !is_valid_slug(api) {
                return Err(ConfigCommandError::new(format!(
                    "api_access api slug '{api}' must contain only lowercase letters, digits, or hyphen"
                )));
            }

            let level = match level {
                "read" => AccessLevel::Read,
                "write" => AccessLevel::Write,
                _ => {
                    return Err(ConfigCommandError::new(format!(
                        "api_access level '{level}' must be one of: read, write"
                    )));
                }
            };

            if let Some(existing) = api_access.insert(api.to_owned(), level) {
                if existing != level {
                    return Err(ConfigCommandError::new(format!(
                        "conflicting api_access entries for api '{api}'"
                    )));
                }
            }
        }
    }

    Ok(api_access)
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

fn validate_timestamp(field: &str, value: &str) -> Result<(), ConfigCommandError> {
    parse_rfc3339_utc(value)
        .map(|_| ())
        .map_err(|error| ConfigCommandError::new(format!("invalid {field}: {error}")))
}

fn default_bearer_token_expires_at() -> Result<String, ConfigCommandError> {
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(180 * 24 * 60 * 60))
        .ok_or_else(|| ConfigCommandError::new("failed to compute bearer token expiration"))?;

    let unix_seconds = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            ConfigCommandError::new(format!("system clock is before unix epoch: {error}"))
        })?
        .as_secs();

    Ok(format_rfc3339(unix_seconds))
}

fn format_rfc3339(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let seconds_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
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

    let days = days_from_civil(year, month, day)?;
    let total_seconds = days
        .checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or("timestamp is out of supported range")?;

    Ok(UNIX_EPOCH + Duration::from_secs(total_seconds))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Result<u64, &'static str> {
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

    u64::try_from(days).map_err(|_| "timestamp predates unix epoch")
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

#[cfg(test)]
mod tests {
    use super::{format_prompt, prompt_field_name, prompt_message};

    #[test]
    fn prompt_message_formats_single_line_metadata() {
        let prompt = prompt_message(
            "Group name",
            None,
            None,
            None,
            Some("default, readonly"),
            None,
        );

        assert_eq!(prompt, "Group name (options: default, readonly)");
    }

    #[test]
    fn prompt_message_omits_example_when_default_exists() {
        let prompt = prompt_message(
            "Config path",
            None,
            Some("/home/fabio/.config/gate-agent/secrets"),
            Some("~/.config/gate-agent/secrets"),
            None,
            None,
        );

        assert!(!prompt.contains("Example:"));
        assert_eq!(
            prompt,
            "Config path (default: /home/fabio/.config/gate-agent/secrets)"
        );
    }

    #[test]
    fn format_prompt_keeps_question_on_single_line() {
        let rendered = format_prompt("Config path (default: /tmp/demo)", Some("/tmp/demo"));

        assert_eq!(rendered, "Config path (default: /tmp/demo): ");
    }

    #[test]
    fn prompt_field_name_uses_question_prefix() {
        assert_eq!(
            prompt_field_name("Client name (example: myclient)"),
            "Client name"
        );
    }
}
