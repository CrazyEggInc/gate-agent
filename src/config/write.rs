use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::SecretString;
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, Table, value};

use crate::config::secrets::{
    ApiAccessMethod, ApiAccessRule, DEFAULT_SERVER_BIND, DEFAULT_SERVER_PORT,
};

use super::ConfigError;
use super::crypto::{
    ConfigFileFormat, LoadedConfigText, load_config_text, resolve_format_from_bytes,
    serialize_for_format, write_config_file_atomic,
};

const DEFAULT_BEARER_TOKEN_VALIDITY_DAYS: u64 = 180;

#[derive(Clone, PartialEq, Eq)]
pub struct ApiBasicAuthUpsert {
    pub username: String,
    pub password: Option<String>,
}

impl Debug for ApiBasicAuthUpsert {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("ApiBasicAuthUpsert");
        debug.field("username", &self.username);

        if self.password.is_some() {
            debug.field("password", &"[REDACTED]");
        }

        debug.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiUpsert {
    pub name: String,
    pub base_url: String,
    pub headers: BTreeMap<String, String>,
    pub basic_auth: Option<ApiBasicAuthUpsert>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAccessUpsert {
    Group(String),
    ApiAccess(BTreeMap<String, Vec<ApiAccessRule>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientUpsert {
    pub name: String,
    pub bearer_token: Option<String>,
    pub bearer_token_expires_at: Option<String>,
    pub access: ClientAccessUpsert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BearerTokenMetadata {
    id: String,
    hash: String,
    expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupUpsert {
    pub name: String,
    pub api_access: BTreeMap<String, Vec<ApiAccessRule>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientUpsertResult {
    pub generated_bearer_token: Option<String>,
    pub bearer_token_expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedClientUpsert {
    metadata: BearerTokenMetadata,
    result: ClientUpsertResult,
}

#[derive(Debug)]
pub struct WriteConfigError {
    message: String,
}

impl WriteConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for WriteConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WriteConfigError {}

impl From<ConfigError> for WriteConfigError {
    fn from(error: ConfigError) -> Self {
        Self::new(error.to_string())
    }
}

pub fn init_config(
    path: &Path,
    encrypted: bool,
    password: Option<&SecretString>,
) -> Result<(), WriteConfigError> {
    init_config_with_default_bearer_token(path, encrypted, password).map(|_| ())
}

pub fn init_config_with_default_bearer_token(
    path: &Path,
    encrypted: bool,
    password: Option<&SecretString>,
) -> Result<String, WriteConfigError> {
    init_config_with_default_bearer_token_and_server(
        path,
        encrypted,
        password,
        DEFAULT_SERVER_BIND,
        DEFAULT_SERVER_PORT,
    )
}

pub fn init_config_with_default_bearer_token_and_server(
    path: &Path,
    encrypted: bool,
    password: Option<&SecretString>,
    server_bind: &str,
    server_port: u16,
) -> Result<String, WriteConfigError> {
    let default_bearer_token = generate_bearer_token()?;
    let config = render_initial_config(&default_bearer_token, server_bind, server_port)?;
    let format = if encrypted {
        ConfigFileFormat::AgeEncryptedToml
    } else {
        ConfigFileFormat::PlaintextToml
    };

    let serialized = serialize_for_format(&format, &config, password)?;
    write_config_file_atomic(path, &serialized)?;
    Ok(default_bearer_token)
}

pub fn upsert_api(
    path: &Path,
    api: &ApiUpsert,
    password: Option<&SecretString>,
) -> Result<(), WriteConfigError> {
    let loaded = load_editable_config(path, password)?;
    let mut document = parse_config(path, &loaded.toml)?;
    let apis = get_or_insert_table(document.as_table_mut(), "apis")?;
    let api_table = get_or_insert_table(apis, &api.name)?;

    set_string(api_table, "base_url", &api.base_url);
    api_table.remove("auth_header");
    api_table.remove("auth_value");
    api_table.remove("auth_scheme");

    if api.headers.is_empty() {
        api_table.remove("headers");
    } else {
        set_string_inline_table(api_table, "headers", &api.headers);
    }

    match &api.basic_auth {
        Some(basic_auth) => set_basic_auth_inline_table(api_table, basic_auth),
        None => {
            api_table.remove("basic_auth");
        }
    }

    set_integer(api_table, "timeout_ms", api.timeout_ms)?;

    write_loaded_config(path, &loaded, &document.to_string(), password)
}

pub fn upsert_client(
    path: &Path,
    client: &ClientUpsert,
    password: Option<&SecretString>,
) -> Result<ClientUpsertResult, WriteConfigError> {
    let loaded = load_editable_config(path, password)?;
    let mut document = parse_config(path, &loaded.toml)?;
    let existing_client = find_table(document.as_table(), &["clients", &client.name]);
    let resolved_upsert = resolve_client_upsert(existing_client, client)?;

    let clients = get_or_insert_table(document.as_table_mut(), "clients")?;
    ensure_unique_bearer_token_id(clients, &client.name, &resolved_upsert.metadata.id)?;
    let client_table = get_or_insert_table(clients, &client.name)?;

    apply_bearer_metadata(client_table, &resolved_upsert.metadata);
    client_table.remove("api_key");
    client_table.remove("api_key_expires_at");
    match &client.access {
        ClientAccessUpsert::Group(group) => {
            set_string(client_table, "group", group);
            client_table.remove("api_access");
        }
        ClientAccessUpsert::ApiAccess(api_access) => {
            client_table.remove("group");
            set_api_access_inline_table(client_table, "api_access", api_access);
        }
    }

    write_loaded_config(path, &loaded, &document.to_string(), password)?;

    Ok(resolved_upsert.result)
}

pub fn upsert_group(
    path: &Path,
    group: &GroupUpsert,
    password: Option<&SecretString>,
) -> Result<(), WriteConfigError> {
    let loaded = load_editable_config(path, password)?;
    let mut document = parse_config(path, &loaded.toml)?;
    let groups = get_or_insert_table(document.as_table_mut(), "groups")?;
    let group_table = get_or_insert_table(groups, &group.name)?;

    set_api_access_inline_table(group_table, "api_access", &group.api_access);

    write_loaded_config(path, &loaded, &document.to_string(), password)
}

pub fn load_display_text(
    path: &Path,
    password: Option<&SecretString>,
) -> Result<LoadedConfigText, WriteConfigError> {
    load_config_text(path, password).map_err(WriteConfigError::from)
}

pub fn replace_config_contents(
    path: &Path,
    contents: &str,
    password: Option<&SecretString>,
) -> Result<(), WriteConfigError> {
    let raw_contents = fs::read(path).map_err(|error| {
        WriteConfigError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })?;
    let format = resolve_format_from_bytes(path, &raw_contents)?;
    let serialized = serialize_for_format(&format, contents, password)?;
    write_config_file_atomic(path, &serialized)?;
    Ok(())
}

fn load_editable_config(
    path: &Path,
    password: Option<&SecretString>,
) -> Result<LoadedConfigText, WriteConfigError> {
    load_config_text(path, password).map_err(WriteConfigError::from)
}

fn write_loaded_config(
    path: &Path,
    loaded: &LoadedConfigText,
    plaintext: &str,
    password: Option<&SecretString>,
) -> Result<(), WriteConfigError> {
    let serialized = serialize_for_format(&loaded.format, plaintext, password)?;
    write_config_file_atomic(path, &serialized)?;
    Ok(())
}

pub fn generate_bearer_token() -> Result<String, WriteConfigError> {
    Ok(format!("{}.{}", generate_secret(8)?, generate_secret(18)?))
}

pub fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex_encode(&digest)
}

fn render_initial_config(
    default_bearer_token: &str,
    server_bind: &str,
    server_port: u16,
) -> Result<String, WriteConfigError> {
    let metadata = bearer_token_metadata(default_bearer_token, default_bearer_token_expires_at()?)?;
    let mut document = DocumentMut::new();

    let clients = get_or_insert_table(document.as_table_mut(), "clients")?;
    let default_client = get_or_insert_table(clients, "default")?;
    apply_bearer_metadata(default_client, &metadata);
    set_string(default_client, "group", "local-default");

    let server = get_or_insert_table(document.as_table_mut(), "server")?;
    set_string(server, "bind", server_bind);
    set_integer(server, "port", u64::from(server_port))?;

    let groups = get_or_insert_table(document.as_table_mut(), "groups")?;
    let local_default_group = get_or_insert_table(groups, "local-default")?;
    set_api_access_inline_table(
        local_default_group,
        "api_access",
        &std::collections::BTreeMap::new(),
    );
    get_or_insert_table(document.as_table_mut(), "apis")?;

    Ok(document.to_string())
}

fn resolve_client_upsert(
    existing_client: Option<&Table>,
    client: &ClientUpsert,
) -> Result<ResolvedClientUpsert, WriteConfigError> {
    let existing_metadata = existing_client.and_then(find_existing_bearer_token_metadata);
    let expires_at = match client
        .bearer_token_expires_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(expires_at) => expires_at.to_owned(),
        None => existing_metadata
            .as_ref()
            .map(|metadata| metadata.expires_at.clone())
            .unwrap_or(default_bearer_token_expires_at()?),
    };

    match client
        .bearer_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(bearer_token) => {
            let metadata = bearer_token_metadata(bearer_token, expires_at.clone())?;
            Ok(ResolvedClientUpsert {
                result: ClientUpsertResult {
                    generated_bearer_token: None,
                    bearer_token_expires_at: expires_at,
                },
                metadata,
            })
        }
        None => match existing_metadata {
            Some(mut metadata) => {
                metadata.expires_at = expires_at.clone();
                Ok(ResolvedClientUpsert {
                    result: ClientUpsertResult {
                        generated_bearer_token: None,
                        bearer_token_expires_at: expires_at,
                    },
                    metadata,
                })
            }
            None => {
                let generated_bearer_token = generate_bearer_token()?;
                let metadata = bearer_token_metadata(&generated_bearer_token, expires_at.clone())?;
                Ok(ResolvedClientUpsert {
                    result: ClientUpsertResult {
                        generated_bearer_token: Some(generated_bearer_token),
                        bearer_token_expires_at: expires_at,
                    },
                    metadata,
                })
            }
        },
    }
}

fn find_existing_bearer_token_metadata(table: &Table) -> Option<BearerTokenMetadata> {
    Some(BearerTokenMetadata {
        id: find_string_value(table, "bearer_token_id")?,
        hash: find_string_value(table, "bearer_token_hash")?,
        expires_at: find_string_value(table, "bearer_token_expires_at")?,
    })
}

fn bearer_token_metadata(
    bearer_token: &str,
    expires_at: String,
) -> Result<BearerTokenMetadata, WriteConfigError> {
    let (id, _) = split_bearer_token(bearer_token)?;

    Ok(BearerTokenMetadata {
        id: id.to_owned(),
        hash: sha256_hex(bearer_token),
        expires_at,
    })
}

fn split_bearer_token(bearer_token: &str) -> Result<(&str, &str), WriteConfigError> {
    let (id, secret) = bearer_token.split_once('.').ok_or_else(|| {
        WriteConfigError::new("bearer token must be formatted as <lookup-id>.<secret>")
    })?;

    if id.is_empty() || secret.is_empty() || secret.contains('.') {
        return Err(WriteConfigError::new(
            "bearer token must be formatted as <lookup-id>.<secret>",
        ));
    }

    Ok((id, secret))
}

fn parse_config(path: &Path, contents: &str) -> Result<DocumentMut, WriteConfigError> {
    contents.parse::<DocumentMut>().map_err(|error| {
        WriteConfigError::new(format!(
            "failed to parse config file '{}': {error}",
            path.display()
        ))
    })
}

fn get_or_insert_table<'a>(
    parent: &'a mut Table,
    key: &str,
) -> Result<&'a mut Table, WriteConfigError> {
    if parent.get(key).is_none() {
        parent.insert(key, Item::Table(Table::new()));
    }

    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| WriteConfigError::new(format!("{key} must be a TOML table")))
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

fn ensure_unique_bearer_token_id(
    clients: &Table,
    client_name: &str,
    bearer_token_id: &str,
) -> Result<(), WriteConfigError> {
    for (existing_name, item) in clients.iter() {
        if existing_name == client_name {
            continue;
        }

        let Some(existing_table) = item.as_table() else {
            continue;
        };

        if find_string_value(existing_table, "bearer_token_id").as_deref() == Some(bearer_token_id)
        {
            return Err(WriteConfigError::new(format!(
                "clients.{client_name}.bearer_token_id duplicates another configured client bearer_token_id"
            )));
        }
    }

    Ok(())
}

fn set_string(table: &mut Table, key: &str, value_str: &str) {
    table[key] = value(value_str);
}

fn set_integer(table: &mut Table, key: &str, value_int: u64) -> Result<(), WriteConfigError> {
    let value_int = i64::try_from(value_int)
        .map_err(|_| WriteConfigError::new(format!("{key} is too large to serialize")))?;
    table[key] = value(value_int);
    Ok(())
}

fn set_api_access_inline_table(
    table: &mut Table,
    key: &str,
    values: &BTreeMap<String, Vec<ApiAccessRule>>,
) {
    let mut inline = toml_edit::InlineTable::new();
    for (api, rules) in values {
        let mut array = toml_edit::Array::new();

        for rule in rules {
            let mut rule_inline = toml_edit::InlineTable::new();
            rule_inline.insert(
                "method",
                toml_edit::Value::from(api_access_method_label(rule)),
            );
            rule_inline.insert("path", toml_edit::Value::from(rule.path.as_str()));
            array.push(toml_edit::Value::InlineTable(rule_inline));
        }

        inline.insert(api, toml_edit::Value::Array(array));
    }
    table[key] = Item::Value(toml_edit::Value::InlineTable(inline));
}

fn api_access_method_label(rule: &ApiAccessRule) -> String {
    match &rule.method {
        ApiAccessMethod::Any => "*".to_owned(),
        ApiAccessMethod::Exact(method) => method.as_str().to_ascii_lowercase(),
    }
}

fn set_string_inline_table(table: &mut Table, key: &str, values: &BTreeMap<String, String>) {
    let mut inline = toml_edit::InlineTable::new();
    for (name, value_str) in values {
        inline.insert(name, toml_edit::Value::from(value_str.as_str()));
    }
    table[key] = Item::Value(toml_edit::Value::InlineTable(inline));
}

fn set_basic_auth_inline_table(table: &mut Table, basic_auth: &ApiBasicAuthUpsert) {
    let mut inline = toml_edit::InlineTable::new();
    inline.insert(
        "username",
        toml_edit::Value::from(basic_auth.username.as_str()),
    );
    if let Some(password) = basic_auth.password.as_deref() {
        inline.insert("password", toml_edit::Value::from(password));
    }
    table["basic_auth"] = Item::Value(toml_edit::Value::InlineTable(inline));
}

fn apply_bearer_metadata(table: &mut Table, metadata: &BearerTokenMetadata) {
    set_string(table, "bearer_token_id", &metadata.id);
    set_string(table, "bearer_token_hash", &metadata.hash);
    set_string(table, "bearer_token_expires_at", &metadata.expires_at);
}

fn generate_secret(byte_len: usize) -> Result<String, WriteConfigError> {
    let mut bytes = vec![0_u8; byte_len];
    let mut file = fs::File::open("/dev/urandom")
        .map_err(|error| WriteConfigError::new(format!("failed to open /dev/urandom: {error}")))?;
    file.read_exact(&mut bytes)
        .map_err(|error| WriteConfigError::new(format!("failed to read random bytes: {error}")))?;

    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn default_bearer_token_expires_at() -> Result<String, WriteConfigError> {
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(
            DEFAULT_BEARER_TOKEN_VALIDITY_DAYS * 24 * 60 * 60,
        ))
        .ok_or_else(|| WriteConfigError::new("failed to compute bearer token expiration"))?;

    let unix_seconds = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            WriteConfigError::new(format!("system clock is before unix epoch: {error}"))
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

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
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
