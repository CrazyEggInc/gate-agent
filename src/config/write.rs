use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use toml_edit::{Array, DocumentMut, Item, Table, value};

pub const DEFAULT_AUTH_ISSUER: &str = "gate-agent";
pub const DEFAULT_AUTH_AUDIENCE: &str = "gate-agent-clients";

const DEFAULT_API_KEY_VALIDITY_DAYS: u64 = 180;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiUpsert {
    pub name: String,
    pub base_url: String,
    pub auth_header: String,
    pub auth_scheme: Option<String>,
    pub auth_value: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientUpsert {
    pub name: String,
    pub api_key: Option<String>,
    pub api_key_expires_at: Option<String>,
    pub allowed_apis: Vec<String>,
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

pub fn init_config(path: &Path) -> Result<(), WriteConfigError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            WriteConfigError::new(format!(
                "failed to create config directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    let config = render_initial_config()?;
    fs::write(path, config).map_err(|error| {
        WriteConfigError::new(format!(
            "failed to write config file '{}': {error}",
            path.display()
        ))
    })
}

pub fn upsert_api(path: &Path, api: &ApiUpsert) -> Result<(), WriteConfigError> {
    let contents = read_config(path)?;
    let mut document = parse_config(path, &contents)?;
    let apis = get_or_insert_table(document.as_table_mut(), "apis")?;
    let api_table = get_or_insert_table(apis, &api.name)?;

    set_string(api_table, "base_url", &api.base_url);
    set_string(api_table, "auth_header", &api.auth_header);

    if let Some(auth_scheme) = api
        .auth_scheme
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        set_string(api_table, "auth_scheme", auth_scheme);
    } else {
        api_table.remove("auth_scheme");
    }

    set_string(api_table, "auth_value", &api.auth_value);
    set_integer(api_table, "timeout_ms", api.timeout_ms)?;

    write_config(path, &document.to_string())
}

pub fn upsert_client(path: &Path, client: &ClientUpsert) -> Result<(), WriteConfigError> {
    let contents = read_config(path)?;
    let mut document = parse_config(path, &contents)?;
    let existing_client = find_table(document.as_table(), &["clients", &client.name]);

    let api_key = match client
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(api_key) => api_key.to_owned(),
        None => existing_client
            .and_then(|table| find_string_value(table, "api_key"))
            .unwrap_or(generate_secret(18)?),
    };

    let api_key_expires_at = match client
        .api_key_expires_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(expires_at) => expires_at.to_owned(),
        None => existing_client
            .and_then(|table| find_string_value(table, "api_key_expires_at"))
            .unwrap_or(default_api_key_expires_at()?),
    };

    let clients = get_or_insert_table(document.as_table_mut(), "clients")?;
    let client_table = get_or_insert_table(clients, &client.name)?;

    set_string(client_table, "api_key", &api_key);
    set_string(client_table, "api_key_expires_at", &api_key_expires_at);
    set_string_array(client_table, "allowed_apis", &client.allowed_apis);

    write_config(path, &document.to_string())
}

fn render_initial_config() -> Result<String, WriteConfigError> {
    let signing_secret = generate_secret(24)?;
    let api_key = generate_secret(18)?;
    let api_key_expires_at = default_api_key_expires_at()?;

    Ok(format!(
        "[auth]\nissuer = \"{DEFAULT_AUTH_ISSUER}\"\naudience = \"{DEFAULT_AUTH_AUDIENCE}\"\nsigning_secret = \"{signing_secret}\"\n\n[clients.default]\napi_key = \"{api_key}\"\napi_key_expires_at = \"{api_key_expires_at}\"\nallowed_apis = []\n\n[apis]\n"
    ))
}

fn read_config(path: &Path) -> Result<String, WriteConfigError> {
    fs::read_to_string(path).map_err(|error| {
        WriteConfigError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })
}

fn parse_config(path: &Path, contents: &str) -> Result<DocumentMut, WriteConfigError> {
    contents.parse::<DocumentMut>().map_err(|error| {
        WriteConfigError::new(format!(
            "failed to parse config file '{}': {error}",
            path.display()
        ))
    })
}

fn write_config(path: &Path, contents: &str) -> Result<(), WriteConfigError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            WriteConfigError::new(format!(
                "failed to create config directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    fs::write(path, contents).map_err(|error| {
        WriteConfigError::new(format!(
            "failed to write config file '{}': {error}",
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

fn set_string(table: &mut Table, key: &str, value_str: &str) {
    table[key] = value(value_str);
}

fn set_integer(table: &mut Table, key: &str, value_int: u64) -> Result<(), WriteConfigError> {
    let value_int = i64::try_from(value_int)
        .map_err(|_| WriteConfigError::new(format!("{key} is too large to serialize")))?;
    table[key] = value(value_int);
    Ok(())
}

fn set_string_array(table: &mut Table, key: &str, values: &[String]) {
    let mut array = Array::default();
    for value_str in values {
        array.push(value_str.as_str());
    }
    table[key] = value(array);
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

fn default_api_key_expires_at() -> Result<String, WriteConfigError> {
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(
            DEFAULT_API_KEY_VALIDITY_DAYS * 24 * 60 * 60,
        ))
        .ok_or_else(|| WriteConfigError::new("failed to compute api key expiration"))?;

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
