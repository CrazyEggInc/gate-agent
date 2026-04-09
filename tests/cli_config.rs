use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gate_agent::commands::config::{
    ConfigAddApiArgs, ConfigAddClientArgs, ConfigInitArgs, add_api, add_client, init,
};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use gate_agent::config::path::CONFIG_ENV_VAR;
use tempfile::tempdir;
use toml::Value;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    original_dir: PathBuf,
    original_config: Option<String>,
    original_home: Option<String>,
}

impl EnvGuard {
    fn enter(current_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let original_dir = std::env::current_dir()?;
        let original_config = std::env::var(CONFIG_ENV_VAR).ok();
        let original_home = std::env::var("HOME").ok();

        std::env::set_current_dir(current_dir)?;

        Ok(Self {
            original_dir,
            original_config,
            original_home,
        })
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_dir);

        unsafe {
            match &self.original_config {
                Some(value) => std::env::set_var(CONFIG_ENV_VAR, value),
                None => std::env::remove_var(CONFIG_ENV_VAR),
            }

            match &self.original_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

fn load_toml(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?.parse::<Value>()?)
}

fn table<'a>(value: &'a Value, key: &str) -> &'a toml::map::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("missing table: {key}"))
}

fn nested_table<'a>(value: &'a Value, path: &[&str]) -> &'a toml::map::Map<String, Value> {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing key: {key}"));
    }

    current
        .as_table()
        .unwrap_or_else(|| panic!("missing nested table: {}", path.join(".")))
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing key: {key}"));
    }

    current
        .as_str()
        .unwrap_or_else(|| panic!("missing string value at {}", path.join(".")))
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> &'a toml::value::Array {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing key: {key}"));
    }

    current
        .as_array()
        .unwrap_or_else(|| panic!("missing array value at {}", path.join(".")))
}

fn parse_rfc3339_utc(value: &str) -> Result<SystemTime, Box<dyn std::error::Error>> {
    if value.len() != 20 {
        return Err(format!("unexpected timestamp length: {value}").into());
    }

    let year: i32 = value[0..4].parse()?;
    let month: u32 = value[5..7].parse()?;
    let day: u32 = value[8..10].parse()?;
    let hour: u64 = value[11..13].parse()?;
    let minute: u64 = value[14..16].parse()?;
    let second: u64 = value[17..19].parse()?;

    if &value[4..5] != "-"
        || &value[7..8] != "-"
        || &value[10..11] != "T"
        || &value[13..14] != ":"
        || &value[16..17] != ":"
        || &value[19..20] != "Z"
    {
        return Err(format!("unexpected timestamp format: {value}").into());
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;

    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Result<u64, Box<dyn std::error::Error>> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err("invalid calendar date".into());
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
    let days = era * 146_097 + day_of_era - 719_468;

    u64::try_from(days).map_err(|_| "date predates unix epoch".into())
}

#[test]
fn config_init_prefers_explicit_path_and_generates_minimal_config()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let explicit_path = temp_dir.path().join("nested/custom/secrets.toml");
    let started_at = SystemTime::now();

    let written_path = init(ConfigInitArgs {
        config: Some(explicit_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let config = load_toml(&written_path)?;
    let expires_at = parse_rfc3339_utc(string_at(
        &config,
        &["clients", "default", "api_key_expires_at"],
    ))?;
    let lower_bound = started_at + Duration::from_secs(60 * 60 * 24 * 170);
    let upper_bound = started_at + Duration::from_secs(60 * 60 * 24 * 190);

    assert_eq!(written_path, explicit_path);
    assert!(written_path.exists());
    assert_eq!(string_at(&config, &["auth", "issuer"]), "gate-agent");
    assert_eq!(
        string_at(&config, &["auth", "audience"]),
        "gate-agent-clients"
    );
    assert!(string_at(&config, &["auth", "signing_secret"]).len() >= 32);
    assert!(string_at(&config, &["clients", "default", "api_key"]).len() >= 32);
    assert_eq!(
        array_at(&config, &["clients", "default", "allowed_apis"]).len(),
        0
    );
    assert!(table(&config, "apis").is_empty());
    assert!(expires_at >= lower_bound);
    assert!(expires_at <= upper_bound);

    Ok(())
}

#[test]
fn config_init_uses_env_path_before_local_and_home() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let current_dir = temp_dir.path().join("workspace");
    std::fs::create_dir_all(home_dir.join(".config/gate-agent"))?;
    std::fs::create_dir_all(&current_dir)?;
    std::fs::write(current_dir.join(".secrets"), "local = true\n")?;
    let _env = EnvGuard::enter(&current_dir)?;
    unsafe {
        std::env::set_var("HOME", &home_dir);
        std::env::set_var(CONFIG_ENV_VAR, temp_dir.path().join("env/gate-agent.toml"));
    }

    let written_path = init(ConfigInitArgs {
        config: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    assert_eq!(written_path, temp_dir.path().join("env/gate-agent.toml"));

    Ok(())
}

#[test]
fn config_add_api_uses_local_precedence_and_upserts_entry() -> Result<(), Box<dyn std::error::Error>>
{
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");
    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    add_api(ConfigAddApiArgs {
        config: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "projects".to_owned(),
        base_url: "http://127.0.0.1:18081/api".to_owned(),
        auth_header: "authorization".to_owned(),
        auth_scheme: Some("Bearer".to_owned()),
        auth_value: "local-upstream-token".to_owned(),
        timeout_ms: 5_000,
    })?;
    add_api(ConfigAddApiArgs {
        config: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "projects".to_owned(),
        base_url: "https://projects.internal.example/api".to_owned(),
        auth_header: "x-api-key".to_owned(),
        auth_scheme: None,
        auth_value: "updated-token".to_owned(),
        timeout_ms: 2_500,
    })?;

    let config = load_toml(&config_path)?;
    let api = nested_table(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert_eq!(
        api.get("auth_header").and_then(Value::as_str),
        Some("x-api-key")
    );
    assert_eq!(api.get("auth_scheme"), None);
    assert_eq!(
        api.get("auth_value").and_then(Value::as_str),
        Some("updated-token")
    );
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(2_500)
    );

    Ok(())
}

#[test]
fn config_add_client_prefers_local_creation_target_before_home_and_upserts_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let current_dir = temp_dir.path().join("workspace");
    std::fs::create_dir_all(home_dir.join(".config/gate-agent"))?;
    std::fs::create_dir_all(&current_dir)?;
    let _env = EnvGuard::enter(&current_dir)?;
    unsafe {
        std::env::set_var("HOME", &home_dir);
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = current_dir.join(".secrets");

    init(ConfigInitArgs {
        config: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    add_client(ConfigAddClientArgs {
        config: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        api_key: Some("partner-key".to_owned()),
        api_key_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        allowed_apis: vec!["billing".to_owned(), "projects".to_owned()],
    })?;
    add_client(ConfigAddClientArgs {
        config: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        api_key: None,
        api_key_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        allowed_apis: vec!["projects".to_owned()],
    })?;

    let config = load_toml(&config_path)?;
    let client = nested_table(&config, &["clients", "partner"]);

    assert_eq!(
        client.get("api_key").and_then(Value::as_str),
        Some("partner-key")
    );
    assert_eq!(
        client.get("api_key_expires_at").and_then(Value::as_str),
        Some("2031-02-03T04:05:06Z")
    );
    assert_eq!(
        client
            .get("allowed_apis")
            .and_then(Value::as_array)
            .expect("allowed_apis array")
            .iter()
            .map(|value| value.as_str().expect("string allowed_api"))
            .collect::<Vec<_>>(),
        vec!["projects"]
    );
    assert_eq!(string_at(&config, &["auth", "issuer"]), "gate-agent");
    assert!(!home_dir.join(".config/gate-agent/secrets").exists());

    Ok(())
}

#[test]
fn config_add_client_rejects_invalid_calendar_date_without_writing_client()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "invalid-date-client".to_owned(),
        api_key: Some("partner-key".to_owned()),
        api_key_expires_at: Some("2030-02-31T04:05:06Z".to_owned()),
        allowed_apis: vec!["projects".to_owned()],
    })
    .expect_err("invalid calendar date should be rejected");

    let config = load_toml(&config_path)?;

    assert!(
        error
            .to_string()
            .contains("invalid api_key_expires_at: invalid calendar date")
    );
    assert!(
        nested_table(&config, &["clients"])
            .get("invalid-date-client")
            .is_none()
    );

    Ok(())
}

#[test]
fn config_commands_accept_explicit_relative_paths() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }

    let init_path = PathBuf::from(".secrets");
    let config_path = PathBuf::from("gate-agent.toml");

    let initialized_path = init(ConfigInitArgs {
        config: Some(init_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let api_path = add_api(ConfigAddApiArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "projects".to_owned(),
        base_url: "https://projects.internal.example/api".to_owned(),
        auth_header: "authorization".to_owned(),
        auth_scheme: Some("Bearer".to_owned()),
        auth_value: "local-upstream-token".to_owned(),
        timeout_ms: 5_000,
    })?;
    let client_path = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        api_key: Some("partner-key".to_owned()),
        api_key_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        allowed_apis: vec!["projects".to_owned()],
    })?;

    assert_eq!(initialized_path, init_path);
    assert_eq!(api_path, config_path);
    assert_eq!(client_path, config_path);
    assert!(temp_dir.path().join(".secrets").exists());

    let config = load_toml(&temp_dir.path().join("gate-agent.toml"))?;

    assert_eq!(
        string_at(&config, &["apis", "projects", "base_url"]),
        "https://projects.internal.example/api"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_key"]),
        "partner-key"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_malformed_clients_root_without_rewriting_file()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");
    let original = concat!(
        "clients = \"oops\"\n\n",
        "[auth]\n",
        "issuer = \"gate-agent\"\n",
        "audience = \"gate-agent-clients\"\n",
        "signing_secret = \"existing-secret\"\n\n",
        "[apis]\n",
    );
    std::fs::write(&config_path, original)?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        api_key: Some("partner-key".to_owned()),
        api_key_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        allowed_apis: vec!["projects".to_owned()],
    })
    .expect_err("malformed clients root should be rejected");

    assert!(error.to_string().contains("clients must be a TOML table"));
    assert_eq!(std::fs::read_to_string(&config_path)?, original);

    Ok(())
}

#[test]
fn config_add_api_rejects_malformed_apis_root_without_rewriting_file()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");
    let original = concat!(
        "apis = []\n\n",
        "[auth]\n",
        "issuer = \"gate-agent\"\n",
        "audience = \"gate-agent-clients\"\n",
        "signing_secret = \"existing-secret\"\n\n",
        "[clients.default]\n",
        "api_key = \"existing-key\"\n",
        "api_key_expires_at = \"2030-01-02T03:04:05Z\"\n",
        "allowed_apis = []\n",
    );
    std::fs::write(&config_path, original)?;

    let error = add_api(ConfigAddApiArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "projects".to_owned(),
        base_url: "https://projects.internal.example/api".to_owned(),
        auth_header: "authorization".to_owned(),
        auth_scheme: Some("Bearer".to_owned()),
        auth_value: "local-upstream-token".to_owned(),
        timeout_ms: 5_000,
    })
    .expect_err("malformed apis root should be rejected");

    assert!(error.to_string().contains("apis must be a TOML table"));
    assert_eq!(std::fs::read_to_string(&config_path)?, original);

    Ok(())
}
