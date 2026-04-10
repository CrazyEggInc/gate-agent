use std::path::Path;

use assert_cmd::Command;
use gate_agent::commands::config::{
    ConfigAddClientArgs, ConfigInitArgs, ConfigShowArgs, ConfigValidateArgs, add_client, init,
    show, validate,
};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use gate_agent::config::secrets::AccessLevel;
use gate_agent::config::write::{self, ClientAccessUpsert, ClientUpsert, sha256_hex};
use secrecy::{ExposeSecret, SecretString};
use tempfile::tempdir;
use toml::Value;

const VALID_BEARER_VALIDATE_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "0011223344556677"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[groups]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

const INVALID_BEARER_VALIDATE_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "0011223344556677"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[groups]

[apis]
"#;

const STDIN_BEARER_VALIDATE_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "8899aabbccddeeff"
bearer_token_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { stdin-projects = "read" }

[groups]

[apis.stdin-projects]
base_url = "https://stdin-projects.internal.example"
auth_header = "x-api-key"
auth_value = "stdin-projects-secret-value"
timeout_ms = 5000
"#;

#[test]
fn config_init_generates_default_bearer_token_and_persists_only_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "init",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "default");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "default", &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);

    Ok(())
}

#[test]
fn config_add_client_generates_bearer_token_when_missing_and_prints_it_once()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "add-client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "partner",
            "--api-access",
            "projects=read",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "partner");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "partner", &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_add_client_generates_bearer_token_with_explicit_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "add-client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "partner",
            "--bearer-token-expires-at",
            "2031-02-03T04:05:06Z",
            "--api-access",
            "projects=write",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "partner");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "partner", &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_eq!(
        string_at(&config, &["clients", "partner", "bearer_token_expires_at"]),
        "2031-02-03T04:05:06Z"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "write"
    );

    Ok(())
}

#[test]
fn config_add_client_updates_expiry_without_rotating_existing_bearer_token()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    let existing_token = "partnertoken01.abcdefabcdefabcdefabcdefabcdefabcdef";

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;
    write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_owned(),
            bearer_token: Some(existing_token.to_owned()),
            bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
            access: ClientAccessUpsert::ApiAccess(
                [("projects".to_owned(), AccessLevel::Read)]
                    .into_iter()
                    .collect(),
            ),
        },
        None,
    )?;

    add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=write".to_owned()],
    })?;

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "partner", existing_token);
    assert_eq!(
        string_at(&config, &["clients", "partner", "bearer_token_expires_at"]),
        "2031-02-03T04:05:06Z"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "write"
    );

    Ok(())
}

#[test]
fn config_add_client_implicit_config_creation_prints_default_and_client_tokens_once()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "add-client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "partner",
            "--api-access",
            "projects=read",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].0, "default");
    assert_eq!(tokens[1].0, "partner");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "default", &tokens[0].1);
    assert_client_metadata_matches(&config, "partner", &tokens[1].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[1].1);

    Ok(())
}

#[test]
fn config_add_client_rejects_invalid_bearer_token_timestamp_message()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-02-31T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })
    .expect_err("invalid timestamp should fail");

    assert_eq!(
        error.to_string(),
        "invalid bearer_token_expires_at: invalid calendar date"
    );

    Ok(())
}

#[test]
fn config_validate_prefers_stdin_for_valid_bearer_config() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, INVALID_BEARER_VALIDATE_CONFIG)?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "validate",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ])
        .write_stdin(STDIN_BEARER_VALIDATE_CONFIG)
        .output()?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "config is valid\n");
    assert_eq!(String::from_utf8(output.stderr)?, "");

    Ok(())
}

#[test]
fn config_validate_returns_json_error_for_invalid_bearer_config()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, INVALID_BEARER_VALIDATE_CONFIG)?;

    let error = validate(ConfigValidateArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })
    .expect_err("invalid config should fail");

    assert_eq!(
        error.to_string(),
        r#"{"errors":[{"message":"clients.default.api_access contains unknown api 'projects'"}]}"#
    );

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "validate",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ])
        .output()?;

    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "");
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "{\"errors\":[{\"message\":\"clients.default.api_access contains unknown api 'projects'\"}]}\n"
    );

    Ok(())
}

#[test]
fn encrypted_config_add_client_preserves_password_workflow()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = SecretString::from("top-secret-password".to_owned());

    write::init_config(&config_path, true, Some(&password))?;

    add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })?;

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;

    let partner = table_at(&config, &["clients", "partner"]);
    assert!(
        partner
            .get("bearer_token_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        partner
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() == 64)
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_add_client_bootstraps_encrypted_config_when_password_is_supplied()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = "top-secret-password";

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "add-client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--password",
            password,
            "--name",
            "partner",
            "--bearer-token-expires-at",
            "2031-02-03T04:05:06Z",
            "--api-access",
            "projects=read",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let raw = std::fs::read_to_string(&config_path)?;
    assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;

    assert!(
        table_at(&config, &["clients", "default"])
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some()
    );
    assert!(
        table_at(&config, &["clients", "partner"])
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some()
    );

    Ok(())
}

#[test]
fn config_init_function_still_creates_explicit_config_path()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("nested/custom/secrets.toml");

    let written_path = init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    assert_eq!(written_path, config_path);
    assert!(written_path.exists());

    let config = load_toml(&written_path)?;
    assert!(config.get("auth").is_none());
    assert!(config.get("groups").and_then(Value::as_table).is_some());
    assert!(config.get("apis").and_then(Value::as_table).is_some());

    Ok(())
}

fn write_text(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;
    Ok(())
}

fn load_toml(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?.parse::<Value>()?)
}

fn table_at<'a>(value: &'a Value, path: &[&str]) -> &'a toml::map::Map<String, Value> {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing key: {key}"));
    }

    current
        .as_table()
        .unwrap_or_else(|| panic!("expected table at {}", path.join(".")))
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
        .unwrap_or_else(|| panic!("expected string at {}", path.join(".")))
}

fn printed_tokens(stdout: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            parse_printed_token(line)
                .ok_or_else(|| format!("unexpected stdout line: {line}").into())
        })
        .collect()
}

fn parse_printed_token(line: &str) -> Option<(String, String)> {
    let prefix = "generated bearer token for client '";
    let rest = line.strip_prefix(prefix)?;
    let (client_name, token) = rest.split_once("': ")?;
    split_full_token(token)?;
    Some((client_name.to_owned(), token.to_owned()))
}

fn split_full_token(value: &str) -> Option<(&str, &str)> {
    let (token_id, secret) = value.split_once('.')?;

    if token_id.is_empty() || secret.is_empty() || secret.contains('.') {
        return None;
    }

    Some((token_id, secret))
}

fn assert_client_metadata_matches(config: &Value, client_name: &str, full_token: &str) {
    let client = table_at(config, &["clients", client_name]);
    let (token_id, _) = split_full_token(full_token).expect("token format");

    assert_eq!(
        client.get("bearer_token_id").and_then(Value::as_str),
        Some(token_id)
    );
    assert_eq!(
        client.get("bearer_token_hash").and_then(Value::as_str),
        Some(sha256_hex(full_token).as_str())
    );
    assert!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str)
            .is_some()
    );
    assert!(client.get("api_key").is_none());
    assert!(client.get("api_key_expires_at").is_none());
}

fn assert_no_plain_bearer_token_persisted(config: &Value, full_token: &str) {
    let rendered = toml::to_string(config).expect("toml render");
    assert!(!rendered.contains(full_token));
}
