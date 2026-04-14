use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::{Mutex, OnceLock};

use assert_cmd::Command;
use gate_agent::commands::config::{
    ConfigAddClientArgs, ConfigAddGroupArgs, ConfigInitArgs, ConfigShowArgs, ConfigValidateArgs,
    add_client, add_group, init, show, validate,
};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use gate_agent::config::password::PASSWORD_ENV_VAR;
use gate_agent::config::path::CONFIG_ENV_VAR;
use gate_agent::config::secrets::AccessLevel;
use gate_agent::config::write::{self, ClientAccessUpsert, ClientUpsert, sha256_hex};
use secrecy::{ExposeSecret, SecretString};
use tempfile::tempdir;
use toml::Value;

const TEST_KEYRING_FILE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_FILE";
const TEST_KEYRING_STORE_FAILURE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_STORE_FAILURE";
const TEST_PROMPT_INPUTS_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_INPUTS";
const TEST_PROMPT_PASSWORD_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_PASSWORD";
const DISABLE_INTERACTIVE_ENV_VAR: &str = "GATE_AGENT_DISABLE_INTERACTIVE";

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

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    original_dir: PathBuf,
    original_env: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn enter(current_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let original_dir = std::env::current_dir()?;
        let original_env = tracked_env_vars()
            .into_iter()
            .map(|name| (name, std::env::var(name).ok()))
            .collect();

        std::env::set_current_dir(current_dir)?;
        unsafe {
            std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, "1");
        }

        Ok(Self {
            original_dir,
            original_env,
        })
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_dir);

        unsafe {
            for (name, value) in &self.original_env {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn tracked_env_vars() -> Vec<&'static str> {
    vec![
        CONFIG_ENV_VAR,
        "HOME",
        PASSWORD_ENV_VAR,
        "VISUAL",
        "EDITOR",
        TEST_KEYRING_FILE_ENV_VAR,
        TEST_KEYRING_STORE_FAILURE_ENV_VAR,
        TEST_PROMPT_INPUTS_ENV_VAR,
        TEST_PROMPT_PASSWORD_ENV_VAR,
        DISABLE_INTERACTIVE_ENV_VAR,
    ]
}

fn load_toml(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?.parse::<Value>()?)
}

fn write_text(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;
    Ok(())
}

fn set_test_prompt_inputs(inputs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::set_var(TEST_PROMPT_INPUTS_ENV_VAR, serde_json::to_string(inputs)?);
    }

    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_gate_agent_in_tty(
    current_dir: &Path,
    args: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let binary = assert_cmd::cargo::cargo_bin("gate-agent");
    let binary = binary.to_str().ok_or("cargo_bin path must be utf-8")?;
    let mut command = shell_quote(binary);

    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }

    Ok(ProcessCommand::new("script")
        .current_dir(current_dir)
        .arg("-qec")
        .arg(command)
        .arg("/dev/null")
        .output()?)
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

#[test]
fn config_init_generates_default_bearer_token_and_persists_only_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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
fn config_add_client_merges_repeated_and_comma_separated_api_access_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec![
            "projects=read,billing=write".to_owned(),
            "reports=read".to_owned(),
        ],
    })?;

    let config = load_toml(&config_path)?;

    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "billing"]),
        "write"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "reports"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_conflicting_duplicate_api_access_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned(), "projects=write".to_owned()],
    })
    .expect_err("conflicting api access should fail");

    assert_eq!(
        error.to_string(),
        "conflicting api_access entries for api 'projects'"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_invalid_api_access_level_with_clear_message()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=admin".to_owned()],
    })
    .expect_err("invalid api access level should fail");

    assert_eq!(
        error.to_string(),
        "api_access level 'admin' must be one of: read, write"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_leading_empty_segment_in_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec![",projects=read".to_owned()],
    })
    .expect_err("leading empty segment should be rejected");

    assert_eq!(
        error.to_string(),
        "api_access entries cannot contain empty comma-separated segments"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_trailing_comma_in_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read,".to_owned()],
    })
    .expect_err("trailing comma should be rejected");

    assert_eq!(
        error.to_string(),
        "api_access entries cannot contain empty comma-separated segments"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_doubled_comma_in_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read,,billing=write".to_owned()],
    })
    .expect_err("doubled comma should be rejected");

    assert_eq!(
        error.to_string(),
        "api_access entries cannot contain empty comma-separated segments"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_malformed_segment_in_comma_separated_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read,billing".to_owned()],
    })
    .expect_err("malformed comma-separated segment should be rejected");

    assert_eq!(
        error.to_string(),
        "invalid api_access entry 'billing'; expected api=level"
    );

    Ok(())
}

#[test]
fn config_add_client_writes_group_reference_without_inline_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    write_text(
        &config_path,
        concat!(
            "[clients.default]\n",
            "bearer_token_id = \"0011223344556677\"\n",
            "bearer_token_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "bearer_token_expires_at = \"2030-01-02T03:04:05Z\"\n",
            "api_access = {}\n\n",
            "[groups.partner-readonly]\n",
            "api_access = { projects = \"read\" }\n\n",
            "[apis.projects]\n",
            "base_url = \"https://projects.internal.example\"\n",
            "auth_header = \"x-api-key\"\n",
            "auth_value = \"projects-secret-value\"\n",
            "timeout_ms = 5000\n",
        ),
    )?;

    add_client(ConfigAddClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: Some("partner-readonly".to_owned()),
        api_access: vec![],
    })?;

    let config = load_toml(&config_path)?;
    let client = table_at(&config, &["clients", "partner"]);

    assert_eq!(
        client.get("group").and_then(Value::as_str),
        Some("partner-readonly")
    );
    assert!(client.get("api_access").is_none());
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_add_client_uses_prompted_name_and_existing_group()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddGroup(
                gate_agent::cli::ConfigAddGroupArgs {
                    config: Some(config_path.clone()),
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    name: "partner-readonly".to_owned(),
                    api_access: vec!["projects=read".to_owned()],
                },
            ),
        },
    ))?;

    set_test_prompt_inputs(&["partner", "partner-readonly"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddClient(
                gate_agent::cli::ConfigAddClientArgs {
                    config: Some(config_path.clone()),
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    name: String::new(),
                    bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
                    group: None,
                    api_access: vec![],
                },
            ),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let client = table_at(&config, &["clients", "partner"]);

    assert_eq!(
        client.get("group").and_then(Value::as_str),
        Some("partner-readonly")
    );
    assert!(client.get("api_access").is_none());
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_add_client_falls_back_to_prompted_inline_api_access_when_group_is_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&["partner", "", "projects=read,reports=write"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddClient(
                gate_agent::cli::ConfigAddClientArgs {
                    config: Some(config_path.clone()),
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    name: String::new(),
                    bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
                    group: None,
                    api_access: vec![],
                },
            ),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let client = table_at(&config, &["clients", "partner"]);

    assert!(client.get("group").is_none());
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "reports"]),
        "write"
    );
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_add_group_uses_prompt_seam_for_missing_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&["readonly", "projects=read,reports=write"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddGroup(
                gate_agent::cli::ConfigAddGroupArgs {
                    config: Some(config_path.clone()),
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    name: String::new(),
                    api_access: vec![],
                },
            ),
        },
    ))?;

    let config = load_toml(&config_path)?;

    assert_eq!(
        string_at(&config, &["groups", "readonly", "api_access", "projects"]),
        "read"
    );
    assert_eq!(
        string_at(&config, &["groups", "readonly", "api_access", "reports"]),
        "write"
    );

    Ok(())
}

#[test]
fn config_add_group_rejects_empty_api_access_entries() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = add_group(ConfigAddGroupArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "readonly".to_owned(),
        api_access: vec![],
    })
    .expect_err("empty group api_access should fail");

    assert_eq!(
        error.to_string(),
        "api_access entries are required for groups"
    );

    Ok(())
}

#[test]
fn config_add_api_uses_prompt_seam_for_missing_fields() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&[
        "projects",
        "https://projects.internal.example/api",
        "authorization",
        "Bearer local-upstream-token",
    ])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddApi(gate_agent::cli::ConfigAddApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                name: String::new(),
                base_url: String::new(),
                auth_header: String::new(),
                auth_value: String::new(),
                timeout_ms: 5_000,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert_eq!(
        api.get("auth_header").and_then(Value::as_str),
        Some("authorization")
    );
    assert_eq!(
        api.get("auth_value").and_then(Value::as_str),
        Some("Bearer local-upstream-token")
    );
    assert!(api.get("auth_scheme").is_none());

    Ok(())
}

#[test]
fn config_add_api_skips_auth_prompts_and_persistence_when_auth_header_is_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&["projects", "https://projects.internal.example/api", "none"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddApi(gate_agent::cli::ConfigAddApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                name: String::new(),
                base_url: String::new(),
                auth_header: String::new(),
                auth_value: String::new(),
                timeout_ms: 5_000,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert!(api.get("auth_header").is_none());
    assert!(api.get("auth_value").is_none());
    assert!(api.get("auth_scheme").is_none());

    Ok(())
}

#[test]
fn config_add_api_non_interactive_allows_missing_auth_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddApi(gate_agent::cli::ConfigAddApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                name: "projects".to_owned(),
                base_url: "https://projects.internal.example/api".to_owned(),
                auth_header: String::new(),
                auth_value: String::new(),
                timeout_ms: 5_000,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert!(api.get("auth_header").is_none());
    assert!(api.get("auth_value").is_none());

    Ok(())
}

#[test]
fn config_add_api_rejects_auth_header_without_auth_value_non_interactively()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddApi(gate_agent::cli::ConfigAddApiArgs {
                config: Some(config_path),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                name: "projects".to_owned(),
                base_url: "https://projects.internal.example/api".to_owned(),
                auth_header: "authorization".to_owned(),
                auth_value: String::new(),
                timeout_ms: 5_000,
            }),
        },
    ))
    .expect_err("auth_header without auth_value should fail");

    assert_eq!(
        error.to_string(),
        "auth_value is required when auth_header is configured"
    );

    Ok(())
}

#[test]
fn config_add_api_rejects_auth_value_without_auth_header_non_interactively()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddApi(gate_agent::cli::ConfigAddApiArgs {
                config: Some(config_path),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                name: "projects".to_owned(),
                base_url: "https://projects.internal.example/api".to_owned(),
                auth_header: String::new(),
                auth_value: "local-upstream-token".to_owned(),
                timeout_ms: 5_000,
            }),
        },
    ))
    .expect_err("auth_value without auth_header should fail");

    assert_eq!(
        error.to_string(),
        "auth_value cannot be set without auth_header"
    );

    Ok(())
}

#[test]
fn config_add_client_implicit_config_creation_prints_default_and_client_tokens_once()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, INVALID_BEARER_VALIDATE_CONFIG)?;

    let output = Command::cargo_bin("gate-agent")?
        .env_remove(CONFIG_ENV_VAR)
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_INPUTS_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env_remove(DISABLE_INTERACTIVE_ENV_VAR)
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
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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

    assert_client_has_bearer_metadata(&config, "partner");
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_show_prints_plaintext_contents() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join(".secrets");
    let contents = concat!(
        "[clients.default]\n",
        "bearer_token_id = \"0011223344556677\"\n",
        "bearer_token_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        "bearer_token_expires_at = \"2030-01-02T03:04:05Z\"\n",
        "api_access = {}\n\n",
        "[groups]\n\n",
        "[apis]\n",
    );
    std::fs::write(&config_path, contents)?;

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    assert_eq!(shown, contents);

    Ok(())
}

#[test]
fn config_init_prompts_for_default_encryption_and_config_path_when_omitted_in_tty()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    let home_dir = temp_dir.path().join("home");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    unsafe {
        std::env::set_var("HOME", &home_dir);
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
        std::env::set_var(TEST_PROMPT_PASSWORD_ENV_VAR, "top-secret-password");
    }
    set_test_prompt_inputs(&["", "nested/interactive.secrets"])?;

    let output = run_gate_agent_in_tty(&workspace, &["config", "init"])?;
    let config_path = workspace.join("nested/interactive.secrets");

    assert!(output.status.success(), "{output:?}");
    assert!(config_path.exists());
    assert!(
        std::fs::read_to_string(&config_path)?.starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    );

    let stderr = String::from_utf8(output.stderr)?;
    let normalized_stderr = stderr.replace("\r", "");
    assert!(
        normalized_stderr.is_empty()
            || (normalized_stderr.contains("Write encrypted config? [Y/n]")
                && normalized_stderr.contains("Config path")
                && normalized_stderr.contains("default: ~/.config/gate-agent/secrets"))
    );

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "default");

    Ok(())
}

#[test]
fn config_add_api_respects_disable_interactive_env_even_in_tty()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    unsafe {
        std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, "1");
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }

    let output = run_gate_agent_in_tty(
        &workspace,
        &[
            "config",
            "add-api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ],
    )?;

    assert!(!output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("config add-api requires --name in non-interactive sessions"),
        "{combined}"
    );
    assert!(!combined.contains("Auth header"), "{combined}");

    Ok(())
}

#[test]
fn config_questionnaire_commands_fail_non_interactively_without_required_input()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let client_error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddClient(
                gate_agent::cli::ConfigAddClientArgs {
                    config: Some(config_path.clone()),
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    name: String::new(),
                    bearer_token_expires_at: None,
                    group: None,
                    api_access: vec![],
                },
            ),
        },
    ))
    .expect_err("missing add-client input should fail");

    let group_error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddGroup(
                gate_agent::cli::ConfigAddGroupArgs {
                    config: Some(config_path.clone()),
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    name: String::new(),
                    api_access: vec![],
                },
            ),
        },
    ))
    .expect_err("missing add-group input should fail");

    let api_error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::AddApi(gate_agent::cli::ConfigAddApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                name: String::new(),
                base_url: String::new(),
                auth_header: String::new(),
                auth_value: String::new(),
                timeout_ms: 5_000,
            }),
        },
    ))
    .expect_err("missing add-api input should fail");

    assert_eq!(
        client_error.to_string(),
        "config add-client requires --name in non-interactive sessions"
    );
    assert_eq!(
        group_error.to_string(),
        "config add-group requires --name in non-interactive sessions"
    );
    assert_eq!(
        api_error.to_string(),
        "config add-api requires --name in non-interactive sessions"
    );

    Ok(())
}

#[test]
fn config_add_client_bootstraps_encrypted_config_when_password_is_supplied()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].0, "default");
    assert_eq!(tokens[1].0, "partner");

    let raw = std::fs::read_to_string(&config_path)?;
    assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;

    assert_client_metadata_matches(&config, "default", &tokens[0].1);
    assert_client_metadata_matches(&config, "partner", &tokens[1].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[1].1);

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
    let prefix = "Generated token for client '";
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
}

fn assert_client_has_bearer_metadata(config: &Value, client_name: &str) {
    let client = table_at(config, &["clients", client_name]);

    assert!(
        client
            .get("bearer_token_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() == 64)
    );
    assert!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str)
            .is_some()
    );
}

fn assert_no_plain_bearer_token_persisted(config: &Value, full_token: &str) {
    let rendered = toml::to_string(config).expect("toml render");
    assert!(!rendered.contains(full_token));
}
