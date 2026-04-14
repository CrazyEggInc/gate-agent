use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use assert_cmd::Command as AssertCommand;
use clap::{Parser, error::ErrorKind};
use gate_agent::cli::{
    Cli, Command, ConfigAddApiArgs, ConfigAddClientArgs, ConfigAddGroupArgs, ConfigArgs,
    ConfigCommand, ConfigInitArgs, ConfigValidateArgs,
};
use gate_agent::commands::config::{ConfigEditArgs, ConfigShowArgs};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use tempfile::tempdir;
use toml::Value;

const TEST_PROMPT_INPUTS_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_INPUTS";
const DISABLE_INTERACTIVE_ENV_VAR: &str = "GATE_AGENT_DISABLE_INTERACTIVE";

const VALID_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

const INVALID_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "x-api-key"
auth_value = "billing-secret-value"
timeout_ms = 5000
"#;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn write_config(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;
    Ok(())
}

fn add_api_args(config: PathBuf, auth_header: &str, auth_value: &str) -> ConfigAddApiArgs {
    ConfigAddApiArgs {
        config: Some(config),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "projects".to_owned(),
        base_url: "https://example.test/api".to_owned(),
        auth_header: auth_header.to_owned(),
        auth_value: auth_value.to_owned(),
        timeout_ms: 5_000,
    }
}

struct EnvGuard {
    original_dir: PathBuf,
    original_home: Option<String>,
    original_disable_interactive: Option<String>,
}

impl EnvGuard {
    fn enter(current_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let original_dir = std::env::current_dir()?;
        let original_home = std::env::var("HOME").ok();
        let original_disable_interactive = std::env::var(DISABLE_INTERACTIVE_ENV_VAR).ok();

        std::env::set_current_dir(current_dir)?;
        unsafe {
            std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, "1");
        }

        Ok(Self {
            original_dir,
            original_home,
            original_disable_interactive,
        })
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_dir);

        unsafe {
            match &self.original_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }

            match &self.original_disable_interactive {
                Some(value) => std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, value),
                None => std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR),
            }
        }
    }
}

#[test]
fn config_command_dispatch_runs_init_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Init(ConfigInitArgs {
            config: Some(config_path.clone()),
            encrypted: false,
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("default"))
        .and_then(Value::as_table)
        .expect("default client config");

    assert!(config_path.exists());
    assert!(written.get("auth").is_none());
    assert!(
        client
            .get("bearer_token_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some_and(|value| value.chars().all(|char| char.is_ascii_hexdigit()))
    );
    assert!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str)
            .is_some()
    );
    assert!(client.get("api_access").and_then(Value::as_table).is_some());
    assert!(written.get("clients").and_then(Value::as_table).is_some());
    assert!(written.get("groups").and_then(Value::as_table).is_some());
    assert!(written.get("apis").and_then(Value::as_table).is_some());

    Ok(())
}

#[test]
fn config_command_dispatch_runs_add_api_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::AddApi(add_api_args(
            config_path.clone(),
            "authorization",
            "top-secret",
        )),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("projects"))
        .and_then(Value::as_table)
        .expect("projects api config");

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://example.test/api")
    );
    assert_eq!(
        api.get("auth_header").and_then(Value::as_str),
        Some("authorization")
    );
    assert_eq!(
        api.get("auth_value").and_then(Value::as_str),
        Some("top-secret")
    );
    assert!(api.get("auth_scheme").is_none());
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(5_000)
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_add_api_subcommand_without_upstream_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::AddApi(add_api_args(config_path.clone(), "", "")),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("projects"))
        .and_then(Value::as_table)
        .expect("projects api config");

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://example.test/api")
    );
    assert!(api.get("auth_header").is_none());
    assert!(api.get("auth_scheme").is_none());
    assert!(api.get("auth_value").is_none());
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(5_000)
    );

    Ok(())
}

#[test]
fn config_command_dispatch_rejects_add_api_auth_value_without_auth_header()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::AddApi(add_api_args(config_path, "", "top-secret")),
    }))
    .expect_err("auth_value without auth_header should fail");

    assert_eq!(
        error.to_string(),
        "auth_value cannot be set without auth_header"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_add_client_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::AddClient(ConfigAddClientArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            name: "mobile-app".to_owned(),
            bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
            group: None,
            api_access: vec!["projects=read,reports=write".to_owned()],
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    assert!(
        client
            .get("bearer_token_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some_and(|value| value.chars().all(|char| char.is_ascii_hexdigit()))
    );
    assert_eq!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str),
        Some("2030-01-02T03:04:05Z")
    );
    assert_eq!(
        client
            .get("api_access")
            .and_then(|value| value.get("projects"))
            .and_then(Value::as_str),
        Some("read")
    );
    assert_eq!(
        client
            .get("api_access")
            .and_then(|value| value.get("reports"))
            .and_then(Value::as_str),
        Some("write")
    );

    Ok(())
}

#[test]
fn cli_rejects_obsolete_curl_subcommand() {
    assert_eq!(
        Cli::try_parse_from(["gate-agent", "curl"])
            .expect_err("curl subcommand should be removed")
            .kind(),
        ErrorKind::InvalidSubcommand
    );
}

#[test]
fn cli_rejects_bearer_token_flag_for_config_add_client() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--bearer-token",
        "partner-secret",
        "--bearer-token-expires-at",
        "2030-01-02T03:04:05Z",
        "--api-access",
        "projects=read",
    ]);

    assert_eq!(
        parsed
            .expect_err("bearer-token flag should be removed")
            .kind(),
        ErrorKind::UnknownArgument
    );
}

#[test]
fn cli_rejects_removed_api_key_flags_for_config_add_client() {
    assert_eq!(
        Cli::try_parse_from([
            "gate-agent",
            "config",
            "add-client",
            "--name",
            "partner",
            "--api-key",
            "partner-secret",
            "--api-access",
            "projects=read",
        ])
        .expect_err("api-key flag should be removed")
        .kind(),
        ErrorKind::UnknownArgument
    );
}

#[test]
fn config_command_dispatch_add_client_prints_generated_bearer_token_once()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    write_config(&config_path, VALID_CONFIG)?;

    let output = AssertCommand::cargo_bin("gate-agent")?
        .current_dir(&workspace)
        .env("HOME", temp_dir.path().join("home"))
        .env_remove(TEST_PROMPT_INPUTS_ENV_VAR)
        .args([
            "config",
            "add-client",
            "--config",
            config_path.to_str().expect("utf-8 config path"),
            "--name",
            "mobile-app",
            "--bearer-token-expires-at",
            "2030-01-02T03:04:05Z",
            "--api-access",
            "projects=read,reports=write",
        ])
        .output()?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr)?, "");

    let stdout = String::from_utf8(output.stdout)?;
    let printed_lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(printed_lines.len(), 1);

    let full_token =
        parse_printed_token(printed_lines[0], "mobile-app").expect("printed bearer token");
    let (token_id, secret) = split_full_token(&full_token).expect("full bearer token format");
    assert!(!secret.is_empty());
    assert!(!stdout.contains("api_key"));

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    assert_eq!(
        client.get("bearer_token_id").and_then(Value::as_str),
        Some(token_id)
    );
    assert_eq!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str),
        Some("2030-01-02T03:04:05Z")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_add_group_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::AddGroup(ConfigAddGroupArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            name: "readonly".to_owned(),
            api_access: vec!["projects=read,reports=write".to_owned()],
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let group = written
        .get("groups")
        .and_then(|value| value.get("readonly"))
        .and_then(Value::as_table)
        .expect("readonly group config");

    assert_eq!(
        group
            .get("api_access")
            .and_then(|value| value.get("projects"))
            .and_then(Value::as_str),
        Some("read")
    );
    assert_eq!(
        group
            .get("api_access")
            .and_then(|value| value.get("reports"))
            .and_then(Value::as_str),
        Some("write")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_validate_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    write_config(&config_path, VALID_CONFIG)?;

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Validate(ConfigValidateArgs {
            config: Some(config_path),
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
        }),
    }))?;

    Ok(())
}

#[test]
fn config_command_dispatch_validate_returns_json_shaped_error_text()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    write_config(&config_path, INVALID_CONFIG)?;

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Validate(ConfigValidateArgs {
            config: Some(config_path),
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
        }),
    }))
    .expect_err("invalid config should fail");

    assert_eq!(
        error.to_string(),
        r#"{"errors":[{"message":"clients.default.api_access contains unknown api 'projects'"}]}"#
    );

    let output = AssertCommand::cargo_bin("gate-agent")?
        .args([
            "config",
            "validate",
            "--config",
            workspace
                .join("nested/secrets.toml")
                .to_str()
                .expect("utf-8 config path"),
        ])
        .output()?;

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "{\"errors\":[{\"message\":\"clients.default.api_access contains unknown api 'projects'\"}]}\n"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_structs_cover_show_and_edit_args() {
    let show_args = ConfigShowArgs {
        config: Some(PathBuf::from(".secrets")),
        password: Some("secret".to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    };
    let edit_args = ConfigEditArgs {
        config: Some(PathBuf::from(".secrets")),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    };

    assert_eq!(show_args.config.as_deref(), Some(Path::new(".secrets")));
    assert_eq!(show_args.password.as_deref(), Some("secret"));
    assert_eq!(edit_args.config.as_deref(), Some(Path::new(".secrets")));
    assert!(edit_args.password.is_none());
}

#[test]
fn help_command_rejects_explicit_help_subcommands() {
    assert!(Cli::try_parse_from(["gate-agent", "help"]).is_err());
    assert!(Cli::try_parse_from(["gate-agent", "config", "help"]).is_err());
    assert_eq!(
        Cli::try_parse_from(["gate-agent", "--help"])
            .expect_err("--help should render built-in help")
            .kind(),
        ErrorKind::DisplayHelp
    );
}

fn parse_printed_token(line: &str, client_name: &str) -> Option<String> {
    let prefix = format!("Generated token for client '{client_name}': ");
    let token = line.strip_prefix(&prefix)?;
    split_full_token(token)?;
    Some(token.to_owned())
}

fn split_full_token(value: &str) -> Option<(&str, &str)> {
    let (token_id, secret) = value.split_once('.')?;

    if token_id.is_empty() || secret.is_empty() || secret.contains('.') {
        return None;
    }

    Some((token_id, secret))
}
