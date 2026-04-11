use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use assert_cmd::Command as AssertCommand;
use clap::{Parser, error::ErrorKind};
use gate_agent::cli::{
    Cli, Command, ConfigAddApiArgs, ConfigAddClientArgs, ConfigArgs, ConfigCommand, ConfigInitArgs,
    ConfigValidateArgs,
};
use gate_agent::commands::config::{ConfigEditArgs, ConfigShowArgs};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use tempfile::tempdir;
use toml::Value;

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

struct EnvGuard {
    original_dir: PathBuf,
    original_home: Option<String>,
}

impl EnvGuard {
    fn enter(current_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let original_dir = std::env::current_dir()?;
        let original_home = std::env::var("HOME").ok();

        std::env::set_current_dir(current_dir)?;

        Ok(Self {
            original_dir,
            original_home,
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
        command: ConfigCommand::AddApi(ConfigAddApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            name: "projects".to_owned(),
            base_url: "https://example.test/api".to_owned(),
            auth_header: "authorization".to_owned(),
            auth_scheme: Some("Bearer".to_owned()),
            auth_value: "top-secret".to_owned(),
            timeout_ms: 5_000,
        }),
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
        api.get("auth_scheme").and_then(Value::as_str),
        Some("Bearer")
    );
    assert_eq!(
        api.get("auth_value").and_then(Value::as_str),
        Some("top-secret")
    );
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(5_000)
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
    assert!(client.get("api_key").is_none());
    assert!(client.get("api_key_expires_at").is_none());
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
