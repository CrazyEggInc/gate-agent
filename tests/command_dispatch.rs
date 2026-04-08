use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use clap::{Parser, error::ErrorKind};
use gate_agent::cli::{
    Cli, Command, ConfigAddApiArgs, ConfigAddClientArgs, ConfigArgs, ConfigCommand, ConfigInitArgs,
};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use tempfile::tempdir;
use toml::Value;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
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
    let _lock = env_lock().lock().expect("lock env");
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
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;

    assert!(config_path.exists());
    assert_eq!(
        written
            .get("auth")
            .and_then(|value| value.get("issuer"))
            .and_then(Value::as_str),
        Some("gate-agent")
    );
    assert!(written.get("clients").and_then(Value::as_table).is_some());
    assert!(written.get("apis").and_then(Value::as_table).is_some());

    Ok(())
}

#[test]
fn config_command_dispatch_runs_add_api_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
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
    let _lock = env_lock().lock().expect("lock env");
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
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            name: "mobile-app".to_owned(),
            api_key: Some("client-secret".to_owned()),
            api_key_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
            allowed_api: vec!["projects".to_owned(), "reports".to_owned()],
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    assert_eq!(
        client.get("api_key").and_then(Value::as_str),
        Some("client-secret")
    );
    assert_eq!(
        client.get("api_key_expires_at").and_then(Value::as_str),
        Some("2030-01-02T03:04:05Z")
    );
    assert_eq!(
        client
            .get("allowed_apis")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec!["projects", "reports"])
    );

    Ok(())
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
