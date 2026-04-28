use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};

use assert_cmd::Command as AssertCommand;
use clap::{Parser, error::ErrorKind};
use gate_agent::cli::{
    Cli, Command, ConfigApiArgs, ConfigArgs, ConfigClientArgs, ConfigClientSubcommand,
    ConfigCommand, ConfigEditArgs, ConfigGroupArgs, ConfigInitArgs, ConfigRotateSecretArgs,
    ConfigShowArgs, ConfigValidateArgs,
};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use tempfile::{NamedTempFile, tempdir};
use toml::Value;

const TEST_PROMPT_INPUTS_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_INPUTS";
const DISABLE_INTERACTIVE_ENV_VAR: &str = "GATE_AGENT_DISABLE_INTERACTIVE";
const TEST_SCRYPT_WORK_FACTOR_ENV_VAR: &str = "GATE_AGENT_TEST_SCRYPT_WORK_FACTOR";
const VERSION_DISPATCH_HELPER_ENV_VAR: &str = "GATE_AGENT_VERSION_DISPATCH_HELPER";
const VERSION_DISPATCH_HELPER_TEST: &str =
    "version_command_dispatch_skips_tracing_bootstrap_helper";
const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

const VALID_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = [{ method = "get", path = "/api/*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#;

const INVALID_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = [{ method = "get", path = "/api/*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { x-api-key = "billing-secret-value" }
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

fn write_config_bytes(path: &Path, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;
    Ok(())
}

fn api_args(config: PathBuf, headers: &[&str]) -> ConfigApiArgs {
    ConfigApiArgs {
        config: Some(config),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: Some("projects".to_owned()),
        base_url: Some("https://example.test/api".to_owned()),
        basic_auth: false,
        header: headers.iter().map(|header| (*header).to_owned()).collect(),
        timeout_ms: Some(5_000),
    }
}

fn client_args(config: PathBuf, name: &str) -> ConfigClientArgs {
    ConfigClientArgs {
        config: Some(config),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: Some(name.to_owned()),
        bearer_token_expires_at: Some("2030-01-02".to_owned()),
        group: None,
        api_access: vec!["projects:get:/api/*,reports:*:*".to_owned()],
        command: None,
    }
}

fn rotate_secret_client_args(config: PathBuf, name: String) -> ConfigClientArgs {
    ConfigClientArgs {
        config: Some(config.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: None,
        bearer_token_expires_at: None,
        group: None,
        api_access: vec![],
        command: Some(ConfigClientSubcommand::RotateSecret(
            ConfigRotateSecretArgs {
                config: Some(config),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                log_level_explicitly_set: false,
                name,
                bearer_token_expires_at: None,
            },
        )),
    }
}

fn rotate_secret_parent_args_with_forbidden_flags(
    config: PathBuf,
    delete: bool,
    group: Option<&str>,
    api_access: &[&str],
) -> ConfigClientArgs {
    ConfigClientArgs {
        config: Some(config),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete,
        name: Some("mobile-app".to_owned()),
        bearer_token_expires_at: Some("2031-02-03".to_owned()),
        group: group.map(str::to_owned),
        api_access: api_access.iter().map(|value| (*value).to_owned()).collect(),
        command: Some(ConfigClientSubcommand::RotateSecret(
            ConfigRotateSecretArgs {
                config: None,
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                log_level_explicitly_set: false,
                name: String::new(),
                bearer_token_expires_at: None,
            },
        )),
    }
}

fn encrypted_client_config() -> String {
    r#"
[auth]
encryption = "age"

[clients.mobile-app]
bearer_token_id = "mobile-app"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
    api_access = { projects = [{ method = "get", path = "/api/*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#
    .to_owned()
}

fn encrypt_test_config(
    contents: &str,
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut recipient =
        age::scrypt::Recipient::new(age::secrecy::SecretString::from(password.to_owned()));
    recipient.set_work_factor(4);
    let encrypted = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?;
    let mut encrypted_bytes = Vec::new();
    {
        let mut writer = encrypted.wrap_output(&mut encrypted_bytes)?;
        writer.write_all(contents.as_bytes())?;
        writer.finish()?;
    }

    Ok(encrypted_bytes)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn assert_api_access_rule(
    api_access: Option<&Value>,
    api: &str,
    index: usize,
    method: &str,
    path: &str,
) {
    let rule = api_access
        .and_then(|value| value.get(api))
        .and_then(Value::as_array)
        .and_then(|rules| rules.get(index))
        .and_then(Value::as_table)
        .expect("api access rule");

    assert_eq!(rule.get("method").and_then(Value::as_str), Some(method));
    assert_eq!(rule.get("path").and_then(Value::as_str), Some(path));
}

struct TtyCommandOutput {
    output: std::process::Output,
    transcript: String,
}

fn normalize_pty_output(output: &str) -> String {
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn run_gate_agent_in_tty_with_stdin(
    current_dir: &Path,
    stdin_lines: &[&str],
    args: &[&str],
) -> Result<TtyCommandOutput, Box<dyn std::error::Error>> {
    let binary = assert_cmd::cargo::cargo_bin("gate-agent");
    let binary = binary.to_str().ok_or("cargo_bin path must be utf-8")?;
    let mut command = shell_quote(binary);
    let transcript_file = NamedTempFile::new_in(current_dir)?;
    let transcript_path = transcript_file.path().to_path_buf();

    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }

    let mut child = ProcessCommand::new("script")
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .arg("-qec")
        .arg(command)
        .arg(&transcript_path)
        .spawn()?;

    {
        let stdin = child.stdin.as_mut().ok_or("script stdin unavailable")?;

        for line in stdin_lines {
            stdin.write_all(line.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
    }

    let output = child.wait_with_output()?;
    let transcript = std::fs::read_to_string(transcript_path)?;

    Ok(TtyCommandOutput { output, transcript })
}

struct EnvGuard {
    original_dir: PathBuf,
    original_home: Option<String>,
    original_test_prompt_inputs: Option<String>,
    original_disable_interactive: Option<String>,
    original_test_scrypt_work_factor: Option<String>,
}

impl EnvGuard {
    fn enter(current_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let original_dir = std::env::current_dir()?;
        let original_home = std::env::var("HOME").ok();
        let original_test_prompt_inputs = std::env::var(TEST_PROMPT_INPUTS_ENV_VAR).ok();
        let original_disable_interactive = std::env::var(DISABLE_INTERACTIVE_ENV_VAR).ok();
        let original_test_scrypt_work_factor = std::env::var(TEST_SCRYPT_WORK_FACTOR_ENV_VAR).ok();

        std::env::set_current_dir(current_dir)?;
        unsafe {
            std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, "1");
            std::env::set_var(TEST_SCRYPT_WORK_FACTOR_ENV_VAR, "4");
        }

        Ok(Self {
            original_dir,
            original_home,
            original_test_prompt_inputs,
            original_disable_interactive,
            original_test_scrypt_work_factor,
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

            match &self.original_test_prompt_inputs {
                Some(value) => std::env::set_var(TEST_PROMPT_INPUTS_ENV_VAR, value),
                None => std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR),
            }

            match &self.original_disable_interactive {
                Some(value) => std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, value),
                None => std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR),
            }

            match &self.original_test_scrypt_work_factor {
                Some(value) => std::env::set_var(TEST_SCRYPT_WORK_FACTOR_ENV_VAR, value),
                None => std::env::remove_var(TEST_SCRYPT_WORK_FACTOR_ENV_VAR),
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
    assert_eq!(
        client.get("group").and_then(Value::as_str),
        Some("local-default")
    );
    assert!(client.get("api_access").is_none());
    assert!(written.get("clients").and_then(Value::as_table).is_some());
    assert!(written.get("groups").and_then(Value::as_table).is_some());
    assert!(
        written
            .get("groups")
            .and_then(|value| value.get("local-default"))
            .and_then(|value| value.get("api_access"))
            .and_then(Value::as_table)
            .is_some()
    );
    assert!(written.get("apis").and_then(Value::as_table).is_some());

    Ok(())
}

#[test]
fn config_command_dispatch_runs_api_subcommand() -> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Api(api_args(
            config_path.clone(),
            &["authorization=Bearer top-secret", "x-api-key=secret-key"],
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
        api.get("headers")
            .and_then(|value| value.get("authorization"))
            .and_then(Value::as_str),
        Some("Bearer top-secret")
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("x-api-key"))
            .and_then(Value::as_str),
        Some("secret-key")
    );
    assert!(api.get("auth_header").is_none());
    assert!(api.get("auth_value").is_none());
    assert!(api.get("auth_scheme").is_none());
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(5_000)
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_api_subcommand_without_upstream_headers()
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
        command: ConfigCommand::Api(api_args(config_path.clone(), &[])),
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
    assert!(api.get("headers").is_none());
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
fn config_command_dispatch_basic_auth_flag_still_requires_interactive_prompts()
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
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://example.test/api".to_owned()),
            basic_auth: true,
            header: vec![],
            timeout_ms: Some(5_000),
        }),
    }))
    .expect_err("basic auth flag should fail without interactive prompts");

    assert_eq!(
        error.to_string(),
        "config api --basic-auth requires interactive username prompt"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_basic_auth_flag_prompts_username_and_password()
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
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&["", "projects-user", "projects-pass"])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://example.test/api".to_owned()),
            basic_auth: true,
            header: vec![],
            timeout_ms: Some(5_000),
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("projects"))
        .and_then(Value::as_table)
        .expect("projects api config");

    assert_eq!(
        api.get("basic_auth")
            .and_then(|value| value.get("username"))
            .and_then(Value::as_str),
        Some("projects-user")
    );
    assert_eq!(
        api.get("basic_auth")
            .and_then(|value| value.get("password"))
            .and_then(Value::as_str),
        Some("projects-pass")
    );
    assert!(api.get("headers").is_none());

    Ok(())
}

#[test]
fn config_command_dispatch_api_preserves_existing_timeout_when_omitted()
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
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://example.test/api".to_owned()),
            basic_auth: false,
            header: vec!["authorization=Bearer top-secret".to_owned()],
            timeout_ms: Some(9_000),
        }),
    }))?;

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://example.test/api/v2".to_owned()),
            basic_auth: false,
            header: vec!["authorization=Bearer rotated-secret".to_owned()],
            timeout_ms: None,
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
        Some("https://example.test/api/v2")
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("authorization"))
            .and_then(Value::as_str),
        Some("Bearer rotated-secret")
    );
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(9_000)
    );
    assert!(api.get("auth_header").is_none());
    assert!(api.get("auth_value").is_none());

    Ok(())
}

#[test]
fn config_command_dispatch_api_preserves_existing_headers_when_header_omitted()
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
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://example.test/api".to_owned()),
            basic_auth: false,
            header: vec![
                "authorization=Bearer top-secret".to_owned(),
                "x-api-key=secret-key".to_owned(),
            ],
            timeout_ms: Some(9_000),
        }),
    }))?;

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://example.test/api/v2".to_owned()),
            basic_auth: false,
            header: vec![],
            timeout_ms: None,
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
        Some("https://example.test/api/v2")
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("authorization"))
            .and_then(Value::as_str),
        Some("Bearer top-secret")
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("x-api-key"))
            .and_then(Value::as_str),
        Some("secret-key")
    );
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(9_000)
    );
    assert!(api.get("auth_header").is_none());
    assert!(api.get("auth_scheme").is_none());
    assert!(api.get("auth_value").is_none());

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_api_prompt_none_clears_existing_headers()
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
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://projects.internal.example/api".to_owned()),
            basic_auth: false,
            header: vec![
                "authorization=Bearer top-secret".to_owned(),
                "x-api-key=secret-key".to_owned(),
            ],
            timeout_ms: Some(5_000),
        }),
    }))?;

    let tty_output = run_gate_agent_in_tty_with_stdin(
        &workspace,
        &["", "none", "n"],
        &[
            "config",
            "api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "projects",
        ],
    )?;

    assert!(
        tty_output.output.status.success(),
        "{:?}",
        tty_output.output
    );

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("projects"))
        .and_then(Value::as_table)
        .expect("projects api config");

    assert!(api.get("headers").is_none());

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_api_prompts_headers_before_basic_auth()
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
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }

    let tty_output = run_gate_agent_in_tty_with_stdin(
        &workspace,
        &[
            "",
            "projects",
            "https://projects.internal.example/api",
            "",
            "n",
        ],
        &[
            "config",
            "api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ],
    )?;

    assert!(
        tty_output.output.status.success(),
        "{:?}",
        tty_output.output
    );

    let combined = normalize_pty_output(&tty_output.transcript);

    let headers_prompt = "Headers (example: x-api-key=secret; leave empty for no headers):";
    let basic_auth_prompt = "Configure basic auth? (blank skips basic auth) [y/N]";

    assert!(combined.contains(headers_prompt), "{combined}");
    assert!(combined.contains(basic_auth_prompt), "{combined}");
    assert!(!combined.contains("Auth mode"), "{combined}");

    let headers_index = combined
        .find(headers_prompt)
        .expect("headers prompt present");
    let basic_auth_index = combined
        .find(basic_auth_prompt)
        .expect("basic auth prompt present");
    assert!(headers_index < basic_auth_index, "{combined}");

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("projects"))
        .and_then(Value::as_table)
        .expect("projects api config");
    assert!(api.get("headers").is_none());

    Ok(())
}

#[test]
fn config_command_dispatch_rejects_malformed_api_prompt_headers()
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
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&[
                "projects",
                "https://projects.internal.example/api",
                "authorization",
                "n",
            ])?,
        );
    }

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: None,
            base_url: None,
            basic_auth: false,
            header: Vec::new(),
            timeout_ms: Some(5_000),
        }),
    }))
    .expect_err("malformed prompt header should fail");

    assert_eq!(
        error.to_string(),
        "header must be formatted as <name>=<value>; repeat --header for multiple upstream headers"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_api_prompt_round_trips_header_values_with_commas()
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
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("projects".to_owned()),
            base_url: Some("https://projects.internal.example/api".to_owned()),
            basic_auth: false,
            header: vec![
                "authorization=Bearer token,with,commas".to_owned(),
                "x-api-key=secret-key".to_owned(),
            ],
            timeout_ms: Some(5_000),
        }),
    }))?;

    let tty_output = run_gate_agent_in_tty_with_stdin(
        &workspace,
        &["", "", "n"],
        &[
            "config",
            "api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "projects",
        ],
    )?;

    assert!(
        tty_output.output.status.success(),
        "{:?}",
        tty_output.output
    );

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("projects"))
        .and_then(Value::as_table)
        .expect("projects api config");

    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("authorization"))
            .and_then(Value::as_str),
        Some("Bearer token,with,commas")
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("x-api-key"))
            .and_then(Value::as_str),
        Some("secret-key")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_api_basic_auth_create_persists_prompted_credentials()
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
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&[
                "billing",
                "https://billing.internal.example/api",
                "x-api-key=secondary-secret",
                "y",
                "billing-user",
                "billing-pass",
            ])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: None,
            base_url: None,
            basic_auth: false,
            header: vec![],
            timeout_ms: None,
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    assert_eq!(
        written
            .get("apis")
            .and_then(|value| value.get("billing"))
            .and_then(|value| value.get("basic_auth"))
            .and_then(|value| value.get("username"))
            .and_then(Value::as_str),
        Some("billing-user")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_basic_auth_strips_default_authorization_header()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    write_config(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example/api"
headers = { Authorization = "Bearer stale-token", x-api-key = "keep-me" }
timeout_ms = 5000
"#,
    )?;

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&["", "", "y", "billing-user", "billing-pass"])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("billing".to_owned()),
            base_url: None,
            basic_auth: false,
            header: vec![],
            timeout_ms: None,
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("billing"))
        .and_then(Value::as_table)
        .expect("billing api config");

    assert!(
        api.get("headers")
            .and_then(|value| value.get("Authorization"))
            .is_none()
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("x-api-key"))
            .and_then(Value::as_str),
        Some("keep-me")
    );
    assert_eq!(
        api.get("basic_auth")
            .and_then(|value| value.get("username"))
            .and_then(Value::as_str),
        Some("billing-user")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_basic_auth_flag_strips_default_authorization_header()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    write_config(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example/api"
headers = { Authorization = "Bearer stale-token", x-api-key = "keep-me" }
timeout_ms = 5000
"#,
    )?;

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&["", "", "billing-user", "billing-pass"])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("billing".to_owned()),
            base_url: None,
            basic_auth: true,
            header: vec![],
            timeout_ms: None,
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("billing"))
        .and_then(Value::as_table)
        .expect("billing api config");

    assert!(
        api.get("headers")
            .and_then(|value| value.get("Authorization"))
            .is_none()
    );
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("x-api-key"))
            .and_then(Value::as_str),
        Some("keep-me")
    );
    assert_eq!(
        api.get("basic_auth")
            .and_then(|value| value.get("username"))
            .and_then(Value::as_str),
        Some("billing-user")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_basic_auth_blank_password_clears_existing_password()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    write_config(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example/api"
basic_auth = { username = "billing-user", password = "billing-pass" }
headers = { x-api-key = "keep-me" }
timeout_ms = 5000
"#,
    )?;

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }

    let tty_output = run_gate_agent_in_tty_with_stdin(
        &workspace,
        &["", "", "y", "", ""],
        &[
            "config",
            "api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "billing",
        ],
    )?;

    assert!(
        tty_output.output.status.success(),
        "{:?}",
        tty_output.output
    );

    let combined = normalize_pty_output(&tty_output.transcript);
    assert!(
        combined.contains("blank clears existing password; enter password to keep or change"),
        "{combined}"
    );

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let basic_auth = written
        .get("apis")
        .and_then(|value| value.get("billing"))
        .and_then(|value| value.get("basic_auth"))
        .and_then(Value::as_table)
        .expect("billing basic_auth config");

    assert_eq!(
        basic_auth.get("username").and_then(Value::as_str),
        Some("billing-user")
    );
    assert!(basic_auth.get("password").is_none());

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_api_none_clears_existing_basic_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    write_config(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example/api"
basic_auth = { username = "billing-user", password = "billing-pass" }
headers = { x-api-key = "keep-me" }
timeout_ms = 5000
"#,
    )?;

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&["", "", "n"])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("billing".to_owned()),
            base_url: None,
            basic_auth: false,
            header: vec![],
            timeout_ms: None,
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    assert!(
        written
            .get("apis")
            .and_then(|value| value.get("billing"))
            .and_then(|value| value.get("basic_auth"))
            .is_none()
    );
    assert_eq!(
        written
            .get("apis")
            .and_then(|value| value.get("billing"))
            .and_then(|value| value.get("headers"))
            .and_then(|value| value.get("x-api-key"))
            .and_then(Value::as_str),
        Some("keep-me")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_interactive_api_header_input_clears_existing_basic_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    write_config(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example/api"
basic_auth = { username = "billing-user", password = "billing-pass" }
headers = { x-api-key = "keep-me" }
timeout_ms = 5000
"#,
    )?;

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&["", "authorization=Bearer rotated-token", "n"])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Api(ConfigApiArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("billing".to_owned()),
            base_url: None,
            basic_auth: false,
            header: vec![],
            timeout_ms: None,
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let api = written
        .get("apis")
        .and_then(|value| value.get("billing"))
        .and_then(Value::as_table)
        .expect("billing api config");

    assert!(api.get("basic_auth").is_none());
    assert_eq!(
        api.get("headers")
            .and_then(|value| value.get("authorization"))
            .and_then(Value::as_str),
        Some("Bearer rotated-token")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_client_subcommand() -> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
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
        Some("2030-01-02T00:00:00Z")
    );
    assert_api_access_rule(client.get("api_access"), "projects", 0, "get", "/api/*");
    assert_api_access_rule(client.get("api_access"), "reports", 0, "*", "*");

    Ok(())
}

#[test]
fn config_command_dispatch_runs_client_rotate_secret_subcommand()
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
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let before: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let original_token_id = before
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(|value| value.get("bearer_token_id"))
        .and_then(Value::as_str)
        .expect("existing bearer token id")
        .to_owned();

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(rotate_secret_client_args(
            config_path.clone(),
            "mobile-app".to_owned(),
        )),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    let rotated_token_id = client
        .get("bearer_token_id")
        .and_then(Value::as_str)
        .expect("rotated bearer token id");
    assert!(!rotated_token_id.is_empty());
    assert_ne!(rotated_token_id, original_token_id);
    assert_eq!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str),
        Some("2030-01-02T00:00:00Z")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_inherits_parent_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");
    let rotated_expiry = "2031-02-03";

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let before: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let original_token_id = before
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(|value| value.get("bearer_token_id"))
        .and_then(Value::as_str)
        .expect("existing bearer token id")
        .to_owned();

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(ConfigClientArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("mobile-app".to_owned()),
            bearer_token_expires_at: Some(rotated_expiry.to_owned()),
            group: None,
            api_access: vec![],
            command: Some(ConfigClientSubcommand::RotateSecret(
                ConfigRotateSecretArgs {
                    config: None,
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    log_level_explicitly_set: false,
                    name: String::new(),
                    bearer_token_expires_at: None,
                },
            )),
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    let rotated_token_id = client
        .get("bearer_token_id")
        .and_then(Value::as_str)
        .expect("rotated bearer token id");
    assert!(!rotated_token_id.is_empty());
    assert_ne!(rotated_token_id, original_token_id);
    assert_eq!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str),
        Some("2031-02-03T00:00:00Z")
    );
    assert!(
        written
            .get("clients")
            .and_then(Value::as_table)
            .is_some_and(|clients| !clients.contains_key(""))
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_rejects_parent_delete_flag()
-> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(rotate_secret_parent_args_with_forbidden_flags(
            config_path,
            true,
            None,
            &[],
        )),
    }))
    .expect_err("rotate-secret should reject parent --delete");

    assert_eq!(
        error.to_string(),
        "config client rotate-secret does not accept parent flags: --delete"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_rejects_parent_group_flag()
-> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(rotate_secret_parent_args_with_forbidden_flags(
            config_path,
            false,
            Some("ops"),
            &[],
        )),
    }))
    .expect_err("rotate-secret should reject parent --group");

    assert_eq!(
        error.to_string(),
        "config client rotate-secret does not accept parent flags: --group"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_rejects_parent_api_access_flag()
-> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(rotate_secret_parent_args_with_forbidden_flags(
            config_path,
            false,
            None,
            &["projects:*:*"],
        )),
    }))
    .expect_err("rotate-secret should reject parent --api-access");

    assert_eq!(
        error.to_string(),
        "config client rotate-secret does not accept parent flags: --api-access"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_rejects_multiple_parent_client_flags()
-> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let error = gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(rotate_secret_parent_args_with_forbidden_flags(
            config_path,
            true,
            Some("ops"),
            &["projects:*:*"],
        )),
    }))
    .expect_err("rotate-secret should reject all forbidden parent client flags");

    assert_eq!(
        error.to_string(),
        "config client rotate-secret does not accept parent flags: --delete, --group, --api-access"
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_inherits_parent_password_for_encrypted_config()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");
    let password = "top-secret-password";

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    let encrypted_bytes = encrypt_test_config(&encrypted_client_config(), password)?;
    write_config_bytes(&config_path, &encrypted_bytes)?;

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(ConfigClientArgs {
            config: Some(config_path.clone()),
            password: Some(password.to_owned()),
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("mobile-app".to_owned()),
            bearer_token_expires_at: Some("2031-02-03".to_owned()),
            group: None,
            api_access: vec![],
            command: Some(ConfigClientSubcommand::RotateSecret(
                ConfigRotateSecretArgs {
                    config: None,
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    log_level_explicitly_set: false,
                    name: String::new(),
                    bearer_token_expires_at: None,
                },
            )),
        }),
    }))?;

    let shown = gate_agent::commands::config::show(gate_agent::commands::config::ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let written: Value = shown.parse()?;

    assert_eq!(
        written
            .get("clients")
            .and_then(|value| value.get("mobile-app"))
            .and_then(|value| value.get("bearer_token_expires_at"))
            .and_then(Value::as_str),
        Some("2031-02-03T00:00:00Z")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_prefers_nested_password_over_parent()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");
    let password = "top-secret-password";

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    let encrypted_bytes = encrypt_test_config(&encrypted_client_config(), password)?;
    write_config_bytes(&config_path, &encrypted_bytes)?;

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(ConfigClientArgs {
            config: Some(config_path.clone()),
            password: Some("wrong-password".to_owned()),
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("wrong-client".to_owned()),
            bearer_token_expires_at: Some("2039-12-31".to_owned()),
            group: None,
            api_access: vec![],
            command: Some(ConfigClientSubcommand::RotateSecret(
                ConfigRotateSecretArgs {
                    config: Some(config_path.clone()),
                    password: Some(password.to_owned()),
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    log_level_explicitly_set: false,
                    name: "mobile-app".to_owned(),
                    bearer_token_expires_at: Some("2031-02-03".to_owned()),
                },
            )),
        }),
    }))?;

    let shown = gate_agent::commands::config::show(gate_agent::commands::config::ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let written: Value = shown.parse()?;

    assert_eq!(
        written
            .get("clients")
            .and_then(|value| value.get("mobile-app"))
            .and_then(|value| value.get("bearer_token_expires_at"))
            .and_then(Value::as_str),
        Some("2031-02-03T00:00:00Z")
    );
    assert!(
        written
            .get("clients")
            .and_then(Value::as_table)
            .is_some_and(|clients| !clients.contains_key("wrong-client"))
    );

    Ok(())
}

#[test]
fn config_command_dispatch_resolves_client_rotate_secret_name_interactively()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    unsafe {
        std::env::set_var("HOME", temp_dir.path().join("home"));
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::set_var(
            TEST_PROMPT_INPUTS_ENV_VAR,
            serde_json::to_string(&["mobile-app", ""])?,
        );
    }

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let before: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let original_token_id = before
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(|value| value.get("bearer_token_id"))
        .and_then(Value::as_str)
        .expect("existing bearer token id")
        .to_owned();

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(rotate_secret_client_args(
            config_path.clone(),
            String::new(),
        )),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    let rotated_token_id = client
        .get("bearer_token_id")
        .and_then(Value::as_str)
        .expect("rotated bearer token id");
    assert!(!rotated_token_id.is_empty());
    assert_ne!(rotated_token_id, original_token_id);
    assert!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some()
    );
    assert_eq!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str),
        Some("2030-01-02T00:00:00Z")
    );
    assert_api_access_rule(client.get("api_access"), "projects", 0, "get", "/api/*");
    assert_api_access_rule(client.get("api_access"), "reports", 0, "*", "*");

    Ok(())
}

#[test]
fn cli_prefers_rotate_secret_log_level_when_nested_value_is_explicit_default() {
    let cli = Cli::try_parse_from([
        "gate-agent",
        "config",
        "client",
        "--log-level",
        "debug",
        "rotate-secret",
        "--log-level",
        DEFAULT_LOG_LEVEL,
        "--name",
        "mobile-app",
    ])
    .expect("rotate-secret command parses");

    assert_eq!(cli.command().log_level(), Some(DEFAULT_LOG_LEVEL));
}

#[test]
fn command_dispatch_rotate_secret_does_not_leak_nested_log_level_explicitness() {
    let cli = Cli::try_parse_from([
        "gate-agent",
        "config",
        "client",
        "--log-level",
        "debug",
        "rotate-secret",
        "--log-level",
        DEFAULT_LOG_LEVEL,
        "--name",
        "mobile-app",
    ])
    .expect("rotate-secret command parses");

    assert_eq!(cli.command().log_level(), Some(DEFAULT_LOG_LEVEL));

    let programmatic = Command::Config(ConfigArgs {
        command: ConfigCommand::Client(ConfigClientArgs {
            config: None,
            password: None,
            log_level: "warn".to_owned(),
            delete: false,
            name: Some("mobile-app".to_owned()),
            bearer_token_expires_at: None,
            group: None,
            api_access: vec![],
            command: Some(ConfigClientSubcommand::RotateSecret(
                ConfigRotateSecretArgs {
                    config: None,
                    password: None,
                    log_level: DEFAULT_LOG_LEVEL.to_owned(),
                    log_level_explicitly_set: false,
                    name: String::new(),
                    bearer_token_expires_at: None,
                },
            )),
        }),
    });

    assert_eq!(programmatic.log_level(), Some("warn"));
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
fn cli_rejects_bearer_token_flag_for_config_client() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "client",
        "--name",
        "partner",
        "--bearer-token",
        "partner-secret",
        "--bearer-token-expires-at",
        "2030-01-02",
        "--api-access",
        "projects:get:/api/*",
    ]);

    assert_eq!(
        parsed
            .expect_err("bearer-token flag should be removed")
            .kind(),
        ErrorKind::UnknownArgument
    );
}

#[test]
fn cli_rejects_removed_api_key_flags_for_config_client() {
    assert_eq!(
        Cli::try_parse_from([
            "gate-agent",
            "config",
            "client",
            "--name",
            "partner",
            "--api-key",
            "partner-secret",
            "--api-access",
            "projects:get:/api/*",
        ])
        .expect_err("api-key flag should be removed")
        .kind(),
        ErrorKind::UnknownArgument
    );
}

#[test]
fn version_command_dispatch_runs_version_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = Vec::new();

    gate_agent::commands::version::write_version(&mut output)?;

    assert_eq!(output, [PACKAGE_VERSION, "\n"].concat().into_bytes());

    Ok(())
}

#[test]
fn version_command_binary_prints_exact_package_version() -> Result<(), Box<dyn std::error::Error>> {
    let output = AssertCommand::cargo_bin("gate-agent")?
        .args(["version"])
        .output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        [PACKAGE_VERSION, "\n"].concat()
    );
    assert_eq!(String::from_utf8(output.stderr)?, "");

    Ok(())
}

#[test]
fn version_command_binary_succeeds_without_home_or_prompt_env()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;

    let output = AssertCommand::cargo_bin("gate-agent")?
        .current_dir(&workspace)
        .env_remove("HOME")
        .env_remove(TEST_PROMPT_INPUTS_ENV_VAR)
        .env_remove(DISABLE_INTERACTIVE_ENV_VAR)
        .args(["version"])
        .output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        [PACKAGE_VERSION, "\n"].concat()
    );
    assert_eq!(String::from_utf8(output.stderr)?, "");

    Ok(())
}

#[test]
fn version_command_dispatch_skips_tracing_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");

    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", VERSION_DISPATCH_HELPER_TEST, "--nocapture"])
        .env(VERSION_DISPATCH_HELPER_ENV_VAR, "1")
        .output()?;

    assert!(
        output.status.success(),
        "helper stdout:\n{}\nhelper stderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

#[test]
fn version_command_dispatch_skips_tracing_bootstrap_helper()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(VERSION_DISPATCH_HELPER_ENV_VAR).is_none() {
        return Ok(());
    }

    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;

    unsafe {
        std::env::remove_var("HOME");
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
    }

    tracing_subscriber::fmt()
        .with_test_writer()
        .try_init()
        .expect("helper tracing subscriber should initialize");

    gate_agent::commands::run(Command::Version)?;

    Ok(())
}

#[test]
fn config_command_dispatch_client_prints_generated_bearer_token_once()
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
            "client",
            "--config",
            config_path.to_str().expect("utf-8 config path"),
            "--name",
            "mobile-app",
            "--bearer-token-expires-at",
            "2030-01-02",
            "--api-access",
            "projects:get:/api/*,reports:*:*",
        ])
        .output()?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr)?, "");

    let stdout = String::from_utf8(output.stdout)?;
    let printed_lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(printed_lines.len(), 2);
    assert_eq!(printed_lines[1], "Added client 'mobile-app'");

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
        Some("2030-01-02T00:00:00Z")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_client_rotate_secret_prints_generated_bearer_token_once()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock().lock().expect("lock env");
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join("nested/secrets.toml");

    gate_agent::commands::run(Command::Config(ConfigArgs {
        command: ConfigCommand::Client(client_args(config_path.clone(), "mobile-app")),
    }))?;

    let before: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let original_token_id = before
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(|value| value.get("bearer_token_id"))
        .and_then(Value::as_str)
        .expect("existing bearer token id")
        .to_owned();

    let output = AssertCommand::cargo_bin("gate-agent")?
        .current_dir(&workspace)
        .env("HOME", temp_dir.path().join("home"))
        .env_remove(TEST_PROMPT_INPUTS_ENV_VAR)
        .args([
            "config",
            "client",
            "rotate-secret",
            "--config",
            config_path.to_str().expect("utf-8 config path"),
            "--name",
            "mobile-app",
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

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let client = written
        .get("clients")
        .and_then(|value| value.get("mobile-app"))
        .and_then(Value::as_table)
        .expect("mobile-app client config");

    assert_ne!(token_id, original_token_id);
    assert_eq!(
        client.get("bearer_token_id").and_then(Value::as_str),
        Some(token_id)
    );
    assert_eq!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str),
        Some("2030-01-02T00:00:00Z")
    );

    Ok(())
}

#[test]
fn config_command_dispatch_runs_group_subcommand() -> Result<(), Box<dyn std::error::Error>> {
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
        command: ConfigCommand::Group(ConfigGroupArgs {
            config: Some(config_path.clone()),
            password: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            delete: false,
            name: Some("readonly".to_owned()),
            api_access: vec!["projects:get:/api/*,reports:*:*".to_owned()],
        }),
    }))?;

    let written: Value = std::fs::read_to_string(&config_path)?.parse()?;
    let group = written
        .get("groups")
        .and_then(|value| value.get("readonly"))
        .and_then(Value::as_table)
        .expect("readonly group config");

    assert_api_access_rule(group.get("api_access"), "projects", 0, "get", "/api/*");
    assert_api_access_rule(group.get("api_access"), "reports", 0, "*", "*");

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
