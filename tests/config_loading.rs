use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use gate_agent::cli::StartArgs;
use gate_agent::config::{
    ConfigSource,
    app_config::{AppConfig, DEFAULT_BIND, StartConfigStdin},
};
use tempfile::tempdir;

const CONFIG_ENV_VAR: &str = "GATE_AGENT_CONFIG";

fn env_var_lock() -> &'static Mutex<()> {
    static ENV_VAR_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    ENV_VAR_LOCK.get_or_init(|| Mutex::new(()))
}

fn write_config_file(
    file_name: &str,
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_file = temp_dir.path().join(file_name);
    std::fs::write(&config_file, contents)?;
    Ok((temp_dir, config_file))
}

fn write_config_at(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(path.parent().expect("config file parent"))?;
    std::fs::write(path, contents)?;
    Ok(())
}

const VALID_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

const SERVER_CONFIG: &str = r#"
[server]
bind = "127.0.0.1"
port = 9898

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

const STDIN_CONFIG: &str = r#"
[server]
bind = "127.0.0.1"
port = 9393

[clients.default]
bearer_token_id = "stdin-default"
bearer_token_hash = "5fd8d7dc05bd649e11e71f60b6bd897ea7d35857c133ccfc74a06537e2ec4f38"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://stdin-projects.internal.example"
auth_header = "x-api-key"
auth_value = "stdin-projects-secret-value"
timeout_ms = 7000
"#;

const CONFIG_WITH_API_METADATA: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
description = "Project API"
docs_url = "https://docs.internal.example/projects"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

fn load_config(args: &StartArgs) -> Result<AppConfig, gate_agent::config::ConfigError> {
    AppConfig::from_start_args_with_stdin(args, StartConfigStdin::terminal())
}

fn load_config_with_stdin(
    args: &StartArgs,
    stdin: impl Into<Vec<u8>>,
) -> Result<AppConfig, gate_agent::config::ConfigError> {
    AppConfig::from_start_args_with_stdin(args, StartConfigStdin::piped(stdin))
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    fn clear(key: &'static str) -> Self {
        let lock = env_var_lock()
            .lock()
            .expect("config env var mutex poisoned");
        let previous = std::env::var_os(key);
        unsafe {
            std::env::remove_var(key);
        }

        Self {
            key,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe {
                std::env::set_var(self.key, value);
            },
            None => unsafe {
                std::env::remove_var(self.key);
            },
        }
    }
}

struct ProcessEnvGuard {
    original_dir: PathBuf,
    original_home: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl ProcessEnvGuard {
    fn enter(
        current_dir: &Path,
        home_dir: Option<&Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let lock = env_var_lock()
            .lock()
            .expect("config env var mutex poisoned");
        let original_dir = std::env::current_dir()?;
        let original_home = std::env::var_os("HOME");

        std::env::set_current_dir(current_dir)?;

        unsafe {
            std::env::remove_var(CONFIG_ENV_VAR);

            match home_dir {
                Some(path) => std::env::set_var("HOME", path),
                None => std::env::remove_var("HOME"),
            }
        }

        Ok(Self {
            original_dir,
            original_home,
            _lock: lock,
        })
    }
}

impl Drop for ProcessEnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_dir);

        unsafe {
            match &self.original_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }

            std::env::remove_var(CONFIG_ENV_VAR);
        }
    }
}

#[test]
fn start_config_loads_runtime_flags_and_resolved_config_path()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", VALID_CONFIG)?;

    let args = StartArgs {
        bind: Some("127.0.0.1:9898".parse::<SocketAddr>()?),
        config: Some(config_file.clone()),
        password: None,
        log_level: " debug ".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.bind(), "127.0.0.1:9898".parse::<SocketAddr>()?);
    assert_eq!(config.log_level(), "debug");
    assert_eq!(config.config_source(), &ConfigSource::Path(config_file));
    assert_eq!(config.secrets().clients.len(), 1);
    assert_eq!(config.secrets().apis.len(), 1);

    Ok(())
}

#[test]
fn start_config_uses_default_bind_when_cli_omits_bind() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", VALID_CONFIG)?;

    let args = StartArgs {
        bind: None,
        config: Some(config_file),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.bind(), DEFAULT_BIND.parse::<SocketAddr>()?);

    Ok(())
}

#[test]
fn start_config_uses_server_section_when_cli_omits_bind() -> Result<(), Box<dyn std::error::Error>>
{
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", SERVER_CONFIG)?;

    let args = StartArgs {
        bind: None,
        config: Some(config_file),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.bind(), "127.0.0.1:9898".parse::<SocketAddr>()?);

    Ok(())
}

#[test]
fn start_config_cli_bind_overrides_server_section() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", SERVER_CONFIG)?;

    let args = StartArgs {
        bind: Some("127.0.0.1:9899".parse::<SocketAddr>()?),
        config: Some(config_file),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.bind(), "127.0.0.1:9899".parse::<SocketAddr>()?);

    Ok(())
}

#[test]
fn start_config_exposes_stable_config_source_accessors() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", VALID_CONFIG)?;

    let args = StartArgs {
        bind: Some("127.0.0.1:9898".parse::<SocketAddr>()?),
        config: Some(config_file.clone()),
        password: None,
        log_level: "debug".to_string(),
    };

    let file_config = load_config(&args)?;

    assert_eq!(file_config.bind(), "127.0.0.1:9898".parse::<SocketAddr>()?);
    assert_eq!(file_config.log_level(), "debug");
    assert_eq!(file_config.secrets().clients.len(), 1);
    assert_eq!(
        file_config.config_source(),
        &ConfigSource::Path(config_file.clone())
    );
    assert_eq!(file_config.config_path(), Some(config_file.as_path()));

    let stdin_config = load_config_with_stdin(&args, STDIN_CONFIG)?;

    assert_eq!(stdin_config.config_source(), &ConfigSource::Stdin);
    assert_eq!(stdin_config.config_path(), None);

    Ok(())
}

#[test]
fn start_config_rejects_blank_log_level() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("config.toml", VALID_CONFIG)?;

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: Some(config_file),
        password: None,
        log_level: "   ".to_string(),
    };

    let error = load_config(&args).unwrap_err();

    assert_eq!(error.to_string(), "log level cannot be empty");

    Ok(())
}

#[test]
fn start_config_uses_env_resolved_path_when_cli_omits_config_override()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-secrets.toml", VALID_CONFIG)?;

    unsafe {
        std::env::set_var(CONFIG_ENV_VAR, &config_file);
    }

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.config_source(), &ConfigSource::Path(config_file));
    assert_eq!(config.secrets().clients.len(), 1);
    assert_eq!(config.secrets().apis.len(), 1);

    Ok(())
}

#[test]
fn start_config_loads_optional_api_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) =
        write_config_file("resolved-config.toml", CONFIG_WITH_API_METADATA)?;

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: Some(config_file),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;
    let api = config.secrets().apis.get("projects").expect("projects api");

    assert_eq!(api.description.as_deref(), Some("Project API"));
    assert_eq!(
        api.docs_url.as_ref().map(url::Url::as_str),
        Some("https://docs.internal.example/projects")
    );

    Ok(())
}

#[test]
fn start_config_uses_local_default_before_home_fallback() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = tempdir()?;
    let workspace_dir = temp_dir.path().join("workspace");
    let home_dir = temp_dir.path().join("home");
    let local_config = workspace_dir.join(".secrets");
    let home_config = home_dir.join(".config/gate-agent/secrets");

    std::fs::create_dir_all(&workspace_dir)?;
    write_config_at(&local_config, VALID_CONFIG)?;
    write_config_at(&home_config, VALID_CONFIG)?;

    let _process_env = ProcessEnvGuard::enter(&workspace_dir, Some(&home_dir))?;
    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.config_source(), &ConfigSource::Path(local_config));

    Ok(())
}

#[test]
fn start_config_uses_home_fallback_when_local_default_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let workspace_dir = temp_dir.path().join("workspace");
    let home_dir = temp_dir.path().join("home");
    let home_config = home_dir.join(".config/gate-agent/secrets");

    std::fs::create_dir_all(&workspace_dir)?;
    write_config_at(&home_config, VALID_CONFIG)?;

    let _process_env = ProcessEnvGuard::enter(&workspace_dir, Some(&home_dir))?;
    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.config_source(), &ConfigSource::Path(home_config));

    Ok(())
}

#[test]
fn start_config_fails_fast_when_no_resolved_config_exists() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = tempdir()?;
    let workspace_dir = temp_dir.path().join("workspace");
    let home_dir = temp_dir.path().join("home");

    std::fs::create_dir_all(&workspace_dir)?;
    std::fs::create_dir_all(&home_dir)?;

    let _process_env = ProcessEnvGuard::enter(&workspace_dir, Some(&home_dir))?;
    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let error = load_config(&args).unwrap_err();

    assert_eq!(
        error.to_string(),
        format!(
            "no config file found; tried '{}' and '{}'",
            workspace_dir.join(".secrets").display(),
            home_dir.join(".config/gate-agent/secrets").display(),
        )
    );

    Ok(())
}

#[test]
fn start_config_prefers_stdin_over_cli_config_path() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", VALID_CONFIG)?;
    let cli_bind = "127.0.0.1:8787".parse::<SocketAddr>()?;

    let args = StartArgs {
        bind: Some(cli_bind),
        config: Some(config_file),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config_with_stdin(&args, STDIN_CONFIG)?;

    assert_eq!(config.config_source(), &ConfigSource::Stdin);
    assert_eq!(config.bind(), cli_bind);
    assert_eq!(
        config.secrets().clients["default"].bearer_token_id,
        "stdin-default"
    );

    Ok(())
}

#[test]
fn start_config_prefers_stdin_over_env_config_path() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-secrets.toml", VALID_CONFIG)?;

    unsafe {
        std::env::set_var(CONFIG_ENV_VAR, &config_file);
    }

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config_with_stdin(&args, STDIN_CONFIG)?;

    assert_eq!(config.config_source(), &ConfigSource::Stdin);
    assert_eq!(
        config.secrets().clients["default"].bearer_token_id,
        "stdin-default"
    );

    Ok(())
}

#[test]
fn start_config_ignores_empty_piped_stdin_and_falls_back_to_file()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("resolved-config.toml", VALID_CONFIG)?;

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: Some(config_file.clone()),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config_with_stdin(&args, "  \n\t  ")?;

    assert_eq!(config.config_source(), &ConfigSource::Path(config_file));
    assert_eq!(
        config.secrets().clients["default"].bearer_token_id,
        "default"
    );

    Ok(())
}

#[test]
fn start_config_reports_stdin_as_chosen_source() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config_with_stdin(&args, STDIN_CONFIG)?;

    assert_eq!(config.config_source(), &ConfigSource::Stdin);

    Ok(())
}

#[test]
fn start_config_stdin_uses_server_section_when_cli_omits_bind()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);

    let args = StartArgs {
        bind: None,
        config: None,
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config_with_stdin(&args, STDIN_CONFIG)?;

    assert_eq!(config.bind(), "127.0.0.1:9393".parse::<SocketAddr>()?);

    Ok(())
}

#[test]
fn start_config_cli_path_still_beats_env_when_stdin_is_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_cli_dir, cli_config) = write_config_file("cli-config.toml", VALID_CONFIG)?;
    let (_env_dir, env_config) = write_config_file("env-config.toml", STDIN_CONFIG)?;

    unsafe {
        std::env::set_var(CONFIG_ENV_VAR, &env_config);
    }

    let args = StartArgs {
        bind: Some("127.0.0.1:8787".parse::<SocketAddr>()?),
        config: Some(cli_config.clone()),
        password: None,
        log_level: "info".to_string(),
    };

    let config = load_config(&args)?;

    assert_eq!(config.config_source(), &ConfigSource::Path(cli_config));
    assert_eq!(
        config.secrets().clients["default"].bearer_token_id,
        "default"
    );

    Ok(())
}
