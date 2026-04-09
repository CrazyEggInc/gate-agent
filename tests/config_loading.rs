use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use gate_agent::cli::StartArgs;
use gate_agent::config::app_config::AppConfig;
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "replace-me"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

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
        bind: "127.0.0.1:9898".parse::<SocketAddr>()?,
        config: Some(config_file.clone()),
        log_level: " debug ".to_string(),
    };

    let config = AppConfig::from_start_args(&args)?;

    assert_eq!(config.bind, "127.0.0.1:9898".parse::<SocketAddr>()?);
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.config_file, config_file);
    assert_eq!(config.secrets.clients.len(), 1);
    assert_eq!(config.secrets.apis.len(), 1);

    Ok(())
}

#[test]
fn start_config_rejects_blank_log_level() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = EnvVarGuard::clear(CONFIG_ENV_VAR);
    let (_temp_dir, config_file) = write_config_file("config.toml", VALID_CONFIG)?;

    let args = StartArgs {
        bind: "127.0.0.1:8787".parse::<SocketAddr>()?,
        config: Some(config_file),
        log_level: "   ".to_string(),
    };

    let error = AppConfig::from_start_args(&args).unwrap_err();

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
        bind: "127.0.0.1:8787".parse::<SocketAddr>()?,
        config: None,
        log_level: "info".to_string(),
    };

    let config = AppConfig::from_start_args(&args)?;

    assert_eq!(config.config_file, config_file);
    assert_eq!(config.secrets.clients.len(), 1);
    assert_eq!(config.secrets.apis.len(), 1);

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
        bind: "127.0.0.1:8787".parse::<SocketAddr>()?,
        config: None,
        log_level: "info".to_string(),
    };

    let config = AppConfig::from_start_args(&args)?;

    assert_eq!(config.config_file, local_config);

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
        bind: "127.0.0.1:8787".parse::<SocketAddr>()?,
        config: None,
        log_level: "info".to_string(),
    };

    let config = AppConfig::from_start_args(&args)?;

    assert_eq!(config.config_file, home_config);

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
        bind: "127.0.0.1:8787".parse::<SocketAddr>()?,
        config: None,
        log_level: "info".to_string(),
    };

    let error = AppConfig::from_start_args(&args).unwrap_err();

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
