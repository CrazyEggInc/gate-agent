use std::net::SocketAddr;

use gate_agent::cli::StartArgs;
use gate_agent::config::app_config::AppConfig;
use tempfile::tempdir;

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

#[test]
fn start_config_loads_runtime_flags_and_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let args = StartArgs {
        bind: "127.0.0.1:9898".parse::<SocketAddr>()?,
        secrets_file: secrets_file.clone(),
        log_level: " debug ".to_string(),
    };

    let config = AppConfig::from_start_args(&args)?;

    assert_eq!(config.bind, "127.0.0.1:9898".parse::<SocketAddr>()?);
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.secrets_file, secrets_file);
    assert_eq!(config.secrets.apis.len(), 1);

    Ok(())
}

#[test]
fn start_config_rejects_blank_log_level() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let args = StartArgs {
        bind: "127.0.0.1:8787".parse::<SocketAddr>()?,
        secrets_file,
        log_level: "   ".to_string(),
    };

    let error = AppConfig::from_start_args(&args).unwrap_err();

    assert_eq!(error.to_string(), "log level cannot be empty");

    Ok(())
}
