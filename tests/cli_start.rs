use assert_cmd::Command;
use gate_agent::{
    cli::StartArgs,
    commands::start,
    config::{
        ConfigSource,
        app_config::{AppConfig, StartConfigStdin},
    },
};
use tempfile::tempdir;

const VALID_CONFIG: &str = r#"
[auth]
issuer = "gate-agent"
audience = "gate-agent-clients"
signing_secret = "replace-me-with-a-long-enough-secret"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

fn write_config_file() -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>>
{
    let temp_dir = tempdir()?;
    let config_file = temp_dir.path().join(".secrets.test");
    std::fs::write(&config_file, VALID_CONFIG)?;

    Ok((temp_dir, config_file))
}

#[test]
fn start_help_lists_runtime_flags() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?
        .args(["start", "--help"])
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    assert!(stdout.contains("Start the local proxy server"));
    assert!(stdout.contains("Bind address for the local listener"));
    assert!(stdout.contains("Path to the config file"));
    assert!(stdout.contains("Log level for server output"));
    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(!stdout.contains("--secrets-file"));

    Ok(())
}

#[test]
fn start_invalid_log_level_emits_human_readable_error_on_stderr()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?
        .args(["start", "--log-level", "trace"])
        .output()?;

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr)?;

    assert!(
        stderr.contains("invalid log level 'trace'"),
        "expected invalid log level text in stderr: {stderr}"
    );
    assert!(
        !stderr.contains("internal error: internal error:"),
        "error output should not be double-prefixed: {stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn start_prepare_loads_runtime_state_and_binds_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;
    let args = StartArgs {
        bind: "127.0.0.1:0".parse()?,
        config: Some(config_file.clone()),
        password: None,
        log_level: "debug".to_owned(),
    };
    let prepared = start::prepare(&args)?;
    let listener = start::bind_listener(prepared.config.bind()).await?;

    assert_eq!(prepared.state.startup().bind, args.bind);
    assert_eq!(prepared.state.startup().log_level, "debug");
    assert_eq!(
        prepared.state.startup().config_source,
        ConfigSource::Path(config_file)
    );
    assert_eq!(prepared.state.secrets().apis.len(), 1);
    assert!(listener.local_addr()?.port() > 0);

    Ok(())
}

#[tokio::test]
async fn start_prepare_accepts_stdin_backed_config_source() -> Result<(), Box<dyn std::error::Error>>
{
    let args = StartArgs {
        bind: "127.0.0.1:0".parse()?,
        config: None,
        password: None,
        log_level: "debug".to_owned(),
    };
    let config =
        AppConfig::from_start_args_with_stdin(&args, StartConfigStdin::piped(VALID_CONFIG))?;
    let prepared = start::prepare_from_config(config)?;
    let listener = start::bind_listener(prepared.config.bind()).await?;

    assert_eq!(prepared.state.startup().config_source, ConfigSource::Stdin);
    assert_eq!(prepared.state.startup().bind, args.bind);
    assert_eq!(prepared.state.startup().log_level, "debug");
    assert_eq!(prepared.state.secrets().apis.len(), 1);
    assert!(listener.local_addr()?.port() > 0);

    Ok(())
}
