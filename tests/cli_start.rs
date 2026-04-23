use assert_cmd::Command;
use gate_agent::{
    cli::StartArgs,
    commands::start,
    config::{
        ConfigSource,
        app_config::{AppConfig, DEFAULT_BIND, StartConfigStdin},
    },
};
use tempfile::tempdir;

const VALID_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#;

fn write_config_file() -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>>
{
    let temp_dir = tempdir()?;
    let config_file = temp_dir.path().join(".secrets.test");
    std::fs::write(&config_file, VALID_CONFIG)?;

    Ok((temp_dir, config_file))
}

fn server_config(port: u16) -> String {
    format!(
        r#"
[server]
bind = "127.0.0.1"
port = {port}

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ projects = "read" }}

[apis.projects]
base_url = "https://projects.internal.example"
headers = {{ x-api-key = "projects-secret-value" }}
timeout_ms = 5000
"#
    )
}

fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn bind_listener_with_retry(
    bind: std::net::SocketAddr,
) -> Result<tokio::net::TcpListener, Box<dyn std::error::Error>> {
    let mut last_error = None;

    for _ in 0..5 {
        match start::bind_listener(bind).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.to_string().contains("Address already in use") => {
                last_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(error) => return Err(Box::new(error)),
        }
    }

    Err(Box::new(
        last_error.expect("retry loop should capture last bind error"),
    ))
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
        bind: Some("127.0.0.1:0".parse()?),
        config: Some(config_file.clone()),
        password: None,
        log_level: "debug".to_owned(),
    };
    let prepared = start::prepare(&args)?;
    let listener = start::bind_listener(prepared.config.bind()).await?;

    assert_eq!(
        prepared.state.startup().bind,
        args.bind.expect("bind override set")
    );
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
    let server_port = available_port()?;
    let args = StartArgs {
        bind: Some("127.0.0.1:0".parse()?),
        config: None,
        password: None,
        log_level: "debug".to_owned(),
    };
    let config = AppConfig::from_start_args_with_stdin(
        &args,
        StartConfigStdin::piped(server_config(server_port)),
    )?;
    let prepared = start::prepare_from_config(config)?;
    let listener = start::bind_listener(prepared.config.bind()).await?;

    assert_eq!(prepared.state.startup().config_source, ConfigSource::Stdin);
    assert_eq!(
        prepared.state.startup().bind,
        args.bind.expect("bind override set")
    );
    assert_eq!(
        prepared.config.bind(),
        args.bind.expect("bind override set")
    );
    assert_eq!(prepared.state.startup().log_level, "debug");
    assert_eq!(prepared.state.secrets().apis.len(), 1);
    assert!(listener.local_addr()?.port() > 0);

    Ok(())
}

#[tokio::test]
async fn start_prepare_uses_default_bind_when_cli_and_config_omit_override()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;
    let args = StartArgs {
        bind: None,
        config: Some(config_file.clone()),
        password: None,
        log_level: "debug".to_owned(),
    };
    let prepared = start::prepare(&args)?;
    let expected_bind = DEFAULT_BIND.parse()?;

    assert_eq!(prepared.config.bind(), expected_bind);
    assert_eq!(prepared.state.startup().bind, expected_bind);
    assert_eq!(prepared.state.startup().log_level, "debug");
    assert_eq!(
        prepared.state.startup().config_source,
        ConfigSource::Path(config_file)
    );

    Ok(())
}

#[tokio::test]
async fn start_prepare_uses_server_bind_when_cli_omits_override()
-> Result<(), Box<dyn std::error::Error>> {
    let port = available_port()?;
    let temp_dir = tempdir()?;
    let config_file = temp_dir.path().join(".secrets.test");
    std::fs::write(&config_file, server_config(port))?;

    let args = StartArgs {
        bind: None,
        config: Some(config_file.clone()),
        password: None,
        log_level: "debug".to_owned(),
    };
    let prepared = start::prepare(&args)?;
    let listener = bind_listener_with_retry(prepared.config.bind()).await?;

    assert_eq!(prepared.state.startup().bind.ip().to_string(), "127.0.0.1");
    assert_eq!(prepared.state.startup().bind.port(), port);
    assert_eq!(prepared.config.bind().port(), port);
    assert_eq!(
        prepared.state.startup().config_source,
        ConfigSource::Path(config_file)
    );
    assert_eq!(listener.local_addr()?.port(), port);

    Ok(())
}

#[tokio::test]
async fn start_prepare_stdin_uses_server_bind_when_cli_omits_override()
-> Result<(), Box<dyn std::error::Error>> {
    let port = available_port()?;
    let args = StartArgs {
        bind: None,
        config: None,
        password: None,
        log_level: "debug".to_owned(),
    };
    let config =
        AppConfig::from_start_args_with_stdin(&args, StartConfigStdin::piped(server_config(port)))?;
    let prepared = start::prepare_from_config(config)?;
    let listener = bind_listener_with_retry(prepared.config.bind()).await?;

    assert_eq!(prepared.state.startup().config_source, ConfigSource::Stdin);
    assert_eq!(prepared.state.startup().bind.ip().to_string(), "127.0.0.1");
    assert_eq!(prepared.state.startup().bind.port(), port);
    assert_eq!(listener.local_addr()?.port(), port);

    Ok(())
}
