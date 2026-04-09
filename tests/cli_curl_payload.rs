use assert_cmd::Command;
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use gate_agent::{cli::CurlArgs, commands::curl::render};
use tempfile::tempdir;

fn write_config_file() -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>>
{
    let temp_dir = tempdir()?;
    let config_file = temp_dir.path().join(".secrets.test");
    std::fs::write(
        &config_file,
        r#"
[auth]
issuer = "gate-agent"
audience = "gate-agent-clients"
signing_secret = "replace-me-with-a-long-enough-secret"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[clients.partner]
api_key = "partner-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
api_access = {}

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    Ok((temp_dir, config_file))
}

fn config_contents(client_api_key: &str, api_slug: &str) -> String {
    format!(
        r#"
[auth]
issuer = "gate-agent"
audience = "gate-agent-clients"
signing_secret = "replace-me-with-a-long-enough-secret"

[clients.default]
api_key = "{client_api_key}"
api_key_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ {api_slug} = "read" }}

[apis.{api_slug}]
base_url = "https://{api_slug}.internal.example"
auth_header = "x-api-key"
auth_value = "{api_slug}-secret-value"
timeout_ms = 5000
"#
    )
}

#[test]
fn curl_auth_mode_renders_exchange_request_for_default_client()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let payload = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "default".to_owned(),
        auth: true,
        proxy: false,
        jwt: None,
        api: None,
        path: None,
    })?;

    assert!(payload.contains("url = \"http://127.0.0.1:8787/auth/exchange\""));
    assert!(payload.contains("request = \"POST\""));
    assert!(payload.contains("header = \"x-api-key: default-client-key\""));
    assert!(payload.contains("header = \"content-type: application/json\""));
    assert!(payload.contains("data = \"{\\\"apis\\\":{\\\"projects\\\":\\\"read\\\"}}\""));

    Ok(())
}

#[test]
fn curl_proxy_mode_renders_proxy_request() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let payload = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "default".to_owned(),
        auth: false,
        proxy: false,
        jwt: Some("jwt-token-value".to_owned()),
        api: Some("projects".to_owned()),
        path: Some("/v1/projects/1/tasks".to_owned()),
    })?;

    assert!(payload.contains("url = \"http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks\""));
    assert!(payload.contains("header = \"Authorization: Bearer jwt-token-value\""));

    Ok(())
}

#[test]
fn curl_auth_mode_rejects_proxy_flags() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let error = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "default".to_owned(),
        auth: true,
        proxy: true,
        jwt: None,
        api: Some("projects".to_owned()),
        path: None,
    })
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "--auth cannot be combined with --proxy, --jwt, --api, or --path"
    );

    Ok(())
}

#[test]
fn curl_proxy_mode_requires_path() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let error = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "default".to_owned(),
        auth: false,
        proxy: false,
        jwt: Some("jwt-token-value".to_owned()),
        api: Some("projects".to_owned()),
        path: None,
    })
    .unwrap_err();

    assert_eq!(error.to_string(), "--path is required when using --jwt");

    Ok(())
}

#[test]
fn curl_auth_mode_rejects_client_without_api_access() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let error = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "partner".to_owned(),
        auth: true,
        proxy: false,
        jwt: None,
        api: None,
        path: None,
    })
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "client 'partner' has no api_access configured"
    );

    Ok(())
}

#[test]
fn curl_explicit_proxy_mode_renders_proxy_request() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let payload = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "default".to_owned(),
        auth: false,
        proxy: true,
        jwt: Some("jwt-token-value".to_owned()),
        api: Some("projects".to_owned()),
        path: Some("/v1/projects/1/tasks".to_owned()),
    })?;

    assert!(payload.contains("url = \"http://127.0.0.1:8787/proxy/projects/v1/projects/1/tasks\""));
    assert!(payload.contains("header = \"Authorization: Bearer jwt-token-value\""));

    Ok(())
}

#[test]
fn curl_proxy_mode_requires_jwt() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let error = render(CurlArgs {
        bind: "127.0.0.1:8787".parse()?,
        config: Some(config_file),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        client: "default".to_owned(),
        auth: false,
        proxy: true,
        jwt: None,
        api: Some("projects".to_owned()),
        path: Some("/v1/projects/1/tasks".to_owned()),
    })
    .unwrap_err();

    assert_eq!(error.to_string(), "--jwt is required in proxy mode");

    Ok(())
}

#[test]
fn curl_auth_mode_renders_exchange_request_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?
        .args(["curl", "--auth", "--bind", "127.0.0.1:8787"])
        .write_stdin(config_contents("stdin-client-key", "stdin-projects"))
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    assert!(stdout.contains("url = \"http://127.0.0.1:8787/auth/exchange\""));
    assert!(stdout.contains("header = \"x-api-key: stdin-client-key\""));
    assert!(stdout.contains("data = \"{\\\"apis\\\":{\\\"stdin-projects\\\":\\\"read\\\"}}\""));

    Ok(())
}

#[test]
fn curl_proxy_mode_renders_proxy_request_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?
        .args([
            "curl",
            "--bind",
            "127.0.0.1:8787",
            "--jwt",
            "jwt-token-value",
            "--api",
            "stdin-projects",
            "--path",
            "/v1/projects/1/tasks",
        ])
        .write_stdin(config_contents("stdin-client-key", "stdin-projects"))
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    assert!(
        stdout.contains("url = \"http://127.0.0.1:8787/proxy/stdin-projects/v1/projects/1/tasks\"")
    );
    assert!(stdout.contains("header = \"Authorization: Bearer jwt-token-value\""));

    Ok(())
}

#[test]
fn curl_stdin_beats_explicit_config_path() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_config_file()?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "curl",
            "--auth",
            "--bind",
            "127.0.0.1:8787",
            "--config",
            config_file.to_str().expect("utf-8 config path"),
        ])
        .write_stdin(config_contents("stdin-client-key", "stdin-projects"))
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    assert!(stdout.contains("header = \"x-api-key: stdin-client-key\""));
    assert!(stdout.contains("data = \"{\\\"apis\\\":{\\\"stdin-projects\\\":\\\"read\\\"}}\""));
    assert!(!stdout.contains("default-client-key"));
    assert!(!stdout.contains("data = \"{\\\"apis\\\":{\\\"projects\\\":\\\"read\\\"}}\""));

    Ok(())
}
