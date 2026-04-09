use assert_cmd::Command;
use clap::Parser;
use gate_agent::cli::Cli;

fn help_output(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?.args(args).output()?;

    assert!(output.status.success());

    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn top_level_help_lists_config_and_curl() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["--help"])?;

    assert!(stdout.contains("start"));
    assert!(stdout.contains("Start the local proxy server"));
    assert!(stdout.contains("config"));
    assert!(stdout.contains("Create or update config entries"));
    assert!(stdout.contains("curl"));
    assert!(stdout.contains("Print a curl command for the proxy"));
    assert!(!stdout.contains("\n  help  "));

    Ok(())
}

#[test]
fn help_subcommand_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?.arg("help").output()?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(stderr.contains("unrecognized subcommand 'help'"));
    assert!(stderr.contains("For more information, try '--help'."));

    Ok(())
}

#[test]
fn start_help_uses_config_flag() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["start", "--help"])?;

    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(!stdout.contains("--secrets-file"));
    assert!(!stdout.contains("SECRETS_FILE"));

    Ok(())
}

#[test]
fn config_help_lists_expected_subcommands() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "--help"])?;

    assert!(stdout.contains("init"));
    assert!(stdout.contains("Create a new config file"));
    assert!(stdout.contains("add-api"));
    assert!(stdout.contains("Add an upstream API entry"));
    assert!(stdout.contains("add-client"));
    assert!(stdout.contains("Add a client entry"));

    Ok(())
}

#[test]
fn curl_help_lists_auth_and_proxy_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["curl", "--help"])?;

    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--client"));
    assert!(stdout.contains("--auth"));
    assert!(stdout.contains("--proxy"));
    assert!(stdout.contains("--jwt"));
    assert!(stdout.contains("--api"));
    assert!(stdout.contains("--path"));
    assert!(!stdout.contains("--secrets-file"));

    Ok(())
}

#[test]
fn config_init_help_uses_config_flag_without_secrets_file_placeholder()
-> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "init", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("Create a new config file"));
    assert!(!stdout.contains("--secrets-file"));
    assert!(!stdout.contains("SECRETS_FILE"));

    Ok(())
}

#[test]
fn config_add_api_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "add-api", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--base-url"));
    assert!(stdout.contains("--auth-header"));
    assert!(stdout.contains("--auth-scheme"));
    assert!(stdout.contains("--auth-value"));
    assert!(stdout.contains("--timeout-ms"));

    Ok(())
}

#[test]
fn config_add_client_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "add-client", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--api-key"));
    assert!(stdout.contains("--api-key-expires-at"));
    assert!(stdout.contains("--allowed-api"));

    Ok(())
}

#[test]
fn config_add_client_accepts_missing_api_key() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--allowed-api",
        "projects",
        "--allowed-api",
        "billing",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_client_rejects_duplicate_api_key_expires_at() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--api-key-expires-at",
        "2026-01-01T00:00:00Z",
        "--api-key-expires-at",
        "2026-02-01T00:00:00Z",
        "--allowed-api",
        "projects",
    ]);

    assert!(parsed.is_err());
}

#[test]
fn curl_accepts_auth_mode_without_proxy_flags() {
    let parsed = Cli::try_parse_from(["gate-agent", "curl", "--auth"]);

    assert!(parsed.is_ok());
}

#[test]
fn curl_accepts_proxy_mode_with_jwt_api_and_path() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "curl",
        "--jwt",
        "test-token",
        "--api",
        "projects",
        "--path",
        "/v1/projects/1/tasks",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn curl_accepts_explicit_proxy_mode() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "curl",
        "--proxy",
        "--jwt",
        "test-token",
        "--api",
        "projects",
        "--path",
        "/v1/projects/1/tasks",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn curl_rejects_auth_and_proxy_together() {
    let parsed = Cli::try_parse_from(["gate-agent", "curl", "--auth", "--proxy"]);

    assert!(parsed.is_err());
}
