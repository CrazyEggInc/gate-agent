use assert_cmd::Command;
use clap::Parser;
use gate_agent::cli::Cli;

fn help_output(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?.args(args).output()?;

    assert!(output.status.success());

    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn top_level_help_lists_only_supported_commands() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["--help"])?;

    assert!(stdout.contains("start"));
    assert!(stdout.contains("Start the local proxy server"));
    assert!(stdout.contains("config"));
    assert!(stdout.contains("Create or update config entries"));
    assert!(!stdout.contains("curl"));
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
    assert!(stdout.contains("--password"));
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
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("Validate config from stdin or file"));
    assert!(stdout.contains("show"));
    assert!(stdout.contains("Print the current config contents"));
    assert!(stdout.contains("edit"));
    assert!(stdout.contains("Open the config in your editor"));
    assert!(stdout.contains("add-api"));
    assert!(stdout.contains("Add an upstream API entry"));
    assert!(stdout.contains("add-client"));
    assert!(stdout.contains("Add a client entry"));

    Ok(())
}

#[test]
fn config_init_help_uses_config_flag_without_secrets_file_placeholder()
-> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "init", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--encrypted"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("Create a new config file"));
    assert!(!stdout.contains("--secrets-file"));
    assert!(!stdout.contains("SECRETS_FILE"));

    Ok(())
}

#[test]
fn config_validate_help_uses_config_flag() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "validate", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("Validate config from stdin or file"));
    assert!(!stdout.contains("--secrets-file"));
    assert!(!stdout.contains("SECRETS_FILE"));

    Ok(())
}

#[test]
fn config_add_api_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "add-api", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--base-url"));
    assert!(stdout.contains("--auth-header"));
    assert!(stdout.contains("--auth-scheme"));
    assert!(stdout.contains("--auth-value"));
    assert!(stdout.contains("--timeout-ms"));
    assert!(stdout.contains("[default: 5000]"));

    Ok(())
}

#[test]
fn config_add_api_accepts_missing_timeout_ms() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-api",
        "--name",
        "projects",
        "--base-url",
        "https://projects.internal.example",
        "--auth-header",
        "authorization",
        "--auth-value",
        "projects-secret-value",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_client_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "add-client", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--bearer-token-expires-at"));
    assert!(stdout.contains("--group"));
    assert!(stdout.contains("--api-access"));
    assert!(stdout.contains("levels: read, write"));
    assert!(stdout.contains("Repeat the flag or comma-separate pairs"));
    assert!(!stdout.contains("--api-key"));
    assert!(!stdout.contains("--api-key-expires-at"));

    Ok(())
}

#[test]
fn config_show_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "show", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--log-level"));

    Ok(())
}

#[test]
fn config_edit_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "edit", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--log-level"));

    Ok(())
}

#[test]
fn config_add_client_accepts_missing_bearer_token_with_group() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--group",
        "partner-readonly",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_client_rejects_bearer_token_flag() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--bearer-token",
        "partner-token",
        "--bearer-token-expires-at",
        "2026-01-01T00:00:00Z",
        "--group",
        "partner-readonly",
    ]);

    assert!(parsed.is_err());
}

#[test]
fn config_add_client_accepts_repeated_api_access_flags() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--api-access",
        "projects=read,billing=write",
        "--api-access",
        "events=read",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_client_rejects_group_and_api_access_together() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--group",
        "partner-readonly",
        "--api-access",
        "projects=read",
    ]);

    assert!(parsed.is_err());
}

#[test]
fn config_add_client_rejects_missing_group_and_api_access() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "add-client", "--name", "partner"]);

    assert!(parsed.is_err());
}

#[test]
fn config_add_client_rejects_removed_api_key_flags() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-client",
        "--name",
        "partner",
        "--api-key",
        "legacy-key",
        "--group",
        "partner-readonly",
    ]);

    assert!(parsed.is_err());
}

#[test]
fn removed_curl_subcommand_is_rejected() {
    let parsed = Cli::try_parse_from(["gate-agent", "curl"]);

    assert!(parsed.is_err());
}
