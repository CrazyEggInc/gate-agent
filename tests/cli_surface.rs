use assert_cmd::Command;
use clap::Parser;
use gate_agent::cli::{Cli, Command as CliCommand, ConfigCommand};

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
    assert!(stdout.contains("version"));
    assert!(stdout.contains("Print build version"));
    assert!(!stdout.contains("curl"));
    assert!(!stdout.contains("\n  help  "));

    Ok(())
}

#[test]
fn version_help_shows_command_local_help() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["version", "--help"])?;

    assert!(stdout.contains("Print build version"));
    assert!(!stdout.contains("--log-level"));
    assert!(!stdout.contains("start"));
    assert!(!stdout.contains("config"));

    Ok(())
}

#[test]
fn version_parses_to_version_command() {
    let parsed = Cli::try_parse_from(["gate-agent", "version"]).expect("parses");

    match parsed.command() {
        CliCommand::Version => {}
        other => panic!("expected version command, got {other:?}"),
    }
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
    assert!(!stdout.contains("[default: 127.0.0.1:8787]"));
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
    assert!(stdout.contains("add-group"));
    assert!(stdout.contains("Add a group entry"));
    assert!(stdout.contains("add-client"));
    assert!(stdout.contains("Add a client entry"));
    assert!(stdout.contains("rotate-client-secret"));
    assert!(stdout.contains("Rotate an existing client bearer token"));

    Ok(())
}

#[test]
fn config_rotate_client_secret_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>>
{
    let stdout = help_output(&["config", "rotate-client-secret", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--bearer-token-expires-at"));
    assert!(!stdout.contains("--group"));
    assert!(!stdout.contains("--api-access"));

    Ok(())
}

#[test]
fn config_rotate_client_secret_accepts_missing_name_for_interactive_flow() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "rotate-client-secret"]);

    assert!(parsed.is_ok());
}

#[test]
fn config_rotate_client_secret_parses_to_expected_variant() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "rotate-client-secret",
        "--name",
        "partner",
    ])
    .expect("parses");

    match parsed.command() {
        CliCommand::Config(args) => match &args.command {
            ConfigCommand::RotateClientSecret(args) => {
                assert_eq!(args.name, "partner");
                assert_eq!(args.bearer_token_expires_at, None);
            }
            other => panic!("expected rotate-client-secret variant, got {other:?}"),
        },
        other => panic!("expected config command, got {other:?}"),
    }
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
fn config_add_group_help_lists_expected_flags() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = help_output(&["config", "add-group", "--help"])?;

    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("--name"));
    assert!(stdout.contains("--api-access"));
    assert!(!stdout.contains("--api-key"));
    assert!(!stdout.contains("--api-key-expires-at"));
    assert!(!stdout.contains("--group"));

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
    assert!(stdout.contains("--auth-value"));
    assert!(stdout.contains("--timeout-ms"));
    assert!(stdout.contains("[default: 5000]"));
    assert!(!stdout.contains("--auth-scheme"));

    Ok(())
}

#[test]
fn config_add_api_accepts_missing_timeout_ms_and_auth_fields() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-api",
        "--name",
        "projects",
        "--base-url",
        "https://projects.internal.example",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_api_accepts_promptable_omissions_for_interactive_flow() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "add-api"]);

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
fn config_add_client_accepts_missing_name_and_access_for_interactive_flow() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "add-client"]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_group_parses_to_add_group() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "add-group"]).expect("parses");

    match parsed.command() {
        CliCommand::Config(args) => match &args.command {
            ConfigCommand::AddGroup(_) => {}
            other => panic!("expected add-group variant, got {other:?}"),
        },
        other => panic!("expected config command, got {other:?}"),
    }
}

#[test]
fn config_add_group_accepts_repeated_api_access_flags() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-group",
        "--name",
        "readonly",
        "--api-access",
        "projects=read,billing=write",
        "--api-access",
        "events=read",
    ]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_group_accepts_missing_name_and_access_for_interactive_flow() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "add-group"]);

    assert!(parsed.is_ok());
}

#[test]
fn config_add_group_rejects_client_only_flags() {
    let parsed = Cli::try_parse_from([
        "gate-agent",
        "config",
        "add-group",
        "--name",
        "readonly",
        "--api-key",
        "client-secret",
    ]);

    assert!(parsed.is_err());
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

#[test]
fn config_init_tracks_explicit_encrypted_flag() {
    let omitted = Cli::try_parse_from(["gate-agent", "config", "init"]).expect("parses");
    let omitted_explicit = match omitted.command() {
        CliCommand::Config(args) => match &args.command {
            ConfigCommand::Init(args) => args.encrypted_was_explicitly_set(),
            other => panic!("expected init variant, got {other:?}"),
        },
        other => panic!("expected config command, got {other:?}"),
    };
    assert!(!omitted_explicit);

    let explicit =
        Cli::try_parse_from(["gate-agent", "config", "init", "--encrypted"]).expect("parses");
    let explicit_flag = match explicit.command() {
        CliCommand::Config(args) => match &args.command {
            ConfigCommand::Init(args) => args.encrypted_was_explicitly_set(),
            other => panic!("expected init variant, got {other:?}"),
        },
        other => panic!("expected config command, got {other:?}"),
    };
    assert!(explicit_flag);
}

#[test]
fn start_tracks_explicit_bind_flag() {
    let omitted = Cli::try_parse_from(["gate-agent", "start"]).expect("parses");
    let omitted_bind = match omitted.command() {
        CliCommand::Start(args) => args.bind,
        other => panic!("expected start command, got {other:?}"),
    };
    assert_eq!(omitted_bind, None);

    let explicit =
        Cli::try_parse_from(["gate-agent", "start", "--bind", "127.0.0.1:9898"]).expect("parses");
    let explicit_bind = match explicit.command() {
        CliCommand::Start(args) => args.bind,
        other => panic!("expected start command, got {other:?}"),
    };
    assert_eq!(
        explicit_bind,
        Some("127.0.0.1:9898".parse().expect("socket addr parses"))
    );
}

#[test]
fn config_init_accepts_promptable_omissions_for_interactive_flow() {
    let parsed = Cli::try_parse_from(["gate-agent", "config", "init"]);

    assert!(parsed.is_ok());
}
