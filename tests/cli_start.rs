use assert_cmd::Command;
use gate_agent::{cli::StartArgs, commands::start};
use tempfile::tempdir;

fn write_secrets_file()
-> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets.test");
    std::fs::write(
        &secrets_file,
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

    Ok((temp_dir, secrets_file))
}

#[test]
fn start_help_lists_runtime_flags() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?
        .args(["start", "--help"])
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--secrets-file"));
    assert!(stdout.contains("--log-level"));

    Ok(())
}

#[tokio::test]
async fn start_prepare_loads_runtime_state_and_binds_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file()?;
    let args = StartArgs {
        bind: "127.0.0.1:0".parse()?,
        secrets_file: secrets_file.clone(),
        log_level: "debug".to_owned(),
    };
    let prepared = start::prepare(&args)?;
    let listener = start::bind_listener(prepared.config.bind).await?;

    assert_eq!(prepared.state.startup().bind, args.bind);
    assert_eq!(prepared.state.startup().log_level, "debug");
    assert_eq!(prepared.state.startup().secrets_file, secrets_file);
    assert_eq!(prepared.state.secrets().apis.len(), 1);
    assert!(listener.local_addr()?.port() > 0);

    Ok(())
}
