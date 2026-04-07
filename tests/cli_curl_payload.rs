use assert_cmd::Command;
use gate_agent::{
    auth::jwt::validate_token,
    config::{
        app_config::{DEFAULT_BIND, DEFAULT_SECRETS_FILE},
        secrets::SecretsConfig,
    },
};
use tempfile::tempdir;

fn write_secrets_file()
-> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(DEFAULT_SECRETS_FILE);
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

fn output_line<'a>(stdout: &'a str, prefix: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    stdout
        .lines()
        .find(|line| line.starts_with(prefix))
        .ok_or_else(|| {
            Box::<dyn std::error::Error>::from(format!("missing output line with prefix: {prefix}"))
        })
}

fn quoted_value<'a>(line: &'a str, prefix: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    let value = line
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            Box::<dyn std::error::Error>::from(format!("invalid output line: {line}"))
        })?;

    Ok(value)
}

#[test]
fn curl_payload_help_lists_required_flags() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("gate-agent")?
        .args(["curl-payload", "--help"])
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;

    assert!(stdout.contains("--api"));
    assert!(stdout.contains("--path"));
    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--secrets-file"));

    Ok(())
}

#[test]
fn curl_payload_uses_explicit_bind_and_secrets_file() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, secrets_file) = write_secrets_file()?;
    let output = Command::cargo_bin("gate-agent")?
        .current_dir(temp_dir.path())
        .args([
            "curl-payload",
            "--bind",
            "127.0.0.1:9999",
            "--secrets-file",
            secrets_file.to_str().expect("secrets path should be utf-8"),
            "--api",
            "projects",
            "--path",
            "/v1/projects/1/tasks",
        ])
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    let url = quoted_value(output_line(&stdout, "url = \"")?, "url = \"")?;

    assert_eq!(url, "http://127.0.0.1:9999/proxy/v1/projects/1/tasks");

    Ok(())
}

#[test]
fn curl_payload_emits_local_proxy_url_and_signed_bearer_token()
-> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, secrets_file) = write_secrets_file()?;
    let output = Command::cargo_bin("gate-agent")?
        .current_dir(temp_dir.path())
        .args([
            "curl-payload",
            "--api",
            "projects",
            "--path",
            "/v1/projects/1/tasks",
        ])
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    let url = quoted_value(output_line(&stdout, "url = \"")?, "url = \"")?;
    let header = quoted_value(output_line(&stdout, "header = \"")?, "header = \"")?;
    let token = header
        .strip_prefix("Authorization: Bearer ")
        .ok_or_else(|| format!("missing bearer token header: {header}"))?;
    let secrets = SecretsConfig::load_from_file(&secrets_file)?;
    let claims = validate_token(token, &secrets)?;

    assert_eq!(
        url,
        &format!("http://{DEFAULT_BIND}/proxy/v1/projects/1/tasks")
    );
    assert_eq!(claims.api, "projects");
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");
    assert!(claims.exp > claims.iat);

    Ok(())
}

#[test]
fn curl_payload_rejects_unknown_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, _secrets_file) = write_secrets_file()?;
    let output = Command::cargo_bin("gate-agent")?
        .current_dir(temp_dir.path())
        .args([
            "curl-payload",
            "--api",
            "billing",
            "--path",
            "/v1/projects/1/tasks",
        ])
        .output()?;

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr)?;

    assert!(stderr.contains("api is not allowed: billing"));

    Ok(())
}
