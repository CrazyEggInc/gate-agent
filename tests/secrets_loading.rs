use secrecy::ExposeSecret;

use gate_agent::config::secrets::{JwtAlgorithm, SecretsConfig};
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
fn secrets_config_loads_validated_structs() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(config.jwt.algorithm, JwtAlgorithm::Hs256);
    assert_eq!(config.jwt.issuer, "gate-agent-dev");
    assert_eq!(config.jwt.audience, "gate-agent-clients");
    assert_eq!(config.jwt.shared_secret.expose_secret(), "replace-me");
    assert_eq!(api.slug, "billing");
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");
    assert_eq!(api.auth_header.as_str(), "authorization");
    assert_eq!(api.auth_scheme.as_deref(), Some("Bearer"));
    assert_eq!(api.auth_value.expose_secret(), "billing-secret-token");
    assert_eq!(api.timeout_ms, 5000);

    Ok(())
}

#[test]
fn secrets_config_requires_at_least_one_api() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis]
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(error.to_string(), "at least one [apis.*] entry is required");

    Ok(())
}

#[test]
fn secrets_config_rejects_non_lowercase_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.Projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(error.to_string(), "api slug 'Projects' must be lowercase");

    Ok(())
}

#[test]
fn secrets_config_rejects_non_hs256_algorithm() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "RS256"
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

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "jwt.algorithm must be HS256, got 'RS256'"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
unexpected = "nope"

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

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unknown field `unexpected`, expected `jwt` or `apis`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_api_fields() -> Result<(), Box<dyn std::error::Error>> {
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
extra_header = "nope"
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unknown field `extra_header`, expected one of `base_url`, `auth_header`, `auth_scheme`, `auth_value`, `timeout_ms`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_http_base_url_schemes() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[jwt]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"

[apis.projects]
base_url = "ftp://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.projects.base_url must use http or https"
    );

    Ok(())
}
