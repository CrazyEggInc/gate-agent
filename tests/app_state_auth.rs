use std::path::PathBuf;

use gate_agent::{
    app::AppState,
    config::{ConfigSource, app_config::AppConfig, secrets::SecretsConfig},
    error::AppError,
};
use tempfile::tempdir;

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

fn load_state(contents: &str) -> Result<AppState, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(contents)?;

    let config = AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    );

    Ok(AppState::from_config(&config)?)
}

fn load_config(contents: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(contents)?;

    Ok(AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    ))
}

const VALID_SECRETS: &str = r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects", "billing"]

[clients.partner]
api_key = "partner-key"
api_key_expires_at = "2026-10-09T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#;

#[test]
fn app_state_exposes_auth_config_and_existing_api_lookup() -> Result<(), Box<dyn std::error::Error>>
{
    let state = load_state(VALID_SECRETS)?;

    let auth = state.auth_config();
    let api = state.api_config("billing")?;

    assert_eq!(auth.issuer, "gate-agent-dev");
    assert_eq!(auth.audience, "gate-agent-clients");
    assert_eq!(api.slug, "billing");
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");

    Ok(())
}

#[test]
fn app_state_resolves_client_by_api_key() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let client = state.client_for_api_key("partner-key")?;

    assert_eq!(client.slug, "partner");
    assert!(client.allowed_apis.contains("projects"));

    Ok(())
}

#[test]
fn app_state_rejects_missing_api_lookup() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let error = state.api_config("missing").unwrap_err();

    assert!(matches!(error, AppError::ForbiddenApi { api } if api == "missing"));

    Ok(())
}

#[test]
fn app_state_rejects_unknown_api_key() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let error = state.client_for_api_key("missing-key").unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn app_state_rejects_expired_api_key() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "expired-key"
api_key_expires_at = "2020-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = state.client_for_api_key("expired-key").unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn app_state_fails_fast_on_duplicate_api_keys() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "shared-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[clients.partner]
api_key = "shared-key"
api_key_expires_at = "2026-10-09T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = AppState::from_config(&config).unwrap_err();

    assert!(
        matches!(error, AppError::Internal(message) if message.contains("duplicate client api_key"))
    );

    Ok(())
}
