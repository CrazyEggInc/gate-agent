use std::path::PathBuf;

use gate_agent::auth::jwt::{
    DEFAULT_LOCAL_TOKEN_TTL_SECS, sign_local_test_token, sign_local_test_token_at,
    validate_bearer_token, validate_token,
};
use gate_agent::config::secrets::SecretsConfig;
use gate_agent::error::AppError;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use secrecy::ExposeSecret;
use serde::Serialize;
use tempfile::tempdir;

fn current_timestamp() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

fn load_test_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
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

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#,
    )?;

    Ok(SecretsConfig::load_from_file(&secrets_file)?)
}

fn encode_token<T: Serialize>(
    claims: &T,
    algorithm: Algorithm,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::new(algorithm),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

#[derive(Serialize)]
struct ManualClaims<'a> {
    api: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
}

#[derive(Serialize)]
struct MissingIssuedAtClaims<'a> {
    api: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
}

#[test]
fn signer_and_validator_round_trip_valid_token() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let issued_at = current_timestamp()?;

    let token = sign_local_test_token_at("projects", &secrets, issued_at, 300)?;
    let claims = validate_token(&token, &secrets)?;

    assert_eq!(claims.api, "projects");
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");
    assert_eq!(claims.iat, issued_at);
    assert_eq!(claims.exp, issued_at + 300);
    assert_eq!(DEFAULT_LOCAL_TOKEN_TTL_SECS, 300);

    Ok(())
}

#[test]
fn sign_local_test_token_uses_default_five_minute_ttl() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    let token = sign_local_test_token("projects", &secrets)?;
    let claims = validate_token(&token, &secrets)?;

    assert_eq!(claims.api, "projects");
    assert_eq!(claims.exp - claims.iat, DEFAULT_LOCAL_TOKEN_TTL_SECS);
    assert_eq!(DEFAULT_LOCAL_TOKEN_TTL_SECS, 300);

    Ok(())
}

#[test]
fn validate_bearer_token_rejects_missing_bearer_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = sign_local_test_token_at("projects", &secrets, 1_700_000_000, 300)?;

    let error = validate_bearer_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_bearer_token_accepts_case_insensitive_scheme_and_extra_spaces()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = sign_local_test_token("projects", &secrets)?;

    let claims = validate_bearer_token(&format!("   bEaReR   {token}   "), &secrets)?;

    assert_eq!(claims.api, "projects");

    Ok(())
}

#[test]
fn validate_bearer_token_rejects_missing_token_after_bearer()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    let error = validate_bearer_token("Bearer   ", &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_unknown_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "unknown",
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: 4_000_000_000,
            exp: 4_000_000_300,
        },
        Algorithm::HS256,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::ForbiddenApi { api } if api == "unknown"));

    Ok(())
}

#[test]
fn validate_token_rejects_uppercase_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "Projects",
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: 4_000_000_000,
            exp: 4_000_000_300,
        },
        Algorithm::HS256,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_wrong_algorithm() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "projects",
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: 4_000_000_000,
            exp: 4_000_000_300,
        },
        Algorithm::HS384,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_bad_signature() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "projects",
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: 4_000_000_000,
            exp: 4_000_000_300,
        },
        Algorithm::HS256,
        "wrong-secret",
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_wrong_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "projects",
            iss: "someone-else",
            aud: "gate-agent-clients",
            iat: 4_000_000_000,
            exp: 4_000_000_300,
        },
        Algorithm::HS256,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_wrong_audience() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "projects",
            iss: "gate-agent-dev",
            aud: "someone-else",
            iat: 4_000_000_000,
            exp: 4_000_000_300,
        },
        Algorithm::HS256,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_expired_token() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &ManualClaims {
            api: "projects",
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: 1,
            exp: 2,
        },
        Algorithm::HS256,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_missing_required_claim() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let token = encode_token(
        &MissingIssuedAtClaims {
            api: "projects",
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            exp: 4_000_000_300,
        },
        Algorithm::HS256,
        secrets.jwt.shared_secret.expose_secret(),
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}
