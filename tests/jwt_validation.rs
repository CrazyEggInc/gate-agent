use std::path::PathBuf;

use gate_agent::auth::jwt::{
    DEFAULT_LOCAL_TOKEN_TTL_SECS, sign_local_test_token, sign_local_test_token_at,
    sign_local_test_token_for_client_at, validate_authorized_request, validate_bearer_token,
    validate_token,
};
use gate_agent::config::secrets::SecretsConfig;
use gate_agent::error::AppError;
use gate_agent::time::unix_timestamp_secs;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use secrecy::ExposeSecret;
use serde::Serialize;
use tempfile::tempdir;

fn valid_claim_window() -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let issued_at = unix_timestamp_secs()?;
    Ok((issued_at, issued_at + 300))
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "replace-me"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
allowed_apis = ["projects", "billing"]

[clients.partner]
api_key = "partner-client-key"
api_key_expires_at = "2030-01-03T03:04:05Z"
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
"#,
    )?;

    Ok(SecretsConfig::load_from_file(&secrets_file)?)
}

fn default_client_secret(secrets: &SecretsConfig) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(secrets.auth.signing_secret.expose_secret())
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
    sub: &'a str,
    apis: &'a [&'a str],
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
}

#[derive(Serialize)]
struct MissingSubjectClaims<'a> {
    apis: &'a [&'a str],
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
}

#[derive(Serialize)]
struct MissingIssuedAtClaims<'a> {
    sub: &'a str,
    apis: &'a [&'a str],
    iss: &'a str,
    aud: &'a str,
    exp: u64,
}

#[test]
fn signer_and_validator_round_trip_valid_token() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let issued_at = unix_timestamp_secs()?;

    let token = sign_local_test_token_at("projects", &secrets, issued_at, 300)?;
    let claims = validate_token(&token, &secrets)?;

    assert_eq!(claims.sub, "default");
    assert_eq!(claims.apis(), vec!["projects"]);
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");
    assert_eq!(claims.iat, issued_at);
    assert_eq!(claims.exp, issued_at + 300);
    assert_eq!(DEFAULT_LOCAL_TOKEN_TTL_SECS, 600);

    Ok(())
}

#[test]
fn sign_local_test_token_uses_default_ten_minute_ttl() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    let token = sign_local_test_token("projects", &secrets)?;
    let claims = validate_token(&token, &secrets)?;

    assert_eq!(claims.sub, "default");
    assert_eq!(claims.apis(), vec!["projects"]);
    assert_eq!(claims.exp - claims.iat, DEFAULT_LOCAL_TOKEN_TTL_SECS);
    assert_eq!(DEFAULT_LOCAL_TOKEN_TTL_SECS, 600);

    Ok(())
}

#[test]
fn validate_token_rejects_future_issued_at() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let now = unix_timestamp_secs()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: now + 3_600,
            exp: now + 3_900,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_bearer_token_rejects_missing_bearer_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let issued_at = unix_timestamp_secs()?;
    let token = sign_local_test_token_at("projects", &secrets, issued_at, 300)?;

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

    assert_eq!(claims.sub, "default");
    assert_eq!(claims.apis(), vec!["projects"]);

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
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["unknown"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::ForbiddenApi { api } if api == "unknown"));

    Ok(())
}

#[test]
fn validate_token_rejects_uppercase_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["Projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_api_slug_with_slash() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["projects/api"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_api_slug_with_trailing_space() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["projects "],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_resolves_client_from_subject() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let issued_at = unix_timestamp_secs()?;
    let token =
        sign_local_test_token_for_client_at("partner", "projects", &secrets, issued_at, 300)?;

    let claims = validate_token(&token, &secrets)?;

    assert_eq!(claims.sub, "partner");
    assert_eq!(claims.apis(), vec!["projects"]);
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");

    Ok(())
}

#[test]
fn validate_token_accepts_multiple_api_claims_and_preserves_normalized_list()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["projects", "billing", "projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let claims = validate_token(&token, &secrets)?;

    assert_eq!(claims.sub, "default");
    assert_eq!(claims.apis(), vec!["billing", "projects"]);

    Ok(())
}

#[test]
fn validate_authorized_request_preserves_multiple_api_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["projects", "billing", "projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let authorized = validate_authorized_request(&token, &secrets)?;

    assert_eq!(authorized.client_slug, "default");
    assert_eq!(authorized.claims.sub, "default");
    assert_eq!(authorized.claims.apis(), vec!["billing", "projects"]);

    Ok(())
}

#[test]
fn validate_token_accepts_different_clients_for_same_api() -> Result<(), Box<dyn std::error::Error>>
{
    let secrets = load_test_secrets()?;
    let issued_at = unix_timestamp_secs()?;

    let default_claims = validate_token(
        &sign_local_test_token_for_client_at("default", "projects", &secrets, issued_at, 300)?,
        &secrets,
    )?;
    let partner_claims = validate_token(
        &sign_local_test_token_for_client_at("partner", "projects", &secrets, issued_at, 300)?,
        &secrets,
    )?;

    assert_eq!(default_claims.sub, "default");
    assert_eq!(partner_claims.sub, "partner");
    assert_eq!(default_claims.apis(), vec!["projects"]);
    assert_eq!(partner_claims.apis(), vec!["projects"]);

    Ok(())
}

#[test]
fn validate_token_rejects_unknown_client_subject() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "unknown",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_uppercase_subject() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "Default",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_subject_with_slash() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default/client",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_subject_with_trailing_space() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default ",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_missing_subject_claim() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &MissingSubjectClaims {
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_disallowed_api_for_valid_client() -> Result<(), Box<dyn std::error::Error>>
{
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "partner",
            apis: &["billing"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::ForbiddenApi { api } if api == "billing"));

    Ok(())
}

#[test]
fn validate_token_rejects_wrong_algorithm() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "default",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS384,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_bad_signature() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "partner",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat,
            exp,
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
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "partner",
            apis: &["projects"],
            iss: "someone-else",
            aud: "gate-agent-clients",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_wrong_audience() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (iat, exp) = valid_claim_window()?;
    let token = encode_token(
        &ManualClaims {
            sub: "partner",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "someone-else",
            iat,
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
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
            sub: "default",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            iat: 1,
            exp: 2,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_missing_required_claim() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let (_, exp) = valid_claim_window()?;
    let token = encode_token(
        &MissingIssuedAtClaims {
            sub: "default",
            apis: &["projects"],
            iss: "gate-agent-dev",
            aud: "gate-agent-clients",
            exp,
        },
        Algorithm::HS256,
        default_client_secret(&secrets)?,
    )?;

    let error = validate_token(&token, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}
