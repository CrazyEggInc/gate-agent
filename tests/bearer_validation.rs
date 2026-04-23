use std::path::PathBuf;

use gate_agent::auth::{
    AccessLevel,
    bearer::{validate_bearer_authorized_request, validate_token},
};
use gate_agent::config::secrets::SecretsConfig;
use gate_agent::error::AppError;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use tempfile::tempdir;

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
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "write", billing = "write" }

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "5773afbb04744f0a04a8534d53d0ab41546e9f6ca1e5c6b32a58cf6fc2f6fb77"
bearer_token_expires_at = "2030-01-03T03:04:05Z"
api_access = { projects = "write" }

[clients.reader]
bearer_token_id = "reader"
bearer_token_hash = "493db4f6f71aa3cc70f177b3cb7d2a1d5ba309a0a8f957f0f0d73d2a9e5ef4db"
bearer_token_expires_at = "2030-01-04T03:04:05Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "Bearer billing-secret-token" }
timeout_ms = 5000
"#,
    )?;

    Ok(SecretsConfig::load_from_file(&secrets_file)?)
}

struct JsonShapedToken<'a> {
    sub: &'a str,
}

struct JsonApiAccess;

impl Serialize for JsonShapedToken<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_map(Some(2))?;
        state.serialize_entry("sub", self.sub)?;
        state.serialize_entry("apis", &JsonApiAccess)?;
        state.end()
    }
}

impl Serialize for JsonApiAccess {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("projects", "read")?;
        map.serialize_entry("projects", "write")?;
        map.end()
    }
}

#[test]
fn validate_token_resolves_client_and_access_map() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let authorized = validate_token("default.s3cr3t", &secrets)?;

    assert_eq!(authorized.client_slug, "default");
    assert_eq!(authorized.access.apis.len(), 2);
    assert_eq!(authorized.access.apis["projects"], AccessLevel::Write);
    assert_eq!(authorized.access.apis["billing"], AccessLevel::Write);

    Ok(())
}

#[test]
fn validate_bearer_authorized_request_accepts_case_insensitive_scheme_and_extra_spaces()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let authorized = validate_bearer_authorized_request("   bEaReR   partner.s3cr3t   ", &secrets)?;

    assert_eq!(authorized.client_slug, "partner");
    assert_eq!(authorized.access.apis.len(), 1);
    assert_eq!(authorized.access.apis["projects"], AccessLevel::Write);

    Ok(())
}

#[test]
fn validate_bearer_authorized_request_rejects_missing_bearer_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    let error = validate_bearer_authorized_request("default.s3cr3t", &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_bearer_authorized_request_rejects_blank_token() -> Result<(), Box<dyn std::error::Error>>
{
    let secrets = load_test_secrets()?;
    let error = validate_bearer_authorized_request("Bearer   ", &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_blank_direct_token() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    for token in ["", "   "] {
        let error = validate_token(token, &secrets).unwrap_err();

        assert!(matches!(error, AppError::InvalidToken));
    }

    Ok(())
}

#[test]
fn validate_token_rejects_malformed_direct_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    for token in ["default", ".s3cr3t", "default.", "default.secret.extra"] {
        let error = validate_token(token, &secrets).unwrap_err();

        assert!(matches!(error, AppError::InvalidToken));
    }

    Ok(())
}

#[test]
fn validate_token_rejects_unknown_token() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    let error = validate_token("missing.s3cr3t", &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;

    let error = validate_token("partner.secret", &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn validate_token_rejects_expired_client_token() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2020-01-02T03:04:05Z"
api_access = { projects = "write" }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;
    let secrets = SecretsConfig::load_from_file(&secrets_file)?;

    let error = validate_token("default.s3cr3t", &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn direct_bearer_validation_does_not_normalize_duplicate_api_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let authorized = validate_token("default.s3cr3t", &secrets)?;

    assert_eq!(authorized.access.apis.len(), 2);

    Ok(())
}

#[test]
fn json_shaped_tokens_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let bogus = serde_json::to_string(&JsonShapedToken { sub: "default" })?;
    let error = validate_token(&bogus, &secrets).unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}
