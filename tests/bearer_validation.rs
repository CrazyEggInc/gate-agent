use std::collections::BTreeMap;
use std::path::PathBuf;

use gate_agent::auth::{
    ApiAccessMethod, ApiAccessRule,
    bearer::{
        AuthorizedApiAccess, AuthorizedRequest, api_access_allows,
        validate_bearer_authorized_request, validate_token,
    },
};
use gate_agent::config::secrets::SecretsConfig;
use gate_agent::error::AppError;
use http::Method;
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

[clients.default.api_access]
projects = [
  { method = "GET", path = "/v1/projects" },
  { method = "POST", path = "/v1/projects" },
]
billing = [
  { method = "*", path = "*" },
]

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "5773afbb04744f0a04a8534d53d0ab41546e9f6ca1e5c6b32a58cf6fc2f6fb77"
bearer_token_expires_at = "2030-01-03T03:04:05Z"

[clients.partner.api_access]
projects = [ { method = "get", path = "/v1/projects" } ]

[clients.reader]
bearer_token_id = "reader"
bearer_token_hash = "493db4f6f71aa3cc70f177b3cb7d2a1d5ba309a0a8f957f0f0d73d2a9e5ef4db"
bearer_token_expires_at = "2030-01-04T03:04:05Z"

[clients.reader.api_access]
projects = [ { method = "GET", path = "/v1/projects/*" } ]

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

fn authorized_with_rules(api: &str, rules: Vec<ApiAccessRule>) -> AuthorizedRequest {
    AuthorizedRequest {
        client_slug: "test".to_owned(),
        access: AuthorizedApiAccess {
            apis: BTreeMap::from([(api.to_owned(), rules)]),
        },
    }
}

fn rule(method: ApiAccessMethod, path: &str) -> ApiAccessRule {
    ApiAccessRule {
        method,
        path: path.to_owned(),
    }
}

fn exact_rule(method: Method, path: &str) -> ApiAccessRule {
    rule(ApiAccessMethod::Exact(method), path)
}

fn any_rule(path: &str) -> ApiAccessRule {
    rule(ApiAccessMethod::Any, path)
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
    assert_eq!(
        authorized.access.apis["projects"],
        vec![
            exact_rule(Method::GET, "/v1/projects"),
            exact_rule(Method::POST, "/v1/projects"),
        ]
    );
    assert_eq!(authorized.access.apis["billing"], vec![any_rule("*")]);

    Ok(())
}

#[test]
fn validate_bearer_authorized_request_accepts_case_insensitive_scheme_and_extra_spaces()
-> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let authorized = validate_bearer_authorized_request("   bEaReR   partner.s3cr3t   ", &secrets)?;

    assert_eq!(authorized.client_slug, "partner");
    assert_eq!(authorized.access.apis.len(), 1);
    assert_eq!(
        authorized.access.apis["projects"],
        vec![exact_rule(Method::GET, "/v1/projects")]
    );

    Ok(())
}

#[test]
fn api_access_allows_exact_method_and_path() {
    let authorized = authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/users")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users"
    ));
    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::POST,
        "/api/users"
    ));
    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/accounts"
    ));
}

#[test]
fn api_access_allows_method_case_normalized_by_config() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = load_test_secrets()?;
    let authorized = validate_token("partner.s3cr3t", &secrets)?;

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/v1/projects"
    ));

    Ok(())
}

#[test]
fn api_access_allows_any_method() {
    let authorized = authorized_with_rules("projects", vec![any_rule("/api/users")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::DELETE,
        "/api/users"
    ));
}

#[test]
fn api_access_allows_any_path() {
    let authorized = authorized_with_rules("projects", vec![exact_rule(Method::PATCH, "*")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::PATCH,
        "/api/users/123"
    ));
}

#[test]
fn api_access_allows_prefix_wildcard_path() {
    let authorized = authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/*")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users"
    ));
    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/v1/api/users"
    ));
}

#[test]
fn api_access_allows_middle_wildcard_path() {
    let authorized =
        authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/*/users")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/v1/users"
    ));
    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/v1/internal/users"
    ));
    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/v1/users/123"
    ));
}

#[test]
fn api_access_ignores_query_string() {
    let authorized = authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/users")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users?limit=10"
    ));
}

#[test]
fn api_access_normalizes_empty_query_only_path_to_root() {
    let authorized = authorized_with_rules("projects", vec![exact_rule(Method::GET, "/")]);

    assert!(api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "?limit=10"
    ));
}

#[test]
fn api_access_rejects_literal_dot_segments() {
    let authorized =
        authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/users/*")]);

    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users/../admin"
    ));
    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users/./profile"
    ));
}

#[test]
fn api_access_rejects_percent_encoded_dot_segments() {
    let authorized =
        authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/users/*")]);

    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users/%2e%2e/admin"
    ));
    assert!(!api_access_allows(
        &authorized,
        "projects",
        &Method::GET,
        "/api/users/%2E/profile"
    ));
}

#[test]
fn api_access_blocks_by_default() {
    let no_api = authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/users")]);
    let empty_rules = authorized_with_rules("projects", Vec::new());
    let method_miss =
        authorized_with_rules("projects", vec![exact_rule(Method::POST, "/api/users")]);
    let path_miss =
        authorized_with_rules("projects", vec![exact_rule(Method::GET, "/api/accounts")]);

    assert!(!api_access_allows(
        &no_api,
        "billing",
        &Method::GET,
        "/api/users"
    ));
    assert!(!api_access_allows(
        &empty_rules,
        "projects",
        &Method::GET,
        "/api/users"
    ));
    assert!(!api_access_allows(
        &method_miss,
        "projects",
        &Method::GET,
        "/api/users"
    ));
    assert!(!api_access_allows(
        &path_miss,
        "projects",
        &Method::GET,
        "/api/users"
    ));
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
api_access = { projects = [ { method = "GET", path = "/v1/projects" } ] }

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
