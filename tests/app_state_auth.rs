use std::path::PathBuf;

use gate_agent::{
    app::AppState,
    config::{
        ConfigSource,
        app_config::AppConfig,
        secrets::{ApiAccessMethod, ApiAccessRule, SecretsConfig},
    },
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

fn any_rule(path: &str) -> ApiAccessRule {
    ApiAccessRule {
        method: ApiAccessMethod::Any,
        path: path.to_owned(),
    }
}

fn exact_rule(method: http::Method, path: &str) -> ApiAccessRule {
    ApiAccessRule {
        method: ApiAccessMethod::Exact(method),
        path: path.to_owned(),
    }
}

const VALID_SECRETS: &str = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "*", path = "*" }], billing = [{ method = "*", path = "*" }] }

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "5773afbb04744f0a04a8534d53d0ab41546e9f6ca1e5c6b32a58cf6fc2f6fb77"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
api_access = { projects = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
description = "Project API"
docs_url = "https://docs.internal.example/projects"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
description = "Billing API"
docs_url = "https://docs.internal.example/billing"
headers = { authorization = "Bearer billing-secret-token" }
timeout_ms = 5000
"#;

#[test]
fn app_state_exposes_existing_api_lookup() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let api = state.api_config("billing")?;

    assert_eq!(api.slug, "billing");
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");

    Ok(())
}

#[test]
fn app_state_resolves_client_by_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let client = state.client_for_bearer_token("partner.s3cr3t")?;
    let projects_access = state.client_api_access(client, "projects")?;

    assert_eq!(projects_access, [any_rule("*")]);

    Ok(())
}

#[test]
fn app_state_exposes_group_derived_client_access() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(
        r#"
[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "5773afbb04744f0a04a8534d53d0ab41546e9f6ca1e5c6b32a58cf6fc2f6fb77"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
group = "shared-read"

[groups.shared-read]
api_access = { projects = [{ method = "get", path = "*" }], billing = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
description = "Project API"
docs_url = "https://docs.internal.example/projects"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
description = "Billing API"
docs_url = "https://docs.internal.example/billing"
headers = { authorization = "Bearer billing-secret-token" }
timeout_ms = 5000
"#,
    )?;

    let client = state.client_for_bearer_token("partner.s3cr3t")?;

    assert_eq!(
        state.client_api_access(client, "projects")?,
        [exact_rule(http::Method::GET, "*")]
    );
    assert_eq!(state.client_api_access(client, "billing")?, [any_rule("*")]);

    Ok(())
}

#[test]
fn app_state_exposes_runtime_api_metadata_for_effective_client_access()
-> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let client = state.client_for_bearer_token("partner.s3cr3t")?;
    let access = state.client_api_access_entry(client, "projects")?;

    assert_eq!(access.rules, [any_rule("*")]);
    assert_eq!(access.api_config.slug, "projects");
    assert_eq!(
        access.api_config.description.as_deref(),
        Some("Project API")
    );
    assert_eq!(
        access.api_config.docs_url.as_ref().map(url::Url::as_str),
        Some("https://docs.internal.example/projects")
    );
    assert_eq!(
        access.api_config.base_url.as_str(),
        "https://projects.internal.example/"
    );

    Ok(())
}

#[test]
fn app_state_lists_effective_client_api_access_entries_for_discovery()
-> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(
        r#"
[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "5773afbb04744f0a04a8534d53d0ab41546e9f6ca1e5c6b32a58cf6fc2f6fb77"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
group = "shared-read"

[groups.shared-read]
api_access = { projects = [{ method = "get", path = "*" }], billing = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
description = "Project API"
docs_url = "https://docs.internal.example/projects"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
description = "Billing API"
docs_url = "https://docs.internal.example/billing"
headers = { authorization = "Bearer billing-secret-token" }
timeout_ms = 5000
"#,
    )?;

    let client = state.client_for_bearer_token("partner.s3cr3t")?;
    let entries = state.client_api_access_entries(client)?;

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].api_config.slug, "billing");
    assert_eq!(entries[0].rules, [any_rule("*")]);
    assert_eq!(
        entries[0].api_config.description.as_deref(),
        Some("Billing API")
    );
    assert_eq!(
        entries[0]
            .api_config
            .docs_url
            .as_ref()
            .map(url::Url::as_str),
        Some("https://docs.internal.example/billing")
    );
    assert_eq!(entries[1].api_config.slug, "projects");
    assert_eq!(entries[1].rules, [exact_rule(http::Method::GET, "*")]);
    assert_eq!(
        entries[1].api_config.description.as_deref(),
        Some("Project API")
    );
    assert_eq!(
        entries[1]
            .api_config
            .docs_url
            .as_ref()
            .map(url::Url::as_str),
        Some("https://docs.internal.example/projects")
    );

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
fn app_state_rejects_blank_malformed_and_unknown_bearer_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    for token in [
        "",
        "   ",
        " partner.s3cr3t ",
        "missing",
        ".secret",
        "partner.",
        "partner.secret.extra",
    ] {
        let error = state.client_for_bearer_token(token).unwrap_err();

        assert!(matches!(error, AppError::InvalidToken));
    }

    let error = state.client_for_bearer_token("missing.s3cr3t").unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn app_state_rejects_hash_mismatch_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(VALID_SECRETS)?;

    let error = state.client_for_bearer_token("partner.secret").unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}

#[test]
fn app_state_rejects_expired_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state(
        r#"
[clients.default]
bearer_token_id = "expired"
bearer_token_hash = "ebb3c39e47bd8ebff3c889fcb0acdde61ef2d7913af92cdf821bb821ee90d048"
bearer_token_expires_at = "2020-10-08T12:00:00Z"
api_access = { projects = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let error = state.client_for_bearer_token("expired.s3cr3t").unwrap_err();

    assert!(matches!(error, AppError::InvalidToken));

    Ok(())
}
