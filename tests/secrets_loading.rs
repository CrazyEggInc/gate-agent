use secrecy::ExposeSecret;

use gate_agent::config::secrets::SecretsConfig;
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
fn secrets_example_matches_dev_sample_contract() -> Result<(), Box<dyn std::error::Error>> {
    let sample_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".secrets.example");
    let sample_contents = std::fs::read_to_string(&sample_path)?;
    let config = SecretsConfig::load_from_file(&sample_path)?;
    let client = config
        .clients
        .get("default")
        .expect("default client config");
    let api = config.apis.get("projects").expect("projects api config");

    assert!(sample_contents.contains("rotate"));
    assert_eq!(config.auth.issuer, "gate-agent-dev");
    assert_eq!(config.auth.audience, "gate-agent-clients");
    assert_eq!(client.api_key_expires_at.as_str(), "2026-10-08T12:00:00Z");
    assert_eq!(
        client.allowed_apis.iter().collect::<Vec<_>>(),
        vec![&"projects"]
    );
    assert_eq!(api.base_url.as_str(), "http://127.0.0.1:18081/api");
    assert_eq!(api.auth_header.as_str(), "authorization");
    assert_eq!(api.auth_scheme.as_deref(), Some("Bearer"));
    assert_eq!(api.auth_value.expose_secret(), "local-upstream-token");
    assert_eq!(api.timeout_ms, 5000);

    Ok(())
}

#[test]
fn secrets_config_loads_validated_structs() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "client-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["billing"]

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let client = config
        .clients
        .get("default")
        .expect("default client config");
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(config.auth.issuer, "gate-agent-dev");
    assert_eq!(config.auth.audience, "gate-agent-clients");
    assert_eq!(config.auth.signing_secret.expose_secret(), "rotate-me");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(client.slug, "default");
    assert_eq!(client.api_key.expose_secret(), "client-api-key");
    assert_eq!(client.api_key_expires_at.as_str(), "2026-10-08T12:00:00Z");
    assert_eq!(client.api_key_expires_at.unix_timestamp(), 1_791_460_800);
    assert_eq!(client.api_key_expires_at.nanosecond(), 0);
    assert_eq!(
        client.allowed_apis.iter().collect::<Vec<_>>(),
        vec![&"billing"]
    );
    assert_eq!(api.slug, "billing");
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");
    assert_eq!(api.auth_header.as_str(), "authorization");
    assert_eq!(api.auth_scheme.as_deref(), Some("Bearer"));
    assert_eq!(api.auth_value.expose_secret(), "billing-secret-token");
    assert_eq!(api.timeout_ms, 5000);

    Ok(())
}

#[test]
fn secrets_config_parses_valid_toml_from_source_label() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecretsConfig::parse(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "client-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["billing"]

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#,
        "stdin",
    )?;

    let client = config
        .clients
        .get("default")
        .expect("default client config");
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(config.auth.issuer, "gate-agent-dev");
    assert_eq!(config.auth.audience, "gate-agent-clients");
    assert_eq!(config.auth.signing_secret.expose_secret(), "rotate-me");
    assert_eq!(client.slug, "default");
    assert_eq!(client.api_key.expose_secret(), "client-api-key");
    assert_eq!(client.api_key_expires_at.as_str(), "2026-10-08T12:00:00Z");
    assert_eq!(
        client.allowed_apis.iter().collect::<Vec<_>>(),
        vec![&"billing"]
    );
    assert_eq!(api.slug, "billing");
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");
    assert_eq!(api.auth_header.as_str(), "authorization");
    assert_eq!(api.auth_scheme.as_deref(), Some("Bearer"));
    assert_eq!(api.auth_value.expose_secret(), "billing-secret-token");
    assert_eq!(api.timeout_ms, 5000);

    Ok(())
}

#[test]
fn secrets_config_parse_errors_use_stdin_source_label() {
    let error = SecretsConfig::parse(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "client-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["billing"
"#,
        "stdin",
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("failed to parse config stdin:")
    );
    assert!(!error.to_string().contains("config file"));
}

#[test]
fn secrets_config_loads_multiple_clients_sharing_one_api() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[clients.partner]
api_key = "partner-key"
api_key_expires_at = "2026-10-09T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;

    assert_eq!(config.clients.len(), 2);
    assert!(
        config
            .clients
            .get("default")
            .expect("default client")
            .allowed_apis
            .contains("projects")
    );
    assert!(
        config
            .clients
            .get("partner")
            .expect("partner client")
            .allowed_apis
            .contains("projects")
    );

    Ok(())
}

#[test]
fn secrets_config_requires_at_least_one_client() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients]

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
        "at least one [clients.*] entry is required"
    );

    Ok(())
}

#[test]
fn secrets_config_allows_empty_apis_and_empty_allowed_apis()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = []

[apis]
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;

    assert_eq!(config.apis.len(), 0);
    assert!(
        config
            .clients
            .get("default")
            .expect("default client")
            .allowed_apis
            .is_empty()
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_lowercase_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

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
fn secrets_config_rejects_api_slug_with_slash() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis."projects/api"]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "api slug 'projects/api' must contain only lowercase letters, digits, or hyphen"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_lowercase_client_slug() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.Default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(error.to_string(), "client slug 'Default' must be lowercase");

    Ok(())
}

#[test]
fn secrets_config_rejects_client_slug_with_trailing_space() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients."default "]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

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
        "client slug 'default ' must contain only lowercase letters, digits, or hyphen"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_lowercase_allowed_api_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["Projects"]

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
        "clients.default.allowed_apis[0] must be lowercase"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_allowed_api_entries_with_trailing_space()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects "]

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
        "clients.default.allowed_apis[0] must contain only lowercase letters, digits, or hyphen"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_api_in_allowed_apis() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["unknown"]

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
        "clients.default.allowed_apis contains unknown api 'unknown'"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_duplicate_allowed_apis() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects", "projects"]

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
        "clients.default.allowed_apis contains duplicate api 'projects'"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_top_level_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
unexpected = "nope"

[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `unexpected`"));
    assert!(
        error
            .to_string()
            .contains("expected one of `auth`, `clients`, `apis`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_client_auth_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
algorithm = "HS256"
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
shared_secret = "replace-me"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `algorithm`"));
    assert!(
        error
            .to_string()
            .contains("expected one of `api_key`, `api_key_expires_at`, `allowed_apis`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_api_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

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

#[test]
fn secrets_config_rejects_zero_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 0
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.projects.timeout_ms must be greater than 0"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_invalid_header_name() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "bad header"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("apis.projects.auth_header is invalid:")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_utc_api_key_expiration() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00+00:00"
allowed_apis = []
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.api_key_expires_at must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_malformed_api_key_expiration() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08 12:00:00Z"
allowed_apis = []
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.api_key_expires_at must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
    );

    Ok(())
}
