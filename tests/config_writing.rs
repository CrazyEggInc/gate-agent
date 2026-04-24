use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gate_agent::config::secrets::AccessLevel;
use gate_agent::config::write::{self, ApiUpsert, ClientUpsert, GroupUpsert};
use secrecy::SecretString;

#[test]
fn init_config_writes_minimal_generated_document_and_creates_parent_dirs()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("nested/config/gate-agent.toml");

    write::init_config(&config_path, false, None)?;

    assert!(config_path.exists());

    let contents = fs::read_to_string(&config_path)?;
    let parsed: toml::Value = contents.parse()?;
    assert!(section_body(&contents, "auth").is_none());
    assert!(!contents.contains("api_key = "));

    let default_client = section_body(&contents, "clients.default").unwrap();

    let bearer_token_id = find_string_value(default_client, "bearer_token_id").unwrap();
    assert!(bearer_token_id.len() >= 16);
    assert!(is_lower_hex(&bearer_token_id));

    let bearer_token_hash = find_string_value(default_client, "bearer_token_hash").unwrap();
    assert_eq!(bearer_token_hash.len(), 64);
    assert!(is_lower_hex(&bearer_token_hash));

    let expires_at = find_string_value(default_client, "bearer_token_expires_at").unwrap();
    let expires_at_unix = parse_rfc3339_z(&expires_at).unwrap();
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let min_expected = now_unix + Duration::from_secs(170 * 24 * 60 * 60).as_secs();
    let max_expected = now_unix + Duration::from_secs(190 * 24 * 60 * 60).as_secs();
    assert!(
        expires_at_unix >= min_expected,
        "expiry too early: {expires_at}"
    );
    assert!(
        expires_at_unix <= max_expected,
        "expiry too late: {expires_at}"
    );

    assert_eq!(
        find_string_value(default_client, "group").as_deref(),
        Some("local-default")
    );
    assert_eq!(find_inline_table_value(default_client, "api_access"), None);
    assert!(!default_client.contains("api_access ="));
    let bearer_token_id_index = default_client.find("bearer_token_id = ").unwrap();
    let bearer_token_hash_index = default_client.find("bearer_token_hash = ").unwrap();
    let bearer_token_expires_at_index = default_client.find("bearer_token_expires_at = ").unwrap();
    let group_index = default_client.find("group = \"local-default\"").unwrap();
    assert!(bearer_token_id_index < bearer_token_hash_index);
    assert!(bearer_token_hash_index < bearer_token_expires_at_index);
    assert!(bearer_token_expires_at_index < group_index);

    let server = section_body(&contents, "server").unwrap();
    assert_eq!(
        find_string_value(server, "bind").as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(find_integer_value(server, "port"), Some(8787));

    let groups = section_body(&contents, "groups").unwrap();
    assert!(groups.trim().is_empty());

    let local_default_group = section_body(&contents, "groups.local-default").unwrap();
    assert_eq!(
        find_inline_table_value(local_default_group, "api_access"),
        Some(vec![])
    );

    let apis = section_body(&contents, "apis").unwrap();
    assert!(apis.trim().is_empty());

    assert!(parsed.get("groups").is_some());
    assert!(parsed.get("apis").is_some());
    assert_eq!(
        parsed
            .get("clients")
            .and_then(|value| value.get("default"))
            .and_then(|value| value.get("group"))
            .and_then(toml::Value::as_str),
        Some("local-default")
    );
    assert!(
        parsed
            .get("clients")
            .and_then(|value| value.get("default"))
            .and_then(|value| value.get("api_access"))
            .is_none()
    );
    assert_eq!(
        parsed
            .get("groups")
            .and_then(|value| value.get("local-default"))
            .and_then(|value| value.get("api_access"))
            .and_then(toml::Value::as_table)
            .map(toml::value::Table::len),
        Some(0)
    );

    let default_client_index = contents.find("[clients.default]\n").unwrap();
    let server_index = contents.find("[server]\n").unwrap();
    let groups_index = contents.find("[groups]\n").unwrap();
    let local_default_group_index = contents.find("[groups.local-default]\n").unwrap();
    let apis_index = contents.find("[apis]\n").unwrap();
    assert!(default_client_index < server_index);
    assert!(server_index < groups_index);
    assert!(groups_index < local_default_group_index);
    assert!(local_default_group_index < apis_index);

    Ok(())
}

#[test]
fn init_config_escapes_server_bind_in_toml_output() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write::init_config_with_default_bearer_token_and_server(
        &config_path,
        false,
        None,
        "127.0.0.1\"quoted",
        8787,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let parsed: toml::Value = contents.parse()?;

    assert_eq!(
        parsed
            .get("server")
            .and_then(|value| value.get("bind"))
            .and_then(toml::Value::as_str),
        Some("127.0.0.1\"quoted")
    );

    Ok(())
}

#[test]
fn init_config_writes_encrypted_document_and_reads_it_back()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("nested/config/gate-agent.secrets");
    let password = SecretString::from("super-secret-passphrase".to_owned());

    write::init_config(&config_path, true, Some(&password))?;

    let raw_contents = fs::read_to_string(&config_path)?;
    assert!(raw_contents.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(!raw_contents.contains("[auth]"));
    assert!(!raw_contents.contains("[clients.default]"));

    let loaded = write::load_display_text(&config_path, Some(&password))?;
    assert!(loaded.toml.contains("[clients.default]"));
    assert!(loaded.toml.contains("[server]"));
    assert!(loaded.toml.contains("group = \"local-default\""));
    assert!(loaded.toml.contains("[groups]"));
    assert!(loaded.toml.contains("[groups.local-default]"));
    assert!(loaded.toml.contains("api_access = {}"));
    assert!(loaded.toml.contains("[apis]"));
    assert!(loaded.toml.contains("bind = \"127.0.0.1\""));
    assert!(loaded.toml.contains("port = 8787"));
    assert!(loaded.toml.contains("bearer_token_id"));
    assert!(!loaded.toml.contains("[auth]"));
    assert!(!loaded.toml.contains("api_key = "));
    assert!(!loaded.toml.contains("clients.default.api_access"));

    let default_client = section_body(&loaded.toml, "clients.default").unwrap();
    assert_eq!(
        find_string_value(default_client, "group").as_deref(),
        Some("local-default")
    );
    assert_eq!(find_inline_table_value(default_client, "api_access"), None);
    assert!(!default_client.contains("api_access ="));

    let local_default_group = section_body(&loaded.toml, "groups.local-default").unwrap();
    assert_eq!(
        find_inline_table_value(local_default_group, "api_access"),
        Some(vec![])
    );

    Ok(())
}

#[test]
fn config_init_prints_default_bearer_token_once_and_persists_only_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "init",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(
        stdout
            .matches("Generated token for client 'default': ")
            .count(),
        1
    );
    let full_token = parse_printed_token(&stdout, "default").ok_or("missing printed token")?;
    let (token_id, secret) = split_full_token(&full_token).ok_or("invalid token format")?;
    assert!(is_lower_hex(token_id));
    assert!(is_lower_hex(secret));

    let contents = fs::read_to_string(&config_path)?;
    let default_client = section_body(&contents, "clients.default").unwrap();

    assert_eq!(
        find_string_value(default_client, "bearer_token_id").as_deref(),
        Some(token_id)
    );
    assert_eq!(
        find_string_value(default_client, "bearer_token_hash").as_deref(),
        Some(write::sha256_hex(&full_token).as_str())
    );
    assert!(!contents.contains(&full_token));

    Ok(())
}

#[test]
fn add_api_upserts_single_header_without_clobbering_unrelated_content()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"# keep this comment
[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "projects".to_string(),
            base_url: "https://projects.internal.example/api".to_string(),
            headers: std::collections::BTreeMap::from([(
                "authorization".to_string(),
                "first-token".to_string(),
            )]),
            basic_auth: None,
            timeout_ms: 5_000,
        },
        None,
    )?;

    let first_contents = fs::read_to_string(&config_path)?;
    let first_projects = section_body(&first_contents, "apis.projects").unwrap();
    let projects_with_notes = first_projects.replacen(
        "headers = { authorization = \"first-token\" }\n",
        "# preserve this api comment\nheaders = { authorization = \"first-token\" }\nnotes = \"keep-me\"\n",
        1,
    );
    let first_projects_header = "[apis.projects]\n";
    let projects_start = first_contents.find(first_projects_header).unwrap();
    let projects_body_start = projects_start + first_projects_header.len();
    let projects_end = projects_body_start + first_projects.len();
    let mut injected_contents = String::with_capacity(first_contents.len() + 64);
    injected_contents.push_str(&first_contents[..projects_body_start]);
    injected_contents.push_str(&projects_with_notes);
    injected_contents.push_str(&first_contents[projects_end..]);
    fs::write(&config_path, injected_contents)?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "projects".to_string(),
            base_url: "https://projects.internal.example/v2".to_string(),
            headers: std::collections::BTreeMap::from([(
                "x-service-token".to_string(),
                "second-token".to_string(),
            )]),
            basic_auth: None,
            timeout_ms: 7_500,
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;

    assert!(contents.starts_with("# keep this comment"));
    assert_eq!(contents.matches("[apis.projects]").count(), 1);
    assert!(contents.contains("# preserve this api comment"));
    assert!(!contents.contains("auth_header ="));
    assert!(!contents.contains("auth_value ="));
    assert!(!contents.contains("auth_scheme ="));

    let projects = section_body(&contents, "apis.projects").unwrap();

    assert_eq!(
        find_string_value(projects, "base_url").as_deref(),
        Some("https://projects.internal.example/v2")
    );
    assert_eq!(
        find_inline_table_value(projects, "headers"),
        Some(vec![(
            "x-service-token".to_string(),
            "second-token".to_string(),
        )])
    );
    assert_eq!(
        find_string_value(projects, "notes").as_deref(),
        Some("keep-me")
    );
    assert_eq!(find_integer_value(projects, "timeout_ms"), Some(7_500));

    Ok(())
}

#[test]
fn add_api_writes_multiple_headers_in_stable_order() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "projects".to_string(),
            base_url: "https://projects.internal.example/api".to_string(),
            headers: std::collections::BTreeMap::from([
                ("x-zeta-token".to_string(), "zeta-secret".to_string()),
                (
                    "authorization".to_string(),
                    "Bearer upstream-token".to_string(),
                ),
            ]),
            basic_auth: None,
            timeout_ms: 5_000,
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let projects = section_body(&contents, "apis.projects").unwrap();

    assert_eq!(
        find_inline_table_value(projects, "headers"),
        Some(vec![
            (
                "authorization".to_string(),
                "Bearer upstream-token".to_string()
            ),
            ("x-zeta-token".to_string(), "zeta-secret".to_string()),
        ])
    );
    assert!(projects.contains(
        "headers = { authorization = \"Bearer upstream-token\", x-zeta-token = \"zeta-secret\" }"
    ));

    Ok(())
}

#[test]
fn add_api_with_basic_auth_writes_basic_auth_table() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "billing".to_string(),
            base_url: "https://billing.internal.example/api".to_string(),
            headers: std::collections::BTreeMap::from([(
                "x-api-key".to_string(),
                "secondary-secret".to_string(),
            )]),
            basic_auth: Some(write::ApiBasicAuthUpsert {
                username: "billing-user".to_string(),
                password: Some("billing-pass".to_string()),
            }),
            timeout_ms: 5_000,
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let billing = section_body(&contents, "apis.billing").unwrap();
    assert!(
        billing
            .contains("basic_auth = { username = \"billing-user\", password = \"billing-pass\" }")
    );
    assert!(billing.contains("headers = { x-api-key = \"secondary-secret\" }"));

    Ok(())
}

#[test]
fn add_api_switching_to_basic_auth_removes_only_authorization_header()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[apis.billing]
base_url = "https://billing.internal.example/api"
headers = { authorization = "Bearer old-token", x-api-key = "keep-me" }
timeout_ms = 5000
"#,
    )?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "billing".to_string(),
            base_url: "https://billing.internal.example/api".to_string(),
            headers: std::collections::BTreeMap::from([(
                "x-api-key".to_string(),
                "keep-me".to_string(),
            )]),
            basic_auth: Some(write::ApiBasicAuthUpsert {
                username: "billing-user".to_string(),
                password: None,
            }),
            timeout_ms: 5_000,
        },
        None,
    )?;

    let parsed: toml::Value = fs::read_to_string(&config_path)?.parse()?;
    assert_eq!(
        parsed
            .get("apis")
            .and_then(|value| value.get("billing"))
            .and_then(|value| value.get("headers"))
            .and_then(|value| value.get("authorization")),
        None
    );
    assert_eq!(
        parsed
            .get("apis")
            .and_then(|value| value.get("billing"))
            .and_then(|value| value.get("headers"))
            .and_then(|value| value.get("x-api-key"))
            .and_then(toml::Value::as_str),
        Some("keep-me")
    );
    assert_eq!(
        parsed
            .get("apis")
            .and_then(|value| value.get("billing"))
            .and_then(|value| value.get("basic_auth"))
            .and_then(|value| value.get("username"))
            .and_then(toml::Value::as_str),
        Some("billing-user")
    );

    Ok(())
}

#[test]
fn add_api_with_empty_headers_removes_headers_and_stale_legacy_auth_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[apis.projects]
base_url = "https://projects.internal.example/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "upstream-token"
timeout_ms = 5000
# preserve this api comment
notes = "keep-me"
"#,
    )?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "projects".to_string(),
            base_url: "https://projects.internal.example/v2".to_string(),
            headers: std::collections::BTreeMap::new(),
            basic_auth: None,
            timeout_ms: 7_500,
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let projects = section_body(&contents, "apis.projects").unwrap();

    assert_eq!(
        find_string_value(projects, "base_url").as_deref(),
        Some("https://projects.internal.example/v2")
    );
    assert_eq!(find_inline_table_value(projects, "headers"), None);
    assert!(!projects.contains("headers ="));
    assert!(!projects.contains("auth_header ="));
    assert!(!projects.contains("auth_value ="));
    assert!(!projects.contains("auth_scheme ="));
    assert!(contents.contains("# preserve this api comment"));
    assert_eq!(
        find_string_value(projects, "notes").as_deref(),
        Some("keep-me")
    );
    assert_eq!(find_integer_value(projects, "timeout_ms"), Some(7_500));

    Ok(())
}

#[test]
fn config_add_api_prints_implicit_default_bearer_token_once_and_persists_only_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "projects",
            "--base-url",
            "https://projects.internal.example/api",
            "--header",
            "authorization=Bearer upstream-token",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(
        stdout
            .matches("Generated token for client 'default': ")
            .count(),
        1
    );
    let full_token = parse_printed_token(&stdout, "default").ok_or("missing printed token")?;
    let (token_id, secret) = split_full_token(&full_token).ok_or("invalid token format")?;
    assert!(is_lower_hex(token_id));
    assert!(is_lower_hex(secret));

    let contents = fs::read_to_string(&config_path)?;
    let default_client = section_body(&contents, "clients.default").unwrap();
    let api = section_body(&contents, "apis.projects").unwrap();

    assert_eq!(
        find_string_value(default_client, "bearer_token_id").as_deref(),
        Some(token_id)
    );
    assert_eq!(
        find_string_value(default_client, "bearer_token_hash").as_deref(),
        Some(write::sha256_hex(&full_token).as_str())
    );
    assert!(!contents.contains(&full_token));
    assert_eq!(
        find_string_value(api, "base_url").as_deref(),
        Some("https://projects.internal.example/api")
    );
    assert_eq!(
        find_inline_table_value(api, "headers"),
        Some(vec![(
            "authorization".to_string(),
            "Bearer upstream-token".to_string(),
        )])
    );
    assert!(!contents.contains("auth_header ="));
    assert!(!contents.contains("auth_value ="));
    assert!(!api.contains("auth_scheme ="));

    Ok(())
}

#[test]
fn add_client_writes_inline_api_access_in_stable_order_and_preserves_existing_token_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[groups]

[apis]
"#,
    )?;

    let first_result = write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            bearer_token: None,
            bearer_token_expires_at: None,
            access: write::ClientAccessUpsert::ApiAccess(std::collections::BTreeMap::from([(
                "projects".to_string(),
                AccessLevel::Read,
            )])),
        },
        None,
    )?;

    let first_contents = fs::read_to_string(&config_path)?;
    let first_client = section_body(&first_contents, "clients.partner").unwrap();
    let original_token_id = find_string_value(first_client, "bearer_token_id").unwrap();
    let original_token_hash = find_string_value(first_client, "bearer_token_hash").unwrap();
    let original_expiration = find_string_value(first_client, "bearer_token_expires_at").unwrap();
    let generated_bearer_token = first_result
        .generated_bearer_token
        .as_deref()
        .ok_or("missing generated bearer token")?;
    let (generated_token_id, generated_secret) =
        split_full_token(generated_bearer_token).ok_or("invalid generated token format")?;
    assert_eq!(generated_token_id, original_token_id);
    assert!(is_lower_hex(generated_token_id));
    assert!(is_lower_hex(generated_secret));
    assert_eq!(
        original_token_hash,
        write::sha256_hex(generated_bearer_token)
    );
    assert_eq!(first_result.bearer_token_expires_at, original_expiration);
    assert!(!first_contents.contains(generated_bearer_token));
    assert!(!first_client.contains("api_key ="));
    assert!(!first_client.contains("api_key_expires_at ="));
    let client_with_notes = first_client.replacen(
        "bearer_token_expires_at = \"",
        "# preserve this client comment\nbearer_token_expires_at = \"",
        1,
    );
    let client_with_notes = client_with_notes.replacen(
        "api_access = { projects = \"read\" }\n",
        "api_access = { projects = \"read\" }\nlabel = \"keep-me\"\n",
        1,
    );
    let client_header = "[clients.partner]\n";
    let client_start = first_contents.find(client_header).unwrap();
    let client_body_start = client_start + client_header.len();
    let client_end = client_body_start + first_client.len();
    let mut injected_contents = String::with_capacity(first_contents.len() + 64);
    injected_contents.push_str(&first_contents[..client_body_start]);
    injected_contents.push_str(&client_with_notes);
    injected_contents.push_str(&first_contents[client_end..]);
    fs::write(&config_path, injected_contents)?;

    let second_result = write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            bearer_token: None,
            bearer_token_expires_at: None,
            access: write::ClientAccessUpsert::ApiAccess(std::collections::BTreeMap::from([
                ("projects".to_string(), AccessLevel::Read),
                ("billing".to_string(), AccessLevel::Write),
            ])),
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let client = section_body(&contents, "clients.partner").unwrap();

    assert_eq!(contents.matches("[clients.partner]").count(), 1);
    assert!(contents.contains("# preserve this client comment"));
    assert_eq!(
        find_string_value(client, "bearer_token_id").as_deref(),
        Some(original_token_id.as_str())
    );
    assert_eq!(
        find_string_value(client, "bearer_token_hash").as_deref(),
        Some(original_token_hash.as_str())
    );
    assert_eq!(
        find_string_value(client, "bearer_token_expires_at").as_deref(),
        Some(original_expiration.as_str())
    );
    assert!(second_result.generated_bearer_token.is_none());
    assert_eq!(second_result.bearer_token_expires_at, original_expiration);

    let api_access = find_inline_table_value(client, "api_access").unwrap();
    assert_eq!(
        api_access,
        vec![
            ("billing".to_string(), "write".to_string()),
            ("projects".to_string(), "read".to_string()),
        ]
    );
    assert_eq!(
        find_string_value(client, "label").as_deref(),
        Some("keep-me")
    );
    assert!(!client.contains("api_key ="));
    assert!(!client.contains("api_key_expires_at ="));

    Ok(())
}

#[test]
fn config_add_client_prints_generated_bearer_token_once_and_persists_only_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = { projects = "read" }

[groups]

[apis.projects]
base_url = "https://projects.internal.example/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "upstream-token"
timeout_ms = 5000
"#,
    )?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "partner",
            "--api-access",
            "projects=read",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    assert_eq!(
        stdout
            .matches("Generated token for client 'partner': ")
            .count(),
        1
    );
    assert_eq!(
        stdout
            .matches("Generated token for client 'default': ")
            .count(),
        0
    );
    let full_token = parse_printed_token(&stdout, "partner").ok_or("missing printed token")?;
    let (token_id, secret) = split_full_token(&full_token).ok_or("invalid token format")?;
    assert!(is_lower_hex(token_id));
    assert!(is_lower_hex(secret));

    let contents = fs::read_to_string(&config_path)?;
    let client = section_body(&contents, "clients.partner").unwrap();

    assert_eq!(
        find_string_value(client, "bearer_token_id").as_deref(),
        Some(token_id)
    );
    assert_eq!(
        find_string_value(client, "bearer_token_hash").as_deref(),
        Some(write::sha256_hex(&full_token).as_str())
    );
    assert!(!contents.contains(&full_token));
    assert!(!client.contains("api_key ="));
    assert!(!client.contains("api_key_expires_at ="));

    let expires_at = find_string_value(client, "bearer_token_expires_at").unwrap();
    let expires_at_unix = parse_rfc3339_z(&expires_at).unwrap();
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let min_expected = now_unix + Duration::from_secs(170 * 24 * 60 * 60).as_secs();
    let max_expected = now_unix + Duration::from_secs(190 * 24 * 60 * 60).as_secs();
    assert!(
        expires_at_unix >= min_expected,
        "expiry too early: {expires_at}"
    );
    assert!(
        expires_at_unix <= max_expected,
        "expiry too late: {expires_at}"
    );

    Ok(())
}

#[test]
fn upsert_group_preserves_unrelated_content_and_writes_stable_api_access_order()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"# keep this comment
[clients.default]
bearer_token_id = "default-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[groups]
"#,
    )?;

    write::upsert_group(
        &config_path,
        &GroupUpsert {
            name: "partner-write".to_string(),
            api_access: std::collections::BTreeMap::from([(
                "projects".to_string(),
                AccessLevel::Read,
            )]),
        },
        None,
    )?;

    let first_contents = fs::read_to_string(&config_path)?;
    let first_group = section_body(&first_contents, "groups.partner-write").unwrap();
    let group_with_notes = first_group.replacen(
        "api_access = { projects = \"read\" }\n",
        "# preserve this group comment\napi_access = { projects = \"read\" }\nlabel = \"keep-me\"\n",
        1,
    );
    let group_header = "[groups.partner-write]\n";
    let group_start = first_contents.find(group_header).unwrap();
    let group_body_start = group_start + group_header.len();
    let group_end = group_body_start + first_group.len();
    let mut injected_contents = String::with_capacity(first_contents.len() + 64);
    injected_contents.push_str(&first_contents[..group_body_start]);
    injected_contents.push_str(&group_with_notes);
    injected_contents.push_str(&first_contents[group_end..]);
    fs::write(&config_path, injected_contents)?;

    write::upsert_group(
        &config_path,
        &GroupUpsert {
            name: "partner-write".to_string(),
            api_access: std::collections::BTreeMap::from([
                ("projects".to_string(), AccessLevel::Read),
                ("billing".to_string(), AccessLevel::Write),
            ]),
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let group = section_body(&contents, "groups.partner-write").unwrap();

    assert!(contents.starts_with("# keep this comment"));
    assert_eq!(contents.matches("[groups.partner-write]").count(), 1);
    assert!(contents.contains("# preserve this group comment"));
    assert_eq!(
        find_inline_table_value(group, "api_access"),
        Some(vec![
            ("billing".to_string(), "write".to_string()),
            ("projects".to_string(), "read".to_string()),
        ])
    );
    assert_eq!(
        find_string_value(group, "label").as_deref(),
        Some("keep-me")
    );

    Ok(())
}

#[test]
fn add_client_writes_group_and_removes_stale_inline_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.partner]
bearer_token_id = "partner-token"
bearer_token_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = { projects = "read" }
note = "keep-me"

[groups.partner-write]
api_access = { projects = "write" }

[apis.projects]
base_url = "https://projects.internal.example/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "upstream-token"
timeout_ms = 5000
"#,
    )?;

    write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            bearer_token: None,
            bearer_token_expires_at: None,
            access: write::ClientAccessUpsert::Group("partner-write".to_string()),
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;
    let client = section_body(&contents, "clients.partner").unwrap();

    assert_eq!(
        find_string_value(client, "group").as_deref(),
        Some("partner-write")
    );
    assert_eq!(
        find_string_value(client, "note").as_deref(),
        Some("keep-me")
    );
    assert!(!client.contains("api_access ="));

    Ok(())
}

#[test]
fn add_client_rejects_duplicate_bearer_token_id_before_writing()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[clients.default]
bearer_token_id = "shared-token"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[groups]

[apis]
"#,
    )?;

    let error = write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            bearer_token: Some("shared-token.partner-secret".to_string()),
            bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_string()),
            access: write::ClientAccessUpsert::ApiAccess(std::collections::BTreeMap::new()),
        },
        None,
    )
    .expect_err("duplicate bearer token id should fail");

    assert_eq!(
        error.to_string(),
        "clients.partner.bearer_token_id duplicates another configured client bearer_token_id"
    );

    let contents = fs::read_to_string(&config_path)?;
    assert!(!contents.contains("[clients.partner]"));

    Ok(())
}

fn tempdir() -> Result<TestTempDir, Box<dyn std::error::Error>> {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    path.push(format!(
        "gate-agent-config-writing-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(TestTempDir { path })
}

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn section_body<'a>(contents: &'a str, section_name: &str) -> Option<&'a str> {
    let header = format!("[{section_name}]");
    let start = contents.find(&header)?;
    let after_header = &contents[start + header.len()..];
    let body_start = after_header
        .find('\n')
        .map(|offset| start + header.len() + offset + 1)?;
    let rest = &contents[body_start..];
    let next_header = rest
        .find("\n[")
        .map(|offset| body_start + offset + 1)
        .unwrap_or(contents.len());
    Some(&contents[body_start..next_header])
}

fn find_string_value(section_body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = ");

    section_body.lines().find_map(|line| {
        let value = line.trim().strip_prefix(&prefix)?;
        unquote(value)
    })
}

fn find_integer_value(section_body: &str, key: &str) -> Option<i64> {
    let prefix = format!("{key} = ");

    section_body.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .and_then(|value| value.parse::<i64>().ok())
    })
}

fn find_inline_table_value(section_body: &str, key: &str) -> Option<Vec<(String, String)>> {
    let prefix = format!("{key} = ");
    let value = section_body
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(str::to_owned))?;
    let trimmed = value.trim();

    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
        return None;
    }

    let inner = trimmed[1..trimmed.len() - 1].trim();

    if inner.is_empty() {
        return Some(Vec::new());
    }

    inner
        .split(',')
        .map(|item| {
            let (key, value) = item.split_once('=')?;
            Some((key.trim().to_string(), unquote(value.trim())?))
        })
        .collect::<Option<Vec<_>>>()
}

fn unquote(value: &str) -> Option<String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
}

fn parse_printed_token(stdout: &str, client_name: &str) -> Option<String> {
    let prefix = format!("Generated token for client '{client_name}': ");

    stdout
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
}

fn split_full_token(value: &str) -> Option<(&str, &str)> {
    let (token_id, secret) = value.split_once('.')?;

    if token_id.is_empty() || secret.is_empty() || secret.contains('.') {
        return None;
    }

    Some((token_id, secret))
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
}

fn parse_rfc3339_z(value: &str) -> Result<u64, &'static str> {
    if value.len() != 20 {
        return Err("unexpected timestamp length");
    }

    let year: i32 = value[0..4].parse().map_err(|_| "invalid year")?;
    let month: u32 = value[5..7].parse().map_err(|_| "invalid month")?;
    let day: u32 = value[8..10].parse().map_err(|_| "invalid day")?;
    let hour: u64 = value[11..13].parse().map_err(|_| "invalid hour")?;
    let minute: u64 = value[14..16].parse().map_err(|_| "invalid minute")?;
    let second: u64 = value[17..19].parse().map_err(|_| "invalid second")?;

    if &value[4..5] != "-"
        || &value[7..8] != "-"
        || &value[10..11] != "T"
        || &value[13..14] != ":"
        || &value[16..17] != ":"
        || &value[19..20] != "Z"
    {
        return Err("unexpected timestamp format");
    }

    let days = days_from_civil(year, month, day)?;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Result<u64, &'static str> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err("invalid calendar date");
    }

    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_index = month as i32;
    let day_index = day as i32;
    let day_of_year =
        (153 * (month_index + if month_index > 2 { -3 } else { 9 }) + 2) / 5 + day_index - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    u64::try_from(days).map_err(|_| "date predates unix epoch")
}
