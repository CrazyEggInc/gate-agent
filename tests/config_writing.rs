use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gate_agent::config::secrets::AccessLevel;
use gate_agent::config::write::{self, ApiUpsert, ClientUpsert};
use secrecy::SecretString;

#[test]
fn init_config_writes_minimal_generated_document_and_creates_parent_dirs()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("nested/config/gate-agent.toml");

    write::init_config(&config_path, false, None)?;

    assert!(config_path.exists());

    let contents = fs::read_to_string(&config_path)?;
    let auth = section_body(&contents, "auth").unwrap();
    assert_eq!(
        find_string_value(auth, "issuer").as_deref(),
        Some(write::DEFAULT_AUTH_ISSUER)
    );
    assert_eq!(
        find_string_value(auth, "audience").as_deref(),
        Some(write::DEFAULT_AUTH_AUDIENCE)
    );

    let signing_secret = find_string_value(auth, "signing_secret").unwrap();
    assert!(signing_secret.len() >= 32);
    assert!(signing_secret.chars().all(|ch| ch.is_ascii_hexdigit()));

    let default_client = section_body(&contents, "clients.default").unwrap();

    let api_key = find_string_value(default_client, "api_key").unwrap();
    assert!(api_key.len() >= 24);
    assert!(api_key.chars().all(|ch| ch.is_ascii_hexdigit()));

    let expires_at = find_string_value(default_client, "api_key_expires_at").unwrap();
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
        find_inline_table_value(default_client, "api_access"),
        Some(vec![])
    );

    let groups = section_body(&contents, "groups").unwrap();
    assert!(groups.trim().is_empty());

    let apis = section_body(&contents, "apis").unwrap();
    assert!(apis.trim().is_empty());

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
    assert!(loaded.toml.contains("[auth]"));
    assert!(loaded.toml.contains("[clients.default]"));

    Ok(())
}

#[test]
fn add_api_upserts_single_entry_without_clobbering_unrelated_content()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"# keep this comment
[auth]
issuer = "issuer"
audience = "audience"
signing_secret = "secret"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    write::upsert_api(
        &config_path,
        &ApiUpsert {
            name: "projects".to_string(),
            base_url: "https://projects.internal.example/api".to_string(),
            auth_header: "authorization".to_string(),
            auth_scheme: Some("Bearer".to_string()),
            auth_value: "first-token".to_string(),
            timeout_ms: 5_000,
        },
        None,
    )?;

    let first_contents = fs::read_to_string(&config_path)?;
    let first_projects = section_body(&first_contents, "apis.projects").unwrap();
    let projects_with_notes = first_projects.replacen(
        "auth_value = \"first-token\"\n",
        "# preserve this api comment\nauth_value = \"first-token\"\nnotes = \"keep-me\"\n",
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
            auth_header: "x-service-token".to_string(),
            auth_scheme: None,
            auth_value: "second-token".to_string(),
            timeout_ms: 7_500,
        },
        None,
    )?;

    let contents = fs::read_to_string(&config_path)?;

    assert!(contents.starts_with("# keep this comment"));
    assert_eq!(contents.matches("[apis.projects]").count(), 1);
    assert!(!contents.contains("auth_scheme = \"Bearer\""));
    assert!(contents.contains("# preserve this api comment"));

    let projects = section_body(&contents, "apis.projects").unwrap();

    assert_eq!(
        find_string_value(projects, "base_url").as_deref(),
        Some("https://projects.internal.example/v2")
    );
    assert_eq!(
        find_string_value(projects, "auth_header").as_deref(),
        Some("x-service-token")
    );
    assert_eq!(
        find_string_value(projects, "auth_value").as_deref(),
        Some("second-token")
    );
    assert_eq!(
        find_string_value(projects, "notes").as_deref(),
        Some("keep-me")
    );
    assert_eq!(find_integer_value(projects, "timeout_ms"), Some(7_500));

    Ok(())
}

#[test]
fn add_client_writes_inline_api_access_in_stable_order_and_preserves_existing_key()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[auth]
issuer = "issuer"
audience = "audience"
signing_secret = "secret"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2030-01-01T00:00:00Z"
api_access = {}

[groups]

[apis]
"#,
    )?;

    write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            api_key: None,
            api_key_expires_at: None,
            access: write::ClientAccessUpsert::ApiAccess(std::collections::BTreeMap::from([(
                "projects".to_string(),
                AccessLevel::Read,
            )])),
        },
        None,
    )?;

    let first_contents = fs::read_to_string(&config_path)?;
    let first_client = section_body(&first_contents, "clients.partner").unwrap();
    let original_key = find_string_value(first_client, "api_key").unwrap();
    let original_expiration = find_string_value(first_client, "api_key_expires_at").unwrap();
    let client_with_notes = first_client.replacen(
        "api_key_expires_at = \"",
        "# preserve this client comment\napi_key_expires_at = \"",
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

    write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            api_key: None,
            api_key_expires_at: None,
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
        find_string_value(client, "api_key").as_deref(),
        Some(original_key.as_str())
    );
    assert_eq!(
        find_string_value(client, "api_key_expires_at").as_deref(),
        Some(original_expiration.as_str())
    );

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

    Ok(())
}

#[test]
fn add_client_writes_group_and_removes_stale_inline_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    fs::write(
        &config_path,
        r#"[auth]
issuer = "issuer"
audience = "audience"
signing_secret = "secret"

[clients.partner]
api_key = "partner-key"
api_key_expires_at = "2030-01-01T00:00:00Z"
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
            api_key: None,
            api_key_expires_at: None,
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
