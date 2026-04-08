#[path = "../src/config/write.rs"]
mod write;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use write::{ApiUpsert, ClientUpsert};

#[test]
fn init_config_writes_minimal_generated_document_and_creates_parent_dirs()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("nested/config/gate-agent.toml");

    write::init_config(&config_path)?;

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
        find_array_value(default_client, "allowed_apis").unwrap(),
        Vec::<String>::new()
    );

    let apis = section_body(&contents, "apis").unwrap();
    assert!(apis.trim().is_empty());

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
allowed_apis = []

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
fn add_client_upserts_single_entry_and_preserves_existing_key_when_omitted_on_update()
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
allowed_apis = []

[apis]
"#,
    )?;

    write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_string(),
            api_key: None,
            api_key_expires_at: None,
            allowed_apis: vec!["projects".to_string()],
        },
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
        "allowed_apis = [\"projects\"]\n",
        "allowed_apis = [\"projects\"]\nlabel = \"keep-me\"\n",
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
            allowed_apis: vec!["billing".to_string(), "projects".to_string()],
        },
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

    let allowed_apis = find_array_value(client, "allowed_apis").unwrap();
    assert_eq!(allowed_apis, vec!["billing", "projects"]);
    assert_eq!(
        find_string_value(client, "label").as_deref(),
        Some("keep-me")
    );

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

fn find_array_value(section_body: &str, key: &str) -> Option<Vec<String>> {
    let prefix = format!("{key} = ");
    let value = section_body
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(str::to_owned))?;
    let trimmed = value.trim();

    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return None;
    }

    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }

    inner
        .split(',')
        .map(|item| unquote(item.trim()))
        .collect::<Option<Vec<_>>>()
}

fn unquote(value: &str) -> Option<String> {
    if !(value.starts_with('"') && value.ends_with('"')) {
        return None;
    }

    let mut result = String::new();
    let mut chars = value[1..value.len() - 1].chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            result.push(chars.next()?);
        } else {
            result.push(ch);
        }
    }

    Some(result)
}

fn parse_rfc3339_z(timestamp: &str) -> Option<u64> {
    if timestamp.len() != 20 || !timestamp.ends_with('Z') {
        return None;
    }

    let year = timestamp.get(0..4)?.parse::<i32>().ok()?;
    let month = timestamp.get(5..7)?.parse::<u32>().ok()?;
    let day = timestamp.get(8..10)?.parse::<u32>().ok()?;
    let hour = timestamp.get(11..13)?.parse::<u64>().ok()?;
    let minute = timestamp.get(14..16)?.parse::<u64>().ok()?;
    let second = timestamp.get(17..19)?.parse::<u64>().ok()?;

    if timestamp.as_bytes().get(4) != Some(&b'-')
        || timestamp.as_bytes().get(7) != Some(&b'-')
        || timestamp.as_bytes().get(10) != Some(&b'T')
        || timestamp.as_bytes().get(13) != Some(&b':')
        || timestamp.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    Some(days * 24 * 60 * 60 + hour * 60 * 60 + minute * 60 + second)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let year = i64::from(year) - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let month_of_year = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_of_year + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    u64::try_from(days).ok()
}
