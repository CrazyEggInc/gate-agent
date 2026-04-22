use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::{Mutex, OnceLock};

use age::Encryptor;
use assert_cmd::Command;
use gate_agent::commands::config::{
    ConfigApiArgs, ConfigClientArgs, ConfigGroupArgs, ConfigInitArgs, ConfigRotateSecretArgs,
    ConfigShowArgs, ConfigValidateArgs, apply_api, apply_client, apply_group, init,
    rotate_client_secret, show, validate,
};
use gate_agent::config::app_config::DEFAULT_LOG_LEVEL;
use gate_agent::config::password::PASSWORD_ENV_VAR;
use gate_agent::config::path::CONFIG_ENV_VAR;
use gate_agent::config::secrets::AccessLevel;
use gate_agent::config::write::{self, ClientAccessUpsert, ClientUpsert, sha256_hex};
use secrecy::{ExposeSecret, SecretString};
use tempfile::tempdir;
use toml::Value;

const TEST_KEYRING_FILE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_FILE";
const TEST_KEYRING_STORE_FAILURE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_STORE_FAILURE";
const TEST_PROMPT_INPUTS_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_INPUTS";
const TEST_PROMPT_PASSWORD_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_PASSWORD";
const DISABLE_INTERACTIVE_ENV_VAR: &str = "GATE_AGENT_DISABLE_INTERACTIVE";

const VALID_BEARER_VALIDATE_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "0011223344556677"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[groups]

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#;

const INVALID_BEARER_VALIDATE_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "0011223344556677"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[groups]

[apis]
"#;

const STDIN_BEARER_VALIDATE_CONFIG: &str = r#"
[clients.default]
bearer_token_id = "8899aabbccddeeff"
bearer_token_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { stdin-projects = "read" }

[groups]

[apis.stdin-projects]
base_url = "https://stdin-projects.internal.example"
headers = { x-api-key = "stdin-projects-secret-value" }
timeout_ms = 5000
"#;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    original_dir: PathBuf,
    original_env: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn enter(current_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let original_dir = std::env::current_dir()?;
        let original_env = tracked_env_vars()
            .into_iter()
            .map(|name| (name, std::env::var(name).ok()))
            .collect();

        std::env::set_current_dir(current_dir)?;
        unsafe {
            std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, "1");
        }

        Ok(Self {
            original_dir,
            original_env,
        })
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_dir);

        unsafe {
            for (name, value) in &self.original_env {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn tracked_env_vars() -> Vec<&'static str> {
    vec![
        CONFIG_ENV_VAR,
        "HOME",
        PASSWORD_ENV_VAR,
        "VISUAL",
        "EDITOR",
        TEST_KEYRING_FILE_ENV_VAR,
        TEST_KEYRING_STORE_FAILURE_ENV_VAR,
        TEST_PROMPT_INPUTS_ENV_VAR,
        TEST_PROMPT_PASSWORD_ENV_VAR,
        DISABLE_INTERACTIVE_ENV_VAR,
    ]
}

fn load_toml(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?.parse::<Value>()?)
}

fn write_text(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;
    Ok(())
}

fn write_binary_age_config(
    path: &Path,
    contents: &str,
    password: &SecretString,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let encryptor = Encryptor::with_user_passphrase(password.clone());
    let mut output = Vec::new();
    let mut writer = encryptor.wrap_output(&mut output)?;
    std::io::Write::write_all(&mut writer, contents.as_bytes())?;
    writer.finish()?;
    std::fs::write(path, output)?;

    Ok(())
}

fn set_test_prompt_inputs(inputs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::set_var(TEST_PROMPT_INPUTS_ENV_VAR, serde_json::to_string(inputs)?);
    }

    Ok(())
}

fn keyring_entry_key(config_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let canonical = if config_path.exists() {
        config_path.canonicalize()?
    } else if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
        parent.canonicalize()?.join(
            config_path
                .file_name()
                .ok_or("config path missing file name")?,
        )
    } else {
        return Err("config path missing parent".into());
    };
    Ok(format!("gate-agent::config:{}", canonical.display()))
}

fn seed_keyring_password(
    keyring_path: &Path,
    config_path: &Path,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = keyring_entry_key(config_path)?;

    if let Some(parent) = keyring_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(
        keyring_path,
        serde_json::json!({ key: password }).to_string(),
    )?;

    Ok(())
}

fn read_keyring_store(
    keyring_path: &Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if !keyring_path.exists() {
        return Ok(serde_json::json!({}));
    }

    Ok(serde_json::from_str(&std::fs::read_to_string(
        keyring_path,
    )?)?)
}

fn keyring_password_for(
    keyring_path: &Path,
    config_path: &Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let store = read_keyring_store(keyring_path)?;
    let key = keyring_entry_key(config_path)?;

    Ok(store
        .as_object()
        .and_then(|entries| entries.get(&key))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_gate_agent_in_tty(
    current_dir: &Path,
    args: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let binary = assert_cmd::cargo::cargo_bin("gate-agent");
    let binary = binary.to_str().ok_or("cargo_bin path must be utf-8")?;
    let mut command = shell_quote(binary);

    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }

    Ok(ProcessCommand::new("script")
        .current_dir(current_dir)
        .arg("-qec")
        .arg(command)
        .arg("/dev/null")
        .output()?)
}

fn run_gate_agent_in_tty_with_input(
    current_dir: &Path,
    args: &[&str],
    input: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let binary = assert_cmd::cargo::cargo_bin("gate-agent");
    let binary = binary.to_str().ok_or("cargo_bin path must be utf-8")?;
    let python = r#"
import json, os, pty, select, subprocess, sys

binary = sys.argv[1]
args = sys.argv[2:]
master, slave = pty.openpty()
proc = subprocess.Popen(
    [binary, *args],
    stdin=slave,
    stdout=subprocess.PIPE,
    stderr=slave,
)
os.close(slave)

input_data = os.environ.get('GATE_AGENT_TTY_INPUT', '').encode()
if input_data:
    os.write(master, input_data)

stderr_chunks = []
while True:
    ready, _, _ = select.select([master], [], [], 0.05)
    if master in ready:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            chunk = b''
        if chunk:
            stderr_chunks.append(chunk)
            continue
        break
    if proc.poll() is not None:
        break

stdout = proc.stdout.read() if proc.stdout is not None else b''
if proc.stdout is not None:
    proc.stdout.close()

while True:
    try:
        chunk = os.read(master, 4096)
    except OSError:
        break
    if not chunk:
        break
    stderr_chunks.append(chunk)

os.close(master)
sys.stdout.write(json.dumps({
    'code': proc.wait(),
    'stdout': stdout.decode('utf-8', errors='replace'),
    'stderr': b''.join(stderr_chunks).decode('utf-8', errors='replace'),
}))
"#;

    let output = ProcessCommand::new("python3")
        .current_dir(current_dir)
        .arg("-c")
        .arg(python)
        .arg(binary)
        .args(args)
        .env("GATE_AGENT_TTY_INPUT", input)
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "python PTY helper failed: status={:?}, stderr={} ",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let rendered: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let code = rendered
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .ok_or("PTY helper missing exit code")? as i32;
    let stdout = rendered
        .get("stdout")
        .and_then(serde_json::Value::as_str)
        .ok_or("PTY helper missing stdout")?
        .as_bytes()
        .to_vec();
    let stderr = rendered
        .get("stderr")
        .and_then(serde_json::Value::as_str)
        .ok_or("PTY helper missing stderr")?
        .as_bytes()
        .to_vec();

    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout,
        stderr,
    })
}

fn table_at<'a>(value: &'a Value, path: &[&str]) -> &'a toml::map::Map<String, Value> {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing key: {key}"));
    }

    current
        .as_table()
        .unwrap_or_else(|| panic!("expected table at {}", path.join(".")))
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing key: {key}"));
    }

    current
        .as_str()
        .unwrap_or_else(|| panic!("expected string at {}", path.join(".")))
}

#[test]
fn config_init_generates_default_bearer_token_and_persists_only_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
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
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "default");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "default", &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    let default_client = table_at(&config, &["clients", "default"]);
    assert_eq!(
        default_client.get("group").and_then(Value::as_str),
        Some("local-default")
    );
    assert!(default_client.get("api_access").is_none());
    assert!(config.get("server").and_then(Value::as_table).is_some());
    assert!(config.get("apis").and_then(Value::as_table).is_some());
    let default_group = table_at(&config, &["groups", "local-default"]);
    let default_group_api_access = default_group
        .get("api_access")
        .and_then(Value::as_table)
        .expect("groups.local-default.api_access should be table");
    assert!(default_group_api_access.is_empty());
    assert_eq!(string_at(&config, &["server", "bind"]), "127.0.0.1");
    assert_eq!(
        config
            .get("server")
            .and_then(|value| value.get("port"))
            .and_then(Value::as_integer),
        Some(8787)
    );
    validate(ConfigValidateArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    Ok(())
}

#[test]
fn config_client_tty_prompts_show_access_mode_options_and_existing_groups()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join(".secrets");

    unsafe {
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
        std::env::remove_var(DISABLE_INTERACTIVE_ENV_VAR);
        std::env::set_var("HOME", temp_dir.path().join("home"));
    }

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    apply_group(ConfigGroupArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner-readonly".to_owned(),
        api_access: vec!["projects=read".to_owned()],
    })?;
    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: Some("partner-readonly".to_owned()),
        api_access: vec![],
    })?;

    let output = run_gate_agent_in_tty_with_input(
        &workspace,
        &[
            "config",
            "client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "partner",
            "--bearer-token-expires-at",
            "2030-01-02T03:04:05Z",
        ],
        "\n\n",
    )?;

    assert!(output.status.success(), "{output:?}");

    let stderr = String::from_utf8(output.stderr)?.replace("\r", "");
    assert!(
        stderr.contains("Access mode (default: group; options: group, inline):"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Group name — existing groups: local-default, partner-readonly (default: partner-readonly):"),
        "{stderr}"
    );

    Ok(())
}

#[test]
fn config_add_client_generates_bearer_token_when_missing_and_prints_it_once()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

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
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "partner");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "partner", &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_add_client_generates_bearer_token_with_explicit_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--name",
            "partner",
            "--bearer-token-expires-at",
            "2031-02-03T04:05:06Z",
            "--api-access",
            "projects=write",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "partner");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "partner", &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_eq!(
        string_at(&config, &["clients", "partner", "bearer_token_expires_at"]),
        "2031-02-03T04:05:06Z"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "write"
    );

    Ok(())
}

#[test]
fn config_rotate_client_secret_rotates_plaintext_client_and_preserves_existing_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;
    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })?;
    let before = load_toml(&config_path)?;
    let old_id = string_at(&before, &["clients", "partner", "bearer_token_id"]).to_owned();
    let old_hash = string_at(&before, &["clients", "partner", "bearer_token_hash"]).to_owned();

    let outcome = rotate_client_secret(ConfigRotateSecretArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: None,
    })?;

    assert_eq!(outcome.path, config_path);
    assert_eq!(outcome.bearer_token_expires_at, "2031-02-03T04:05:06Z");
    assert!(split_full_token(&outcome.generated_bearer_token).is_some());

    let after = load_toml(&config_path)?;
    assert_client_metadata_matches(&after, "partner", &outcome.generated_bearer_token);
    assert_no_plain_bearer_token_persisted(&after, &outcome.generated_bearer_token);
    assert_ne!(
        string_at(&after, &["clients", "partner", "bearer_token_id"]),
        old_id
    );
    assert_ne!(
        string_at(&after, &["clients", "partner", "bearer_token_hash"]),
        old_hash
    );
    assert_eq!(
        string_at(&after, &["clients", "partner", "bearer_token_expires_at"]),
        "2031-02-03T04:05:06Z"
    );
    assert_eq!(
        string_at(&after, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_rotate_client_secret_updates_expiry_when_override_is_supplied()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;
    apply_group(ConfigGroupArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner-readonly".to_owned(),
        api_access: vec!["projects=read".to_owned()],
    })?;
    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: Some("partner-readonly".to_owned()),
        api_access: vec![],
    })?;

    let outcome = rotate_client_secret(ConfigRotateSecretArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2034-05-06T07:08:09Z".to_owned()),
    })?;

    assert_eq!(outcome.path, config_path);
    assert_eq!(outcome.bearer_token_expires_at, "2034-05-06T07:08:09Z");

    let after = load_toml(&config_path)?;
    assert_client_metadata_matches(&after, "partner", &outcome.generated_bearer_token);
    assert_eq!(
        string_at(&after, &["clients", "partner", "bearer_token_expires_at"]),
        "2034-05-06T07:08:09Z"
    );
    assert_eq!(
        string_at(&after, &["clients", "partner", "group"]),
        "partner-readonly"
    );
    assert!(
        table_at(&after, &["clients", "partner"])
            .get("api_access")
            .is_none()
    );

    Ok(())
}

#[test]
fn config_add_client_updates_expiry_without_rotating_existing_bearer_token()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    let existing_token = "partnertoken01.abcdefabcdefabcdefabcdefabcdefabcdef";

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;
    write::upsert_client(
        &config_path,
        &ClientUpsert {
            name: "partner".to_owned(),
            bearer_token: Some(existing_token.to_owned()),
            bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
            access: ClientAccessUpsert::ApiAccess(
                [("projects".to_owned(), AccessLevel::Read)]
                    .into_iter()
                    .collect(),
            ),
        },
        None,
    )?;

    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=write".to_owned()],
    })?;

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "partner", existing_token);
    assert_eq!(
        string_at(&config, &["clients", "partner", "bearer_token_expires_at"]),
        "2031-02-03T04:05:06Z"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "write"
    );

    Ok(())
}

#[test]
fn encrypted_config_rotate_client_secret_preserves_password_workflow()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = SecretString::from("top-secret-password".to_owned());

    write::init_config(&config_path, true, Some(&password))?;
    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })?;

    let outcome = rotate_client_secret(ConfigRotateSecretArgs {
        config: Some(config_path.clone()),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: None,
    })?;

    let raw = std::fs::read_to_string(&config_path)?;
    assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;

    assert_eq!(outcome.bearer_token_expires_at, "2031-02-03T04:05:06Z");
    assert_client_metadata_matches(&config, "partner", &outcome.generated_bearer_token);
    assert_no_plain_bearer_token_persisted(&config, &outcome.generated_bearer_token);
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn encrypted_config_rotate_client_secret_cli_uses_keyring_password_after_show_backfill()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let config_path_str = config_path.to_str().ok_or("non-utf8 config path")?;
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = "top-secret-password";

    let init_output = Command::cargo_bin("gate-agent")?
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env_remove(TEST_KEYRING_FILE_ENV_VAR)
        .env_remove(TEST_KEYRING_STORE_FAILURE_ENV_VAR)
        .args([
            "config",
            "init",
            "--config",
            config_path_str,
            "--encrypted",
            "--password",
            password,
        ])
        .output()?;
    assert!(init_output.status.success(), "{init_output:?}");

    let add_client_output = Command::cargo_bin("gate-agent")?
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env_remove(TEST_KEYRING_FILE_ENV_VAR)
        .env_remove(TEST_KEYRING_STORE_FAILURE_ENV_VAR)
        .args([
            "config",
            "client",
            "--config",
            config_path_str,
            "--password",
            password,
            "--name",
            "partner",
            "--api-access",
            "projects=read",
        ])
        .output()?;
    assert!(add_client_output.status.success(), "{add_client_output:?}");

    if keyring_path.exists() {
        std::fs::remove_file(&keyring_path)?;
    }

    let show_output = Command::cargo_bin("gate-agent")?
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env(TEST_KEYRING_FILE_ENV_VAR, &keyring_path)
        .env_remove(TEST_KEYRING_STORE_FAILURE_ENV_VAR)
        .args([
            "config",
            "show",
            "--config",
            config_path_str,
            "--password",
            password,
        ])
        .output()?;
    assert!(show_output.status.success(), "{show_output:?}");

    let shown_config = String::from_utf8(show_output.stdout)?.parse::<Value>()?;
    assert_eq!(
        string_at(
            &shown_config,
            &["clients", "partner", "api_access", "projects"]
        ),
        "read"
    );
    assert_eq!(
        keyring_password_for(&keyring_path, &config_path)?,
        Some(password.to_owned())
    );

    let before_id = string_at(&shown_config, &["clients", "partner", "bearer_token_id"]).to_owned();
    let before_hash =
        string_at(&shown_config, &["clients", "partner", "bearer_token_hash"]).to_owned();

    let rotate_output = Command::cargo_bin("gate-agent")?
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env(TEST_KEYRING_FILE_ENV_VAR, &keyring_path)
        .env_remove(TEST_KEYRING_STORE_FAILURE_ENV_VAR)
        .args([
            "config",
            "client",
            "rotate-secret",
            "--config",
            config_path_str,
            "--name",
            "partner",
        ])
        .output()?;
    assert!(rotate_output.status.success(), "{rotate_output:?}");

    let rotate_stdout = String::from_utf8(rotate_output.stdout)?;
    let tokens = printed_tokens(&rotate_stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "partner");

    let show_after_output = Command::cargo_bin("gate-agent")?
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env(TEST_KEYRING_FILE_ENV_VAR, &keyring_path)
        .env_remove(TEST_KEYRING_STORE_FAILURE_ENV_VAR)
        .args(["config", "show", "--config", config_path_str])
        .output()?;
    assert!(show_after_output.status.success(), "{show_after_output:?}");

    let updated_config = String::from_utf8(show_after_output.stdout)?.parse::<Value>()?;
    let rotated_token = &tokens[0].1;
    assert_client_metadata_matches(&updated_config, "partner", rotated_token);
    assert_no_plain_bearer_token_persisted(&updated_config, rotated_token);
    assert_eq!(
        string_at(
            &updated_config,
            &["clients", "partner", "api_access", "projects"]
        ),
        "read"
    );
    assert_ne!(
        string_at(&updated_config, &["clients", "partner", "bearer_token_id"]),
        before_id
    );
    assert_ne!(
        string_at(
            &updated_config,
            &["clients", "partner", "bearer_token_hash"]
        ),
        before_hash
    );
    assert_eq!(
        keyring_password_for(&keyring_path, &config_path)?,
        Some(password.to_owned())
    );
    assert!(
        std::fs::read_to_string(&config_path)?.starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    );

    Ok(())
}

#[test]
fn config_show_reads_binary_age_config_with_password() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = SecretString::from("top-secret-password".to_owned());

    write_binary_age_config(&config_path, VALID_BEARER_VALIDATE_CONFIG, &password)?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "show",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--password",
            password.expose_secret(),
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let shown = String::from_utf8(output.stdout)?;
    assert_eq!(shown, VALID_BEARER_VALIDATE_CONFIG);
    let config = shown.parse::<Value>()?;
    assert_eq!(
        string_at(&config, &["clients", "default", "bearer_token_id"]),
        "0011223344556677"
    );
    assert_eq!(
        string_at(&config, &["clients", "default", "api_access", "projects"]),
        "read"
    );
    assert_eq!(String::from_utf8(output.stderr)?, "");

    Ok(())
}

#[test]
fn encrypted_config_rotate_client_secret_supports_binary_age_config()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let config_path_str = config_path.to_str().ok_or("non-utf8 config path")?;
    let password = "top-secret-password";

    write_binary_age_config(
        &config_path,
        VALID_BEARER_VALIDATE_CONFIG,
        &SecretString::from(password.to_owned()),
    )?;

    let before_show_output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "show",
            "--config",
            config_path_str,
            "--password",
            password,
        ])
        .output()?;
    assert!(
        before_show_output.status.success(),
        "{before_show_output:?}"
    );
    let before_config = String::from_utf8(before_show_output.stdout)?.parse::<Value>()?;
    let before_id =
        string_at(&before_config, &["clients", "default", "bearer_token_id"]).to_owned();
    let before_hash =
        string_at(&before_config, &["clients", "default", "bearer_token_hash"]).to_owned();

    let rotate_output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "client",
            "rotate-secret",
            "--config",
            config_path_str,
            "--password",
            password,
            "--name",
            "default",
        ])
        .output()?;
    assert!(rotate_output.status.success(), "{rotate_output:?}");

    let rotate_stdout = String::from_utf8(rotate_output.stdout)?;
    let tokens = printed_tokens(&rotate_stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "default");

    let show_after_output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "show",
            "--config",
            config_path_str,
            "--password",
            password,
        ])
        .output()?;
    assert!(show_after_output.status.success(), "{show_after_output:?}");

    let updated_config = String::from_utf8(show_after_output.stdout)?.parse::<Value>()?;
    let rotated_token = &tokens[0].1;
    assert_client_metadata_matches(&updated_config, "default", rotated_token);
    assert_no_plain_bearer_token_persisted(&updated_config, rotated_token);
    assert_eq!(
        string_at(
            &updated_config,
            &["clients", "default", "api_access", "projects"]
        ),
        "read"
    );
    assert_ne!(
        string_at(&updated_config, &["clients", "default", "bearer_token_id"]),
        before_id
    );
    assert_ne!(
        string_at(
            &updated_config,
            &["clients", "default", "bearer_token_hash"]
        ),
        before_hash
    );

    Ok(())
}

#[test]
fn config_rotate_client_secret_fails_for_missing_client_without_writing()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;
    let before = std::fs::read(&config_path)?;

    let error = rotate_client_secret(ConfigRotateSecretArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: None,
    })
    .expect_err("missing client should fail");

    assert_eq!(error.to_string(), "client 'partner' not found");
    assert_eq!(std::fs::read(&config_path)?, before);

    Ok(())
}

#[test]
fn config_rotate_client_secret_does_not_bootstrap_missing_config()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("missing.toml");

    let error = rotate_client_secret(ConfigRotateSecretArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        bearer_token_expires_at: None,
    })
    .expect_err("missing config should fail");

    let message = error.to_string();
    assert!(message.contains("failed to read config file"), "{message}");
    assert!(
        message.contains(config_path.to_str().ok_or("non-utf8 config path")?),
        "{message}"
    );
    assert!(!config_path.exists());

    Ok(())
}

#[test]
fn config_add_client_merges_repeated_and_comma_separated_api_access_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec![
            "projects=read,billing=write".to_owned(),
            "reports=read".to_owned(),
        ],
    })?;

    let config = load_toml(&config_path)?;

    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "billing"]),
        "write"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "reports"]),
        "read"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_conflicting_duplicate_api_access_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned(), "projects=write".to_owned()],
    })
    .expect_err("conflicting api access should fail");

    assert_eq!(
        error.to_string(),
        "conflicting api_access entries for api 'projects'"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_invalid_api_access_level_with_clear_message()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=admin".to_owned()],
    })
    .expect_err("invalid api access level should fail");

    assert_eq!(
        error.to_string(),
        "api_access level 'admin' must be one of: read, write"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_leading_empty_segment_in_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec![",projects=read".to_owned()],
    })
    .expect_err("leading empty segment should be rejected");

    assert_eq!(
        error.to_string(),
        "api_access entries cannot contain empty comma-separated segments"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_trailing_comma_in_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read,".to_owned()],
    })
    .expect_err("trailing comma should be rejected");

    assert_eq!(
        error.to_string(),
        "api_access entries cannot contain empty comma-separated segments"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_doubled_comma_in_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read,,billing=write".to_owned()],
    })
    .expect_err("doubled comma should be rejected");

    assert_eq!(
        error.to_string(),
        "api_access entries cannot contain empty comma-separated segments"
    );

    Ok(())
}

#[test]
fn config_add_client_rejects_malformed_segment_in_comma_separated_api_access_arg()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: None,
        api_access: vec!["projects=read,billing".to_owned()],
    })
    .expect_err("malformed comma-separated segment should be rejected");

    assert_eq!(
        error.to_string(),
        "invalid api_access entry 'billing'; expected api=level"
    );

    Ok(())
}

#[test]
fn config_add_client_writes_group_reference_without_inline_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    write_text(
        &config_path,
        concat!(
            "[clients.default]\n",
            "bearer_token_id = \"0011223344556677\"\n",
            "bearer_token_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "bearer_token_expires_at = \"2030-01-02T03:04:05Z\"\n",
            "api_access = {}\n\n",
            "[groups.partner-readonly]\n",
            "api_access = { projects = \"read\" }\n\n",
            "[apis.projects]\n",
            "base_url = \"https://projects.internal.example\"\n",
            "headers = { x-api-key = \"projects-secret-value\" }\n",
            "timeout_ms = 5000\n",
        ),
    )?;

    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
        group: Some("partner-readonly".to_owned()),
        api_access: vec![],
    })?;

    let config = load_toml(&config_path)?;
    let client = table_at(&config, &["clients", "partner"]);

    assert_eq!(
        client.get("group").and_then(Value::as_str),
        Some("partner-readonly")
    );
    assert!(client.get("api_access").is_none());
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_add_client_uses_prompted_name_and_existing_group()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Group(gate_agent::cli::ConfigGroupArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("partner-readonly".to_owned()),
                api_access: vec!["projects=read".to_owned()],
            }),
        },
    ))?;

    set_test_prompt_inputs(&["partner", "group", "partner-readonly"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Client(gate_agent::cli::ConfigClientArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
                group: None,
                api_access: vec![],
                command: None,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let client = table_at(&config, &["clients", "partner"]);

    assert_eq!(
        client.get("group").and_then(Value::as_str),
        Some("partner-readonly")
    );
    assert!(client.get("api_access").is_none());
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_add_client_falls_back_to_prompted_inline_api_access_when_group_is_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&["partner", "", "projects=read,reports=write"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Client(gate_agent::cli::ConfigClientArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
                group: None,
                api_access: vec![],
                command: None,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let client = table_at(&config, &["clients", "partner"]);

    assert!(client.get("group").is_none());
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "reports"]),
        "write"
    );
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_add_group_uses_prompt_seam_for_missing_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&["readonly", "projects=read,reports=write"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Group(gate_agent::cli::ConfigGroupArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                api_access: vec![],
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;

    assert_eq!(
        string_at(&config, &["groups", "readonly", "api_access", "projects"]),
        "read"
    );
    assert_eq!(
        string_at(&config, &["groups", "readonly", "api_access", "reports"]),
        "write"
    );

    Ok(())
}

#[test]
fn config_add_group_rejects_empty_api_access_entries() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = apply_group(ConfigGroupArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "readonly".to_owned(),
        api_access: vec![],
    })
    .expect_err("empty group api_access should fail");

    assert_eq!(
        error.to_string(),
        "api_access entries are required for groups"
    );

    Ok(())
}

#[test]
fn config_add_api_uses_prompt_seam_for_missing_fields() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&[
        "projects",
        "https://projects.internal.example/api",
        "authorization=Bearer local-upstream-token",
    ])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                base_url: None,
                header: vec![],
                timeout_ms: Some(5_000),
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer local-upstream-token"
    );
    assert!(api.get("auth_scheme").is_none());

    Ok(())
}

#[test]
fn config_add_api_skips_header_prompts_and_persistence_when_headers_are_none()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    set_test_prompt_inputs(&["projects", "https://projects.internal.example/api", "none"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                base_url: None,
                header: vec![],
                timeout_ms: Some(5_000),
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert!(api.get("headers").is_none());
    assert!(api.get("auth_scheme").is_none());

    Ok(())
}

#[test]
fn config_update_api_interactive_preserves_existing_no_headers_when_prompt_left_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: None,
        timeout_ms: Some(5_000),
    })?;

    set_test_prompt_inputs(&["", ""])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: None,
                header: vec![],
                timeout_ms: None,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert!(api.get("headers").is_none());
    assert!(api.get("auth_scheme").is_none());

    Ok(())
}

#[test]
fn config_update_api_interactive_preserves_existing_header_values_with_commas_when_prompt_left_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec![
            "authorization=Bearer token,with,commas".to_owned(),
            "x-api-key=secret-key".to_owned(),
        ]),
        timeout_ms: Some(5_000),
    })?;

    set_test_prompt_inputs(&["", ""])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: None,
                header: vec![],
                timeout_ms: None,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;

    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer token,with,commas"
    );
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "x-api-key"]),
        "secret-key"
    );

    Ok(())
}

#[test]
fn config_update_api_interactive_preserves_existing_regular_table_headers_when_prompt_left_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    write_text(
        &config_path,
        concat!(
            "[clients.default]\n",
            "bearer_token_id = \"0011223344556677\"\n",
            "bearer_token_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "bearer_token_expires_at = \"2030-01-02T03:04:05Z\"\n",
            "api_access = { projects = \"read\" }\n\n",
            "[groups]\n\n",
            "[apis.projects]\n",
            "base_url = \"https://projects.internal.example/api\"\n",
            "timeout_ms = 5000\n\n",
            "[apis.projects.headers]\n",
            "authorization = \"Bearer token,with,commas\"\n",
            "x-api-key = \"secret-key\"\n",
        ),
    )?;

    set_test_prompt_inputs(&["", ""])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: None,
                header: vec![],
                timeout_ms: None,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;

    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer token,with,commas"
    );
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "x-api-key"]),
        "secret-key"
    );

    Ok(())
}

#[test]
fn config_update_api_rejects_non_string_regular_table_header_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(
        &config_path,
        concat!(
            "[clients.default]\n",
            "bearer_token_id = \"0011223344556677\"\n",
            "bearer_token_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "bearer_token_expires_at = \"2030-01-02T03:04:05Z\"\n",
            "api_access = { projects = \"read\" }\n\n",
            "[groups]\n\n",
            "[apis.projects]\n",
            "base_url = \"https://projects.internal.example/api\"\n",
            "timeout_ms = 5000\n\n",
            "[apis.projects.headers]\n",
            "authorization = 123\n",
        ),
    )?;

    let error = apply_api(ConfigApiArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: None,
        headers: None,
        timeout_ms: None,
    })
    .expect_err("non-string regular table header should fail");

    assert_eq!(
        error.to_string(),
        "apis.projects.headers.authorization must be a string"
    );

    Ok(())
}

#[test]
fn config_update_api_interactive_clears_existing_headers_when_prompt_is_none()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec![
            "authorization=Bearer top-secret".to_owned(),
            "x-api-key=secret-key".to_owned(),
        ]),
        timeout_ms: Some(5_000),
    })?;

    set_test_prompt_inputs(&["", "none"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: None,
                header: vec![],
                timeout_ms: None,
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert!(api.get("headers").is_none());

    Ok(())
}

#[test]
fn config_add_api_non_interactive_allows_missing_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: Some("https://projects.internal.example/api".to_owned()),
                header: vec![],
                timeout_ms: Some(5_000),
            }),
        },
    ))?;

    let config = load_toml(&config_path)?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert!(api.get("headers").is_none());

    Ok(())
}

#[test]
fn config_add_api_rejects_malformed_header_non_interactively()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: Some("https://projects.internal.example/api".to_owned()),
                header: vec!["authorization".to_owned()],
                timeout_ms: Some(5_000),
            }),
        },
    ))
    .expect_err("malformed header should fail");

    assert_eq!(
        error.to_string(),
        "header must be formatted as <name>=<value>; repeat --header for multiple upstream headers"
    );

    Ok(())
}

#[test]
fn config_add_api_rejects_duplicate_header_keys_after_normalization()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: Some("projects".to_owned()),
                base_url: Some("https://projects.internal.example/api".to_owned()),
                header: vec![
                    "Authorization=Bearer one".to_owned(),
                    "authorization=Bearer two".to_owned(),
                ],
                timeout_ms: Some(5_000),
            }),
        },
    ))
    .expect_err("duplicate normalized headers should fail");

    assert_eq!(
        error.to_string(),
        "apis.projects.headers contains duplicate header 'authorization'"
    );

    Ok(())
}

#[test]
fn config_add_api_persists_one_header() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec![
            " authorization = Bearer local-upstream-token ".to_owned(),
        ]),
        timeout_ms: Some(5_000),
    })?;

    let config = load_toml(&config_path)?;
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer local-upstream-token"
    );

    Ok(())
}

#[test]
fn config_add_api_persists_multiple_headers() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec![
            "authorization=Bearer local-upstream-token".to_owned(),
            "x-api-key = secret-value ".to_owned(),
        ]),
        timeout_ms: Some(5_000),
    })?;

    let config = load_toml(&config_path)?;
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer local-upstream-token"
    );
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "x-api-key"]),
        "secret-value"
    );

    Ok(())
}

#[test]
fn config_add_api_rejects_invalid_header_name() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let error = apply_api(ConfigApiArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec!["bad header=value".to_owned()]),
        timeout_ms: Some(5_000),
    })
    .expect_err("invalid header name should fail");

    assert!(
        error
            .to_string()
            .starts_with("apis.projects.headers is invalid:"),
        "{error}"
    );

    Ok(())
}

#[test]
fn config_add_api_rejects_invalid_header_value() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let error = apply_api(ConfigApiArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec!["authorization=bad\nvalue".to_owned()]),
        timeout_ms: Some(5_000),
    })
    .expect_err("invalid header value should fail");

    assert!(
        error
            .to_string()
            .starts_with("apis.projects.headers is invalid:"),
        "{error}"
    );

    Ok(())
}

#[test]
fn config_add_client_implicit_config_creation_prints_default_and_client_tokens_once()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.toml");

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
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].0, "default");
    assert_eq!(tokens[1].0, "partner");

    let config = load_toml(&config_path)?;
    assert_client_metadata_matches(&config, "default", &tokens[0].1);
    assert_client_metadata_matches(&config, "partner", &tokens[1].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[1].1);

    Ok(())
}

#[test]
fn config_add_api_invalid_mutation_does_not_create_missing_config()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("missing.toml");

    let error = apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "projects".to_owned(),
        delete: false,
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec!["authorization".to_owned()]),
        timeout_ms: Some(5_000),
    })
    .expect_err("invalid api mutation should fail");

    assert_eq!(
        error.to_string(),
        "header must be formatted as <name>=<value>; repeat --header for multiple upstream headers"
    );
    assert!(!config_path.exists());

    Ok(())
}

#[test]
fn config_add_group_invalid_mutation_does_not_create_missing_config()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("missing.toml");

    let error = apply_group(ConfigGroupArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "readonly".to_owned(),
        delete: false,
        api_access: vec![],
    })
    .expect_err("invalid group mutation should fail");

    assert_eq!(
        error.to_string(),
        "api_access entries are required for groups"
    );
    assert!(!config_path.exists());

    Ok(())
}

#[test]
fn config_add_client_invalid_mutation_does_not_create_missing_config()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("missing.toml");

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        name: "partner".to_owned(),
        delete: false,
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec![],
    })
    .expect_err("invalid client mutation should fail");

    assert_eq!(
        error.to_string(),
        "config client requires --group or --api-access in non-interactive sessions"
    );
    assert!(!config_path.exists());

    Ok(())
}

#[test]
fn config_add_client_rejects_invalid_bearer_token_timestamp_message()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, VALID_BEARER_VALIDATE_CONFIG)?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2030-02-31T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })
    .expect_err("invalid timestamp should fail");

    assert_eq!(
        error.to_string(),
        "invalid bearer_token_expires_at: invalid calendar date"
    );

    Ok(())
}

#[test]
fn config_validate_prefers_stdin_for_valid_bearer_config() -> Result<(), Box<dyn std::error::Error>>
{
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, INVALID_BEARER_VALIDATE_CONFIG)?;

    let output = Command::cargo_bin("gate-agent")?
        .env_remove(CONFIG_ENV_VAR)
        .env_remove(PASSWORD_ENV_VAR)
        .env_remove(TEST_PROMPT_INPUTS_ENV_VAR)
        .env_remove(TEST_PROMPT_PASSWORD_ENV_VAR)
        .env_remove(DISABLE_INTERACTIVE_ENV_VAR)
        .args([
            "config",
            "validate",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ])
        .write_stdin(STDIN_BEARER_VALIDATE_CONFIG)
        .output()?;

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "config is valid\n");
    assert_eq!(String::from_utf8(output.stderr)?, "");

    Ok(())
}

#[test]
fn config_validate_returns_json_error_for_invalid_bearer_config()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.toml");

    write_text(&config_path, INVALID_BEARER_VALIDATE_CONFIG)?;

    let error = validate(ConfigValidateArgs {
        config: Some(config_path.clone()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })
    .expect_err("invalid config should fail");

    assert_eq!(
        error.to_string(),
        r#"{"errors":[{"message":"clients.default.api_access contains unknown api 'projects'"}]}"#
    );

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "validate",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ])
        .output()?;

    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, "");
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "{\"errors\":[{\"message\":\"clients.default.api_access contains unknown api 'projects'\"}]}\n"
    );

    Ok(())
}

#[test]
fn encrypted_config_add_client_preserves_password_workflow()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = SecretString::from("top-secret-password".to_owned());

    write::init_config(&config_path, true, Some(&password))?;

    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })?;

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;

    assert_client_has_bearer_metadata(&config, "partner");
    assert_eq!(
        string_at(&config, &["clients", "partner", "api_access", "projects"]),
        "read"
    );

    Ok(())
}

#[test]
fn encrypted_config_add_client_removes_stale_keyring_password_after_failed_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = SecretString::from("top-secret-password".to_owned());

    write::init_config(&config_path, true, Some(&password))?;
    unsafe {
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }
    seed_keyring_password(&keyring_path, &config_path, "stale-password")?;

    let error = apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })
    .expect_err("stale keyring password should fail decrypt");

    assert!(
        error
            .to_string()
            .contains("invalid password for config file")
    );
    assert_eq!(keyring_password_for(&keyring_path, &config_path)?, None);

    Ok(())
}

#[test]
fn encrypted_config_add_client_backfills_keyring_after_flag_password_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = "top-secret-password";

    write::init_config(
        &config_path,
        true,
        Some(&SecretString::from(password.to_owned())),
    )?;
    unsafe {
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }

    apply_client(ConfigClientArgs {
        config: Some(config_path.clone()),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner".to_owned(),
        bearer_token_expires_at: Some("2031-02-03T04:05:06Z".to_owned()),
        group: None,
        api_access: vec!["projects=read".to_owned()],
    })?;

    assert_eq!(
        keyring_password_for(&keyring_path, &config_path)?,
        Some(password.to_owned())
    );

    Ok(())
}

#[test]
fn encrypted_config_add_api_removes_stale_keyring_password_after_failed_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = SecretString::from("top-secret-password".to_owned());

    write::init_config(&config_path, true, Some(&password))?;
    unsafe {
        std::env::remove_var(PASSWORD_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_PASSWORD_ENV_VAR);
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }
    seed_keyring_password(&keyring_path, &config_path, "stale-password")?;

    let error = apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec!["authorization=Bearer local-upstream-token".to_owned()]),
        timeout_ms: Some(5_000),
    })
    .expect_err("stale keyring password should fail decrypt");

    assert!(
        error
            .to_string()
            .contains("invalid password for config file")
    );
    assert_eq!(keyring_password_for(&keyring_path, &config_path)?, None);

    Ok(())
}

#[test]
fn encrypted_config_add_api_preserves_password_workflow() -> Result<(), Box<dyn std::error::Error>>
{
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = SecretString::from("top-secret-password".to_owned());

    write::init_config(&config_path, true, Some(&password))?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec!["authorization=Bearer local-upstream-token".to_owned()]),
        timeout_ms: Some(5_000),
    })?;

    let raw = std::fs::read_to_string(&config_path)?;
    assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.expose_secret().to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer local-upstream-token"
    );
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(5_000)
    );

    Ok(())
}

#[test]
fn encrypted_config_add_api_backfills_keyring_after_flag_password_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = "top-secret-password";

    write::init_config(
        &config_path,
        true,
        Some(&SecretString::from(password.to_owned())),
    )?;
    unsafe {
        std::env::remove_var(PASSWORD_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_PASSWORD_ENV_VAR);
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "projects".to_owned(),
        base_url: Some("https://projects.internal.example/api".to_owned()),
        headers: Some(vec!["authorization=Bearer local-upstream-token".to_owned()]),
        timeout_ms: Some(5_000),
    })?;

    assert_eq!(
        keyring_password_for(&keyring_path, &config_path)?,
        Some(password.to_owned())
    );

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;
    let api = table_at(&config, &["apis", "projects"]);

    assert_eq!(
        api.get("base_url").and_then(Value::as_str),
        Some("https://projects.internal.example/api")
    );
    assert_eq!(
        string_at(&config, &["apis", "projects", "headers", "authorization"]),
        "Bearer local-upstream-token"
    );
    assert_eq!(
        api.get("timeout_ms").and_then(Value::as_integer),
        Some(5_000)
    );

    Ok(())
}

#[test]
fn encrypted_config_add_group_backfills_keyring_after_flag_password_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = "top-secret-password";

    write::init_config(
        &config_path,
        true,
        Some(&SecretString::from(password.to_owned())),
    )?;
    unsafe {
        std::env::remove_var(PASSWORD_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_PASSWORD_ENV_VAR);
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }

    apply_group(ConfigGroupArgs {
        config: Some(config_path.clone()),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner-readonly".to_owned(),
        api_access: vec!["projects=read".to_owned()],
    })?;

    assert_eq!(
        keyring_password_for(&keyring_path, &config_path)?,
        Some(password.to_owned())
    );

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;
    assert_eq!(
        string_at(
            &config,
            &["groups", "partner-readonly", "api_access", "projects"]
        ),
        "read"
    );

    Ok(())
}

#[test]
fn encrypted_config_add_client_group_prompt_backfills_keyring_after_flag_password_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    let password = "top-secret-password";

    write::init_config(
        &config_path,
        true,
        Some(&SecretString::from(password.to_owned())),
    )?;
    unsafe {
        std::env::remove_var(PASSWORD_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_PASSWORD_ENV_VAR);
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }

    apply_group(ConfigGroupArgs {
        config: Some(config_path.clone()),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
        delete: false,
        name: "partner-readonly".to_owned(),
        api_access: vec!["projects=read".to_owned()],
    })?;
    std::fs::remove_file(&keyring_path)?;

    set_test_prompt_inputs(&["partner", "group", "partner-readonly"])?;

    gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Client(gate_agent::cli::ConfigClientArgs {
                config: Some(config_path.clone()),
                password: Some(password.to_owned()),
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                bearer_token_expires_at: Some("2030-01-02T03:04:05Z".to_owned()),
                group: None,
                api_access: vec![],
                command: None,
            }),
        },
    ))?;

    assert_eq!(
        keyring_password_for(&keyring_path, &config_path)?,
        Some(password.to_owned())
    );

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;
    let client = table_at(&config, &["clients", "partner"]);

    assert_eq!(
        client.get("group").and_then(Value::as_str),
        Some("partner-readonly")
    );
    assert!(client.get("api_access").is_none());
    assert_client_has_bearer_metadata(&config, "partner");

    Ok(())
}

#[test]
fn config_show_prints_plaintext_contents() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join(".secrets");
    let contents = concat!(
        "[clients.default]\n",
        "bearer_token_id = \"0011223344556677\"\n",
        "bearer_token_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        "bearer_token_expires_at = \"2030-01-02T03:04:05Z\"\n",
        "api_access = {}\n\n",
        "[groups]\n\n",
        "[apis]\n",
    );
    std::fs::write(&config_path, contents)?;

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    assert_eq!(shown, contents);

    Ok(())
}

#[test]
fn config_init_prompts_for_default_encryption_and_config_path_when_omitted_in_tty()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    let home_dir = temp_dir.path().join("home");
    let keyring_path = temp_dir.path().join("test-keyring.json");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    unsafe {
        std::env::set_var("HOME", &home_dir);
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
        std::env::set_var(TEST_PROMPT_PASSWORD_ENV_VAR, "top-secret-password");
    }
    set_test_prompt_inputs(&["", "nested/interactive.secrets", "0.0.0.0", "9999"])?;

    let output = run_gate_agent_in_tty(&workspace, &["config", "init"])?;
    let config_path = workspace.join("nested/interactive.secrets");

    assert!(output.status.success(), "{output:?}");
    assert!(config_path.exists());
    assert!(
        std::fs::read_to_string(&config_path)?.starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    );
    assert!(!keyring_path.exists());

    let shown = show(ConfigShowArgs {
        config: Some(config_path.clone()),
        password: Some("top-secret-password".to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;
    assert_eq!(string_at(&config, &["server", "bind"]), "0.0.0.0");
    assert_eq!(
        config
            .get("server")
            .and_then(|value| value.get("port"))
            .and_then(Value::as_integer),
        Some(9999)
    );

    let stderr = String::from_utf8(output.stderr)?;
    let normalized_stderr = stderr.replace("\r", "");
    assert!(
        normalized_stderr.is_empty()
            || (normalized_stderr.contains("Write encrypted config? [Y/n]")
                && normalized_stderr.contains("Config path")
                && normalized_stderr.contains("default: ~/.config/gate-agent/secrets")
                && normalized_stderr.contains(
                    "Server bind (default: 127.0.0.1; remote setups should use 0.0.0.0)"
                )
                && normalized_stderr.contains("Server port (default: 8787)"))
    );

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "default");

    Ok(())
}

#[test]
fn config_add_api_respects_disable_interactive_env_even_in_tty()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let workspace = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let _env = EnvGuard::enter(&workspace)?;
    let config_path = workspace.join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    unsafe {
        std::env::set_var(DISABLE_INTERACTIVE_ENV_VAR, "1");
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }

    let output = run_gate_agent_in_tty(
        &workspace,
        &[
            "config",
            "api",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
        ],
    )?;

    assert!(!output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("config api requires --name in non-interactive sessions"),
        "{combined}"
    );
    assert!(!combined.contains("Auth header"), "{combined}");

    Ok(())
}

#[test]
fn config_init_removes_existing_keyring_password_for_new_encrypted_config()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("encrypted.secrets");
    let keyring_path = temp_dir.path().join("test-keyring.json");

    std::fs::create_dir_all(temp_dir.path())?;
    unsafe {
        std::env::set_var(TEST_KEYRING_FILE_ENV_VAR, &keyring_path);
        std::env::remove_var(TEST_KEYRING_STORE_FAILURE_ENV_VAR);
    }

    seed_keyring_password(&keyring_path, &config_path, "stale-password")?;

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "init",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--encrypted",
            "--password",
            "new-password",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let store = read_keyring_store(&keyring_path)?;
    assert!(
        !store.to_string().contains("stale-password"),
        "stale password should be removed: {store}"
    );

    Ok(())
}

#[test]
fn config_questionnaire_commands_fail_non_interactively_without_required_input()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    unsafe {
        std::env::remove_var(CONFIG_ENV_VAR);
        std::env::remove_var(TEST_PROMPT_INPUTS_ENV_VAR);
    }
    let config_path = temp_dir.path().join(".secrets");

    init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    let client_error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Client(gate_agent::cli::ConfigClientArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                bearer_token_expires_at: None,
                group: None,
                api_access: vec![],
                command: None,
            }),
        },
    ))
    .expect_err("missing add-client input should fail");

    let group_error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Group(gate_agent::cli::ConfigGroupArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                api_access: vec![],
            }),
        },
    ))
    .expect_err("missing add-group input should fail");

    let api_error = gate_agent::commands::run(gate_agent::cli::Command::Config(
        gate_agent::cli::ConfigArgs {
            command: gate_agent::cli::ConfigCommand::Api(gate_agent::cli::ConfigApiArgs {
                config: Some(config_path.clone()),
                password: None,
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                delete: false,
                name: None,
                base_url: None,
                header: vec![],
                timeout_ms: Some(5_000),
            }),
        },
    ))
    .expect_err("missing add-api input should fail");

    assert_eq!(
        client_error.to_string(),
        "config client requires --name in non-interactive sessions"
    );
    assert_eq!(
        group_error.to_string(),
        "config group requires --name in non-interactive sessions"
    );
    assert_eq!(
        api_error.to_string(),
        "config api requires --name in non-interactive sessions"
    );

    Ok(())
}

#[test]
fn config_add_client_bootstraps_encrypted_config_when_password_is_supplied()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp_dir = tempdir()?;
    let _env = EnvGuard::enter(temp_dir.path())?;
    let config_path = temp_dir.path().join("gate-agent.secrets");
    let password = "top-secret-password";

    let output = Command::cargo_bin("gate-agent")?
        .args([
            "config",
            "client",
            "--config",
            config_path.to_str().ok_or("non-utf8 config path")?,
            "--password",
            password,
            "--name",
            "partner",
            "--bearer-token-expires-at",
            "2031-02-03T04:05:06Z",
            "--api-access",
            "projects=read",
        ])
        .output()?;

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout)?;
    let tokens = printed_tokens(&stdout)?;
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].0, "default");
    assert_eq!(tokens[1].0, "partner");

    let raw = std::fs::read_to_string(&config_path)?;
    assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let shown = show(ConfigShowArgs {
        config: Some(config_path),
        password: Some(password.to_owned()),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;
    let config = shown.parse::<Value>()?;

    assert_client_metadata_matches(&config, "default", &tokens[0].1);
    assert_client_metadata_matches(&config, "partner", &tokens[1].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[0].1);
    assert_no_plain_bearer_token_persisted(&config, &tokens[1].1);

    Ok(())
}

#[test]
fn config_init_function_still_creates_explicit_config_path()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("nested/custom/secrets.toml");

    let written_path = init(ConfigInitArgs {
        config: Some(config_path.clone()),
        encrypted: false,
        password: None,
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    })?;

    assert_eq!(written_path, config_path);
    assert!(written_path.exists());

    let config = load_toml(&written_path)?;
    assert!(config.get("auth").is_none());
    assert_eq!(string_at(&config, &["server", "bind"]), "127.0.0.1");
    assert_eq!(
        config
            .get("server")
            .and_then(|value| value.get("port"))
            .and_then(Value::as_integer),
        Some(8787)
    );
    assert!(config.get("groups").and_then(Value::as_table).is_some());
    assert!(config.get("apis").and_then(Value::as_table).is_some());

    Ok(())
}

fn printed_tokens(stdout: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(parse_printed_token)
        .map(Ok)
        .collect()
}

fn parse_printed_token(line: &str) -> Option<(String, String)> {
    let prefix = "Generated token for client '";
    let rest = line.strip_prefix(prefix)?;
    let (client_name, token) = rest.split_once("': ")?;
    split_full_token(token)?;
    Some((client_name.to_owned(), token.to_owned()))
}

fn split_full_token(value: &str) -> Option<(&str, &str)> {
    let (token_id, secret) = value.split_once('.')?;

    if token_id.is_empty() || secret.is_empty() || secret.contains('.') {
        return None;
    }

    Some((token_id, secret))
}

fn assert_client_metadata_matches(config: &Value, client_name: &str, full_token: &str) {
    let client = table_at(config, &["clients", client_name]);
    let (token_id, _) = split_full_token(full_token).expect("token format");

    assert_eq!(
        client.get("bearer_token_id").and_then(Value::as_str),
        Some(token_id)
    );
    assert_eq!(
        client.get("bearer_token_hash").and_then(Value::as_str),
        Some(sha256_hex(full_token).as_str())
    );
    assert!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str)
            .is_some()
    );
}

fn assert_client_has_bearer_metadata(config: &Value, client_name: &str) {
    let client = table_at(config, &["clients", client_name]);

    assert!(
        client
            .get("bearer_token_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        client
            .get("bearer_token_hash")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() == 64)
    );
    assert!(
        client
            .get("bearer_token_expires_at")
            .and_then(Value::as_str)
            .is_some()
    );
}

fn assert_no_plain_bearer_token_persisted(config: &Value, full_token: &str) {
    let rendered = toml::to_string(config).expect("toml render");
    assert!(!rendered.contains(full_token));
}
