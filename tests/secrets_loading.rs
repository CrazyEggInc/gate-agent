use std::any::Any;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use keyring::Credential;
use keyring::credential::{CredentialApi, CredentialBuilderApi, CredentialPersistence};
use secrecy::ExposeSecret;

use gate_agent::config::secrets::{AccessLevel, BearerTokenHash, SecretsConfig};
use gate_agent::config::{
    crypto,
    password::{PASSWORD_ENV_VAR, PasswordArgs, PasswordSource, resolve_for_encrypted_create},
};
use tempfile::tempdir;

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

fn write_encrypted_secrets_file(
    plaintext: &str,
    password: &str,
) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    let encrypted =
        crypto::encrypt_string(plaintext, &secrecy::SecretString::from(password.to_owned()))?;
    std::fs::write(&secrets_file, encrypted)?;
    Ok((temp_dir, secrets_file))
}

fn password_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct PasswordEnvGuard {
    previous: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl PasswordEnvGuard {
    fn clear(keys: &[&'static str]) -> Self {
        let lock = password_test_lock()
            .lock()
            .expect("password test mutex poisoned");
        let previous = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect::<Vec<_>>();

        for key in keys {
            unsafe {
                std::env::remove_var(key);
            }
        }

        Self {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for PasswordEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            match value {
                Some(value) => unsafe {
                    std::env::set_var(key, value);
                },
                None => unsafe {
                    std::env::remove_var(key);
                },
            }
        }

        keyring::set_default_credential_builder(keyring::default::default_credential_builder());
    }
}

#[derive(Default)]
struct SharedKeyringStore {
    secrets: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    next_errors: Mutex<BTreeMap<(String, String), keyring::Error>>,
}

impl SharedKeyringStore {
    fn set_password(&self, service: &str, user: &str, password: &str) {
        self.secrets
            .lock()
            .expect("shared keyring secrets mutex poisoned")
            .insert(
                (service.to_owned(), user.to_owned()),
                password.as_bytes().to_vec(),
            );
    }

    fn fail_next(&self, service: &str, user: &str, error: keyring::Error) {
        self.next_errors
            .lock()
            .expect("shared keyring errors mutex poisoned")
            .insert((service.to_owned(), user.to_owned()), error);
    }

    fn get_password(&self, service: &str, user: &str) -> Result<String, keyring::Error> {
        self.secrets
            .lock()
            .expect("shared keyring secrets mutex poisoned")
            .get(&(service.to_owned(), user.to_owned()))
            .cloned()
            .ok_or(keyring::Error::NoEntry)
            .and_then(|value| {
                String::from_utf8(value)
                    .map_err(|error| keyring::Error::PlatformFailure(Box::new(error)))
            })
    }

    fn take_error(&self, key: &(String, String)) -> Option<keyring::Error> {
        self.next_errors
            .lock()
            .expect("shared keyring errors mutex poisoned")
            .remove(key)
    }
}

#[derive(Clone)]
struct SharedKeyringCredential {
    store: Arc<SharedKeyringStore>,
    key: (String, String),
}

impl CredentialApi for SharedKeyringCredential {
    fn set_secret(&self, secret: &[u8]) -> Result<(), keyring::Error> {
        if let Some(error) = self.store.take_error(&self.key) {
            return Err(error);
        }

        self.store
            .secrets
            .lock()
            .expect("shared keyring secrets mutex poisoned")
            .insert(self.key.clone(), secret.to_vec());
        Ok(())
    }

    fn get_secret(&self) -> Result<Vec<u8>, keyring::Error> {
        if let Some(error) = self.store.take_error(&self.key) {
            return Err(error);
        }

        self.store
            .secrets
            .lock()
            .expect("shared keyring secrets mutex poisoned")
            .get(&self.key)
            .cloned()
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> Result<(), keyring::Error> {
        if let Some(error) = self.store.take_error(&self.key) {
            return Err(error);
        }

        self.store
            .secrets
            .lock()
            .expect("shared keyring secrets mutex poisoned")
            .remove(&self.key)
            .map(|_| ())
            .ok_or(keyring::Error::NoEntry)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct SharedKeyringBuilder {
    store: Arc<SharedKeyringStore>,
}

impl CredentialBuilderApi for SharedKeyringBuilder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> Result<Box<Credential>, keyring::Error> {
        Ok(Box::new(SharedKeyringCredential {
            store: Arc::clone(&self.store),
            key: (service.to_owned(), user.to_owned()),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }
}

fn install_shared_keyring() -> Arc<SharedKeyringStore> {
    let store = Arc::new(SharedKeyringStore::default());
    keyring::set_default_credential_builder(Box::new(SharedKeyringBuilder {
        store: Arc::clone(&store),
    }));
    store
}

fn keyring_user_for(path: &Path) -> String {
    format!(
        "config:{}",
        path.canonicalize()
            .expect("config path should canonicalize")
            .display()
    )
}

fn valid_config_body() -> &'static str {
    r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "write" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#
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

    assert!(!sample_contents.contains("[auth]"));
    assert!(!sample_contents.contains("api_key"));
    assert!(sample_contents.contains("bearer_token_id = \"default\""));
    assert!(sample_contents.contains("bearer_token_hash"));
    assert!(sample_contents.contains("bearer_token_expires_at = \"2036-10-08T12:00:00Z\""));
    assert!(sample_contents.contains("group = \"local-default\""));
    assert!(sample_contents.contains("[groups.local-default]"));
    assert_eq!(client.bearer_token_id, "default");
    assert_eq!(
        client.bearer_token_hash.as_str(),
        "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
    );
    assert_eq!(
        client.bearer_token_expires_at.as_str(),
        "2036-10-08T12:00:00Z"
    );
    assert_eq!(
        client.api_access,
        [("projects".to_string(), AccessLevel::Read)]
            .into_iter()
            .collect()
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
    let (_temp_dir, secrets_file) = write_secrets_file(valid_config_body())?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let client = config
        .clients
        .get("default")
        .expect("default client config");
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(config.clients.len(), 1);
    assert_eq!(client.bearer_token_id, "default");
    assert_eq!(
        client.bearer_token_hash.as_str(),
        "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
    );
    assert!(client.bearer_token_hash.matches_token("default.s3cr3t"));
    assert_eq!(
        client.bearer_token_expires_at.as_str(),
        "2026-10-08T12:00:00Z"
    );
    assert_eq!(
        client.bearer_token_expires_at.unix_timestamp(),
        1_791_460_800
    );
    assert_eq!(client.bearer_token_expires_at.nanosecond(), 0);
    assert_eq!(
        client.api_access,
        [("billing".to_string(), AccessLevel::Write)]
            .into_iter()
            .collect()
    );
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");
    assert_eq!(api.auth_header.as_str(), "authorization");
    assert_eq!(api.auth_scheme.as_deref(), Some("Bearer"));
    assert_eq!(api.auth_value.expose_secret(), "billing-secret-token");
    assert_eq!(api.timeout_ms, 5000);
    let client_by_token_id = config
        .client_by_bearer_token_id("default")
        .expect("client by token id");
    assert_eq!(client_by_token_id.bearer_token_id, "default");
    assert!(
        client_by_token_id
            .bearer_token_hash
            .matches_token("default.s3cr3t")
    );

    Ok(())
}

#[test]
fn secrets_config_parses_valid_toml_from_source_label() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecretsConfig::parse(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "read" }

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

    assert_eq!(client.bearer_token_id, "default");
    assert_eq!(
        client.bearer_token_expires_at.as_str(),
        "2026-10-08T12:00:00Z"
    );
    assert_eq!(
        client.api_access,
        [("billing".to_string(), AccessLevel::Read)]
            .into_iter()
            .collect()
    );
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
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "write"
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
fn secrets_config_loads_encrypted_file_with_password() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "read" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#;
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    let password = secrecy::SecretString::from("passphrase".to_owned());
    let encrypted = crypto::encrypt_string(plaintext, &password)?;
    std::fs::write(&secrets_file, encrypted)?;

    let config = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs {
            password: Some("passphrase".to_owned()),
        },
    )?;

    assert_eq!(config.clients["default"].bearer_token_id, "default");
    assert_eq!(
        config
            .apis
            .get("billing")
            .expect("billing api")
            .auth_value
            .expose_secret(),
        "billing-secret-token"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_wrong_password_for_encrypted_file()
-> Result<(), Box<dyn std::error::Error>> {
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#;
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    let password = secrecy::SecretString::from("passphrase".to_owned());
    let encrypted = crypto::encrypt_string(plaintext, &password)?;
    std::fs::write(&secrets_file, encrypted)?;

    let error = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs {
            password: Some("wrong-passphrase".to_owned()),
        },
    )
    .unwrap_err();

    assert!(error.to_string().contains("invalid password"));

    Ok(())
}

#[test]
fn secrets_config_loads_encrypted_file_with_keyring_password()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[PASSWORD_ENV_VAR]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "read" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#;
    let (_temp_dir, secrets_file) = write_encrypted_secrets_file(plaintext, "passphrase")?;
    let keyring = install_shared_keyring();
    keyring.set_password("gate-agent", &keyring_user_for(&secrets_file), "passphrase");

    let config = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs { password: None },
    )?;

    assert_eq!(config.clients["default"].bearer_token_id, "default");
    assert_eq!(
        config
            .apis
            .get("billing")
            .expect("billing api")
            .auth_value
            .expose_secret(),
        "billing-secret-token"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_wrong_keyring_password_for_encrypted_file()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[PASSWORD_ENV_VAR]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#;
    let (_temp_dir, secrets_file) = write_encrypted_secrets_file(plaintext, "passphrase")?;
    let keyring = install_shared_keyring();
    keyring.set_password(
        "gate-agent",
        &keyring_user_for(&secrets_file),
        "wrong-passphrase",
    );

    let error = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs { password: None },
    )
    .unwrap_err();

    assert!(error.to_string().contains("invalid password"));

    Ok(())
}

#[test]
fn secrets_config_falls_through_to_prompt_after_keyring_read_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[
        PASSWORD_ENV_VAR,
        "GATE_AGENT_TEST_PROMPT_PASSWORD",
        "GATE_AGENT_TEST_PROMPT_CONFIRM",
    ]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "read" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#;
    let (_temp_dir, secrets_file) = write_encrypted_secrets_file(plaintext, "passphrase")?;
    let keyring = install_shared_keyring();
    keyring.fail_next(
        "gate-agent",
        &keyring_user_for(&secrets_file),
        keyring::Error::NoStorageAccess(std::io::Error::other("keyring locked").into()),
    );

    unsafe {
        std::env::set_var("GATE_AGENT_TEST_PROMPT_PASSWORD", "passphrase");
    }

    let config = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs { password: None },
    )?;

    assert_eq!(config.clients["default"].bearer_token_id, "default");
    assert_eq!(
        keyring.get_password("gate-agent", &keyring_user_for(&secrets_file))?,
        "passphrase"
    );

    Ok(())
}

#[test]
fn secrets_config_backfills_keyring_after_successful_prompt_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[
        PASSWORD_ENV_VAR,
        "GATE_AGENT_TEST_PROMPT_PASSWORD",
        "GATE_AGENT_TEST_PROMPT_CONFIRM",
    ]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "read" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#;
    let (_temp_dir, secrets_file) = write_encrypted_secrets_file(plaintext, "passphrase")?;
    let keyring = install_shared_keyring();

    unsafe {
        std::env::set_var("GATE_AGENT_TEST_PROMPT_PASSWORD", "passphrase");
    }

    let config = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs { password: None },
    )?;

    assert_eq!(config.clients["default"].bearer_token_id, "default");
    assert_eq!(
        keyring.get_password("gate-agent", &keyring_user_for(&secrets_file))?,
        "passphrase"
    );

    Ok(())
}

#[test]
fn secrets_config_removes_stale_keyring_password_after_decrypt_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[PASSWORD_ENV_VAR]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#;
    let (_temp_dir, secrets_file) = write_encrypted_secrets_file(plaintext, "passphrase")?;
    let keyring = install_shared_keyring();
    keyring.set_password(
        "gate-agent",
        &keyring_user_for(&secrets_file),
        "wrong-passphrase",
    );

    let error = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs { password: None },
    )
    .unwrap_err();

    assert!(error.to_string().contains("invalid password"));
    assert!(matches!(
        keyring.get_password("gate-agent", &keyring_user_for(&secrets_file)),
        Err(keyring::Error::NoEntry)
    ));

    Ok(())
}

#[test]
fn encrypted_create_resolution_reports_password_source() -> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[
        PASSWORD_ENV_VAR,
        "GATE_AGENT_TEST_PROMPT_PASSWORD",
        "GATE_AGENT_TEST_PROMPT_CONFIRM",
    ]);
    let temp_dir = tempdir()?;
    let path = temp_dir.path().join("new-config.toml");

    unsafe {
        std::env::set_var("GATE_AGENT_TEST_PROMPT_PASSWORD", "prompt-passphrase");
        std::env::set_var("GATE_AGENT_TEST_PROMPT_CONFIRM", "prompt-passphrase");
    }

    let resolved = resolve_for_encrypted_create(&PasswordArgs { password: None }, &path)?;

    assert_eq!(resolved.password.expose_secret(), "prompt-passphrase");
    assert_eq!(resolved.source, PasswordSource::Prompt);

    Ok(())
}

#[test]
fn secrets_config_loads_multiple_clients_sharing_one_api() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "4e738ca5563c06cf5ef8d7f41250e0d2c1f7c9c5218b9d0f9a3c1f2a6b3d4c5e"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
group = "shared-read"

[groups.shared-read]
api_access = { projects = "read" }

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
            .api_access
            .get("projects")
            == Some(&AccessLevel::Read)
    );
    assert!(
        config
            .clients
            .get("partner")
            .expect("partner client")
            .api_access
            .get("projects")
            == Some(&AccessLevel::Read)
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_client_with_both_group_and_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "shared-read"
api_access = { projects = "read" }

[groups.shared-read]
api_access = { projects = "read" }

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
        "clients.default must specify exactly one of group or api_access"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_client_with_neither_group_nor_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"

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
        "clients.default must specify exactly one of group or api_access"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_group_reference() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "missing-group"

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
        "clients.default.group references unknown group 'missing-group'"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_group_with_extra_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "shared-read"

[groups.shared-read]
api_access = { projects = "read" }
description = "readonly"

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `description`"));
    assert!(error.to_string().contains("expected `api_access`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_legacy_allowed_apis_field() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `allowed_apis`"));
    assert!(error.to_string().contains(
        "expected one of `bearer_token_id`, `bearer_token_hash`, `bearer_token_expires_at`, `group`, `api_access`"
    ));

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_access_level_in_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "admin" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown variant `admin`"));
    assert!(error.to_string().contains("expected `read` or `write`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_access_level_in_group_api_access()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "shared-access"

[groups.shared-access]
api_access = { projects = "admin" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown variant `admin`"));
    assert!(error.to_string().contains("expected `read` or `write`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_api_in_group_api_access() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "shared-access"

[groups.shared-access]
api_access = { unknown = "read" }

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
        "groups.shared-access.api_access contains unknown api 'unknown'"
    );

    Ok(())
}

#[test]
fn secrets_config_requires_group_api_access() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "shared-access"

[groups.shared-access]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("missing field `api_access`"));

    Ok(())
}

#[test]
fn secrets_config_requires_at_least_one_client() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
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
fn secrets_config_allows_empty_apis_and_empty_api_access() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

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
            .api_access
            .is_empty()
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_lowercase_api_slug() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
[clients.Default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
[clients."default "]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
fn secrets_config_rejects_non_lowercase_api_access_keys() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { Projects = "read" }

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
        "clients.default.api_access contains invalid api slug 'Projects'"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_api_access_keys_with_trailing_space()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { "projects " = "read" }

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
        "clients.default.api_access contains invalid api slug 'projects '"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_api_in_api_access() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { unknown = "write" }

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
        "clients.default.api_access contains unknown api 'unknown'"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_duplicate_api_access_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read", projects = "write" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("failed to parse config file '")
    );
    assert!(error.to_string().contains("duplicate key `projects`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_duplicate_client_bearer_token_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "shared-id"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[clients.partner]
bearer_token_id = "shared-id"
bearer_token_hash = "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
api_access = { projects = "read" }

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
        "clients.partner.bearer_token_id duplicates another configured client bearer_token_id"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_duplicate_client_bearer_token_hashes()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
api_access = { projects = "read" }

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
        "clients.partner.bearer_token_hash duplicates another configured client bearer_token_hash"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_top_level_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
unexpected = "nope"

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
            .contains("expected one of `clients`, `groups`, `apis`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_legacy_client_auth_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
signing_secret = "replace-me"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error.to_string().contains("unknown field `api_key`, expected one of `bearer_token_id`, `bearer_token_hash`, `bearer_token_expires_at`, `group`, `api_access`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_legacy_auth_section() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `auth`"));
    assert!(
        error
            .to_string()
            .contains("expected one of `clients`, `groups`, `apis`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_api_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
fn secrets_config_defaults_missing_timeout_ms() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;

    assert_eq!(config.apis["projects"].timeout_ms, 5_000);

    Ok(())
}

#[test]
fn secrets_config_rejects_invalid_header_name() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

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
fn secrets_config_rejects_non_utc_bearer_token_expiration() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00+00:00"
api_access = {}
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.bearer_token_expires_at must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_malformed_bearer_token_expiration()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08 12:00:00Z"
api_access = {}
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.bearer_token_expires_at must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_blank_bearer_token_id() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "   "
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.bearer_token_id cannot be empty"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_malformed_bearer_token_hash() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "not-a-sha"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.bearer_token_hash must be a 64-character lowercase SHA-256 hex digest"
    );

    Ok(())
}

#[test]
fn bearer_token_hash_matches_full_token_sha256() {
    let hash = BearerTokenHash::from_token("lookup.secret-part");

    assert_eq!(
        hash.as_str(),
        "e67c21f73a790b90a2b80487ca69aaa6cdf4db8a0efb3d4dbc0798e73a5fd57e"
    );
    assert!(hash.matches_token("lookup.secret-part"));
    assert!(!hash.matches_token("lookup.other-secret"));
}
