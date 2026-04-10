use std::any::Any;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use keyring::Credential;
use keyring::credential::{CredentialApi, CredentialBuilderApi, CredentialPersistence};
use secrecy::{ExposeSecret, SecretString};

use gate_agent::config::secrets::{AccessLevel, SecretsConfig};
use gate_agent::config::{
    crypto,
    password::{PASSWORD_ENV_VAR, PasswordArgs},
};
use tempfile::tempdir;

const KEYRING_SERVICE: &str = "gate-agent";
const TEST_PROMPT_PASSWORD_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_PASSWORD";
const TEST_PROMPT_CONFIRM_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_CONFIRM";
const ENCRYPTED_PASSWORD: &str = "passphrase";
const WRONG_PASSWORD: &str = "wrong-passphrase";

fn encrypted_secrets_fixture() -> &'static str {
    r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "client-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "read" }

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#
}

fn write_fixture_encrypted_secrets_file(
    password: &str,
) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    write_encrypted_secrets_file(encrypted_secrets_fixture(), password)
}

fn assert_encrypted_fixture_loaded(config: &SecretsConfig) {
    assert_eq!(config.auth.issuer, "gate-agent-dev");
    assert_eq!(config.auth.audience, "gate-agent-clients");
    assert_eq!(config.auth.signing_secret.expose_secret(), "rotate-me");
    assert_eq!(
        config
            .clients
            .get("default")
            .expect("default client")
            .api_access,
        [("billing".to_string(), AccessLevel::Read)]
            .into_iter()
            .collect()
    );
    assert_eq!(
        config
            .apis
            .get("billing")
            .expect("billing api")
            .auth_value
            .expose_secret(),
        "billing-secret-token"
    );
}

fn set_keyring_password(store: &SharedKeyringStore, path: &Path, password: &str) {
    store.set_password(KEYRING_SERVICE, &keyring_user_for(path), password);
}

fn assert_keyring_password(
    store: &SharedKeyringStore,
    path: &Path,
    expected_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        store.get_password(KEYRING_SERVICE, &keyring_user_for(path))?,
        expected_password
    );
    Ok(())
}

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
    let encrypted = crypto::encrypt_string(plaintext, &SecretString::from(password.to_owned()))?;
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
    fn set(values: &[(&'static str, Option<&'static str>)]) -> Self {
        let lock = password_test_lock()
            .lock()
            .expect("password test mutex poisoned");
        let previous = values
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect::<Vec<_>>();

        for (key, value) in values {
            match value {
                Some(value) => unsafe {
                    std::env::set_var(key, value);
                },
                None => unsafe {
                    std::env::remove_var(key);
                },
            }
        }

        Self {
            previous,
            _lock: lock,
        }
    }

    fn clear(keys: &[&'static str]) -> Self {
        let cleared = keys.iter().map(|key| (*key, None)).collect::<Vec<_>>();
        Self::set(&cleared)
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
    assert!(sample_contents.contains("group = \"local-default\""));
    assert!(sample_contents.contains("[groups.local-default]"));
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
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "client-api-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = "write" }

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
        client.api_access,
        [("billing".to_string(), AccessLevel::Write)]
            .into_iter()
            .collect()
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

    assert_eq!(config.auth.issuer, "gate-agent-dev");
    assert_eq!(config.auth.audience, "gate-agent-clients");
    assert_eq!(config.auth.signing_secret.expose_secret(), "rotate-me");
    assert_eq!(client.slug, "default");
    assert_eq!(client.api_key.expose_secret(), "client-api-key");
    assert_eq!(client.api_key_expires_at.as_str(), "2026-10-08T12:00:00Z");
    assert_eq!(
        client.api_access,
        [("billing".to_string(), AccessLevel::Read)]
            .into_iter()
            .collect()
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
fn encrypted_read_loads_and_parses_fixture_with_flag_password()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_fixture_encrypted_secrets_file(ENCRYPTED_PASSWORD)?;

    let config = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs {
            password: Some(ENCRYPTED_PASSWORD.to_owned()),
        },
    )?;

    assert_encrypted_fixture_loaded(&config);

    Ok(())
}

#[test]
fn secrets_config_rejects_wrong_password_for_encrypted_file()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_fixture_encrypted_secrets_file(ENCRYPTED_PASSWORD)?;

    let error = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs {
            password: Some(WRONG_PASSWORD.to_owned()),
        },
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
        TEST_PROMPT_PASSWORD_ENV_VAR,
        TEST_PROMPT_CONFIRM_ENV_VAR,
    ]);
    let (_temp_dir, secrets_file) = write_fixture_encrypted_secrets_file(ENCRYPTED_PASSWORD)?;
    let keyring = install_shared_keyring();
    keyring.fail_next(
        KEYRING_SERVICE,
        &keyring_user_for(&secrets_file),
        keyring::Error::NoStorageAccess(std::io::Error::other("keyring locked").into()),
    );

    unsafe {
        std::env::set_var(TEST_PROMPT_PASSWORD_ENV_VAR, ENCRYPTED_PASSWORD);
    }

    let config = SecretsConfig::load_from_file_with_password_args(
        &secrets_file,
        &PasswordArgs { password: None },
    )?;

    assert_encrypted_fixture_loaded(&config);
    assert_keyring_password(&keyring, &secrets_file, ENCRYPTED_PASSWORD)?;

    Ok(())
}

#[test]
fn secrets_config_removes_stale_keyring_password_after_decrypt_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::clear(&[PASSWORD_ENV_VAR]);
    let (_temp_dir, secrets_file) = write_fixture_encrypted_secrets_file(ENCRYPTED_PASSWORD)?;
    let keyring = install_shared_keyring();
    set_keyring_password(&keyring, &secrets_file, WRONG_PASSWORD);

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
api_access = { projects = "read" }

[clients.partner]
api_key = "partner-key"
api_key_expires_at = "2026-10-09T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"

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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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

    assert!(error.to_string().contains("unknown field `allowed_apis`"));
    assert!(
        error
            .to_string()
            .contains("expected one of `api_key`, `api_key_expires_at`, `group`, `api_access`")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_unknown_access_level_in_api_access()
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
fn secrets_config_allows_empty_apis_and_empty_api_access() -> Result<(), Box<dyn std::error::Error>>
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.Default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients."default "]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
fn secrets_config_rejects_duplicate_client_api_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "shared-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[clients.partner]
api_key = "shared-key"
api_key_expires_at = "2026-10-09T12:00:00Z"
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
        "clients.partner.api_key duplicates another configured client api_key"
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
            .contains("expected one of `auth`, `clients`, `groups`, `apis`")
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
api_access = { projects = "read" }

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
            .contains("expected one of `api_key`, `api_key_expires_at`, `group`, `api_access`")
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-key"
api_key_expires_at = "2026-10-08T12:00:00Z"
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
api_access = {}
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
api_access = {}
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "clients.default.api_key_expires_at must be an RFC3339 UTC timestamp like 2026-10-08T12:00:00Z"
    );

    Ok(())
}
