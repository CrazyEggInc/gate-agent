use std::any::Any;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use keyring::Credential;
use keyring::credential::{CredentialApi, CredentialBuilderApi, CredentialPersistence};
use secrecy::ExposeSecret;

use gate_agent::config::secrets::{ApiAccessMethod, ApiAccessRule, BearerTokenHash, SecretsConfig};
use gate_agent::config::{
    crypto,
    password::{PASSWORD_ENV_VAR, PasswordArgs, PasswordSource, resolve_for_encrypted_create},
};
use tempfile::tempdir;

const ENCRYPTION_FACTOR_ENV_VAR: &str = "GATE_AGENT_ENCRYPTION_FACTOR";
const DEFAULT_SERVER_BIND: &str = "127.0.0.1";
const DEFAULT_SERVER_PORT: u16 = 8787;

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
    fn set(values: &[(&'static str, Option<&str>)]) -> Self {
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
        let values = keys.iter().map(|key| (*key, None)).collect::<Vec<_>>();
        Self::set(&values)
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
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "Bearer billing-secret-token" }
timeout_ms = 5000
"#
}

fn api_access_config_error(api_access: &str) -> String {
    let body = format!(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {{ {api_access} }}

[apis.projects]
base_url = "https://projects.internal.example"
headers = {{ x-api-key = "projects-secret-value" }}
timeout_ms = 5000
"#
    );
    let (_temp_dir, secrets_file) = write_secrets_file(&body).expect("write secrets config");

    SecretsConfig::load_from_file(&secrets_file)
        .unwrap_err()
        .to_string()
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
    assert!(!sample_contents.contains("auth_scheme"));
    assert!(sample_contents.contains("bearer_token_id = \"default\""));
    assert!(sample_contents.contains("bearer_token_hash"));
    assert!(sample_contents.contains("bearer_token_expires_at = \"2036-10-08T12:00:00Z\""));
    assert!(sample_contents.contains("group = \"default\""));
    assert!(sample_contents.contains("[groups.default]"));
    assert!(
        sample_contents.contains("api_access = { projects = [{ method = \"*\", path = \"*\" }] }")
    );
    assert!(
        sample_contents.contains("headers = { authorization = \"Bearer local-upstream-token\" }")
    );
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
        [("projects".to_string(), vec![any_rule("*")])]
            .into_iter()
            .collect()
    );
    assert_eq!(api.base_url.as_str(), "http://127.0.0.1:18081/api");
    assert_eq!(api.headers.len(), 1);
    assert_eq!(api.headers[0].0.as_str(), "authorization");
    assert_eq!(
        api.headers[0].1.expose_secret(),
        "Bearer local-upstream-token"
    );
    assert_eq!(api.description, None);
    assert_eq!(api.docs_url, None);
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
    assert_eq!(config.server.bind, DEFAULT_SERVER_BIND);
    assert_eq!(config.server.port, DEFAULT_SERVER_PORT);
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
        [("billing".to_string(), vec![any_rule("*")])]
            .into_iter()
            .collect()
    );
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");
    assert_eq!(api.headers.len(), 1);
    assert_eq!(api.headers[0].0.as_str(), "authorization");
    assert_eq!(
        api.headers[0].1.expose_secret(),
        "Bearer billing-secret-token"
    );
    assert_eq!(api.description, None);
    assert_eq!(api.docs_url, None);
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
fn secrets_config_loads_mixed_api_access_route_rules() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "/api/*" }, { method = "POST", path = "/api/users/*" }], datadog = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000

[apis.datadog]
base_url = "https://datadog.internal.example"
headers = { x-api-key = "datadog-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let client = config.clients.get("default").expect("default client");

    assert_eq!(
        client.api_access["projects"],
        vec![
            exact_rule(http::Method::GET, "/api/*"),
            exact_rule(http::Method::POST, "/api/users/*"),
        ]
    );
    assert_eq!(client.api_access["datadog"], vec![any_rule("*")]);

    Ok(())
}

#[test]
fn secrets_config_loads_empty_api_access_array() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = []

[apis.project]
base_url = "https://project.internal.example"
headers = { x-api-key = "project-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let client = config.clients.get("default").expect("default client");

    assert!(client.api_access.is_empty());

    Ok(())
}

#[test]
fn secrets_config_loads_empty_api_access_rules_array() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = [{ project = [] }]

[apis.project]
base_url = "https://project.internal.example"
headers = { x-api-key = "project-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let client = config.clients.get("default").expect("default client");

    assert_eq!(client.api_access.get("project"), Some(&Vec::new()));

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
api_access = { billing = [{ method = "get", path = "*" }] }

        [apis.billing]
        base_url = "https://billing.internal.example"
        headers = { authorization = "Bearer billing-secret-token" }
        timeout_ms = 5000
"#,
        "stdin",
    )?;

    let client = config
        .clients
        .get("default")
        .expect("default client config");
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(config.server.bind, DEFAULT_SERVER_BIND);
    assert_eq!(config.server.port, DEFAULT_SERVER_PORT);
    assert_eq!(client.bearer_token_id, "default");
    assert_eq!(
        client.bearer_token_expires_at.as_str(),
        "2026-10-08T12:00:00Z"
    );
    assert_eq!(
        client.api_access,
        [(
            "billing".to_string(),
            vec![exact_rule(http::Method::GET, "*")]
        )]
        .into_iter()
        .collect()
    );
    assert_eq!(api.base_url.as_str(), "https://billing.internal.example/");
    assert_eq!(api.headers.len(), 1);
    assert_eq!(api.headers[0].0.as_str(), "authorization");
    assert_eq!(
        api.headers[0].1.expose_secret(),
        "Bearer billing-secret-token"
    );
    assert_eq!(api.description, None);
    assert_eq!(api.docs_url, None);
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
api_access = { billing = [{ method = "*", path = "*" }]
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
    let _env_guard = PasswordEnvGuard::set(&[(ENCRYPTION_FACTOR_ENV_VAR, Some("1"))]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "get", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "billing-secret-token" }
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
        config.apis.get("billing").expect("billing api").headers[0]
            .1
            .expose_secret(),
        "billing-secret-token"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_wrong_password_for_encrypted_file()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::set(&[(ENCRYPTION_FACTOR_ENV_VAR, Some("1"))]);
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
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (ENCRYPTION_FACTOR_ENV_VAR, Some("1")),
    ]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "get", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "billing-secret-token" }
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
        config.apis.get("billing").expect("billing api").headers[0]
            .1
            .expose_secret(),
        "billing-secret-token"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_wrong_keyring_password_for_encrypted_file()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (ENCRYPTION_FACTOR_ENV_VAR, Some("1")),
    ]);
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
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        ("GATE_AGENT_TEST_PROMPT_PASSWORD", None),
        ("GATE_AGENT_TEST_PROMPT_CONFIRM", None),
        (ENCRYPTION_FACTOR_ENV_VAR, Some("1")),
    ]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "get", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "billing-secret-token" }
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
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        ("GATE_AGENT_TEST_PROMPT_PASSWORD", None),
        ("GATE_AGENT_TEST_PROMPT_CONFIRM", None),
        (ENCRYPTION_FACTOR_ENV_VAR, Some("1")),
    ]);
    let plaintext = r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "get", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "billing-secret-token" }
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
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (ENCRYPTION_FACTOR_ENV_VAR, Some("1")),
    ]);
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
api_access = { projects = [{ method = "get", path = "*" }] }

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "4e738ca5563c06cf5ef8d7f41250e0d2c1f7c9c5218b9d0f9a3c1f2a6b3d4c5e"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
group = "shared-read"

[groups.shared-read]
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
            == Some(&vec![exact_rule(http::Method::GET, "*")])
    );
    assert!(
        config
            .clients
            .get("partner")
            .expect("partner client")
            .api_access
            .get("projects")
            == Some(&vec![exact_rule(http::Method::GET, "*")])
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
api_access = { projects = [{ method = "get", path = "*" }] }

[groups.shared-read]
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
headers = { x-api-key = "projects-secret-value" }
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
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }
description = "readonly"

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
headers = { x-api-key = "projects-secret-value" }
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
fn secrets_config_rejects_old_string_api_access_syntax() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("data did not match any variant of untagged enum RawApiAccess")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_old_string_group_api_access_syntax()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
group = "shared-access"

[groups.shared-access]
api_access = { projects = "read" }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("data did not match any variant of untagged enum RawApiAccess")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_blank_api_access_method() {
    let error = api_access_config_error(r#"projects = [{ method = "", path = "*" }]"#);

    assert_eq!(
        error,
        "clients.default.api_access.projects[0].method cannot be empty"
    );
}

#[test]
fn secrets_config_rejects_invalid_api_access_method() {
    let error = api_access_config_error(r#"projects = [{ method = "bad method", path = "*" }]"#);

    assert!(error.starts_with("clients.default.api_access.projects[0].method is invalid:"));
}

#[test]
fn secrets_config_rejects_blank_api_access_path() {
    let error = api_access_config_error(r#"projects = [{ method = "get", path = "" }]"#);

    assert_eq!(
        error,
        "clients.default.api_access.projects[0].path cannot be empty"
    );
}

#[test]
fn secrets_config_rejects_api_access_path_without_leading_slash() {
    let error = api_access_config_error(r#"projects = [{ method = "get", path = "api/*" }]"#);

    assert_eq!(
        error,
        "clients.default.api_access.projects[0].path must be '*' or start with '/'"
    );
}

#[test]
fn secrets_config_rejects_api_access_path_with_query() {
    let error = api_access_config_error(r#"projects = [{ method = "get", path = "/api?x=1" }]"#);

    assert_eq!(
        error,
        "clients.default.api_access.projects[0].path must not contain query strings"
    );
}

#[test]
fn secrets_config_rejects_api_access_path_with_fragment() {
    let error = api_access_config_error(r#"projects = [{ method = "get", path = "/api#users" }]"#);

    assert_eq!(
        error,
        "clients.default.api_access.projects[0].path must not contain fragments"
    );
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
api_access = { unknown = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
headers = { x-api-key = "projects-secret-value" }
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
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.Projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis."projects/api"]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { Projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { "projects " = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { unknown = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }], projects = [{ method = "*", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[clients.partner]
bearer_token_id = "shared-id"
bearer_token_hash = "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-09T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `unexpected`"));
    assert!(error.to_string().contains("expected one of"));
    assert!(error.to_string().contains("`server`"));

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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
    assert!(error.to_string().contains("expected one of"));
    assert!(error.to_string().contains("`server`"));

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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
extra_header = "nope"
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unknown field `extra_header`, expected one of `base_url`, `description`, `docs_url`, `headers`, `basic_auth`, `timeout_ms`")
    );

    Ok(())
}

#[test]
fn secrets_config_loads_optional_api_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
description = "Project API"
docs_url = "https://docs.internal.example/projects"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("projects").expect("projects api config");

    assert_eq!(api.description.as_deref(), Some("Project API"));
    assert_eq!(
        api.docs_url.as_ref().map(url::Url::as_str),
        Some("https://docs.internal.example/projects")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_non_http_docs_url() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
docs_url = "ftp://docs.internal.example/projects"
headers = { x-api-key = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.projects.docs_url must use http or https"
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "ftp://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "projects-secret-value" }
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
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { "bad header" = "projects-secret-value" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("apis.projects.headers.bad header is invalid:")
    );

    Ok(())
}

#[test]
fn secrets_config_allows_api_without_upstream_auth_injection()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("projects").expect("projects api config");

    assert!(api.headers.is_empty());

    Ok(())
}

#[test]
fn secrets_config_loads_api_with_one_header() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "Bearer billing-secret-token" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(api.headers.len(), 1);
    assert_eq!(api.headers[0].0.as_str(), "authorization");
    assert_eq!(
        api.headers[0].1.expose_secret(),
        "Bearer billing-secret-token"
    );

    Ok(())
}

#[test]
fn secrets_config_loads_api_with_multiple_headers() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "Bearer billing-secret-token", x-api-key = "secondary-secret" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");

    assert_eq!(api.headers.len(), 2);
    assert_eq!(api.headers[0].0.as_str(), "authorization");
    assert_eq!(
        api.headers[0].1.expose_secret(),
        "Bearer billing-secret-token"
    );
    assert_eq!(api.headers[1].0.as_str(), "x-api-key");
    assert_eq!(api.headers[1].1.expose_secret(), "secondary-secret");

    Ok(())
}

#[test]
fn secrets_config_loads_api_with_basic_auth() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = "billing-user", password = "billing-pass" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");
    let basic_auth = api.basic_auth.as_ref().expect("billing basic auth");

    assert_eq!(basic_auth.username, "billing-user");
    assert_eq!(basic_auth.password.expose_secret(), "billing-pass");
    assert!(api.headers.is_empty());

    Ok(())
}

#[test]
fn secrets_config_loads_api_with_basic_auth_username_only() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = "billing-user" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");
    let basic_auth = api.basic_auth.as_ref().expect("billing basic auth");

    assert_eq!(basic_auth.username, "billing-user");
    assert_eq!(basic_auth.password.expose_secret(), "");

    Ok(())
}

#[test]
fn secrets_config_loads_api_with_basic_auth_empty_password()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = "billing-user", password = "" }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");
    let basic_auth = api.basic_auth.as_ref().expect("billing basic auth");

    assert_eq!(basic_auth.username, "billing-user");
    assert_eq!(basic_auth.password.expose_secret(), "");

    Ok(())
}

#[test]
fn secrets_config_rejects_basic_auth_with_authorization_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
headers = { authorization = "Bearer billing-secret-token" }
basic_auth = { username = "billing-user", password = "billing-pass" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.billing cannot set both headers.authorization and basic_auth"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_empty_basic_auth_username() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = "", password = "billing-pass" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.billing.basic_auth.username cannot be empty"
    );

    Ok(())
}

#[test]
fn secrets_config_preserves_raw_basic_auth_values_without_trim_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { billing = [{ method = "*", path = "*" }] }

[apis.billing]
base_url = "https://billing.internal.example"
basic_auth = { username = " billing-user ", password = " billing-pass " }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("billing").expect("billing api config");
    let basic_auth = api.basic_auth.as_ref().expect("billing basic auth");

    assert_eq!(basic_auth.username, " billing-user ");
    assert_eq!(basic_auth.password.expose_secret(), " billing-pass ");

    Ok(())
}

#[test]
fn secrets_config_rejects_case_only_duplicate_api_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { authorization = "Bearer first-secret", Authorization = "Bearer second-secret" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.projects.headers.authorization duplicates another configured header"
    );

    Ok(())
}

#[test]
fn secrets_config_preserves_raw_header_value_without_trim_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { authorization = " Bearer projects-secret-value " }
timeout_ms = 5000
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;
    let api = config.apis.get("projects").expect("projects api config");

    assert_eq!(api.headers.len(), 1);
    assert_eq!(api.headers[0].0.as_str(), "authorization");
    assert_eq!(
        api.headers[0].1.expose_secret(),
        " Bearer projects-secret-value "
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_legacy_api_auth_header_field() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `auth_header`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_legacy_api_auth_value_field() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `auth_value`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_legacy_api_auth_scheme_field() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
auth_scheme = "Bearer"
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `auth_scheme`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_invalid_header_value_without_secret_leak()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "bad\u007fsecret" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("apis.projects.headers.x-api-key is invalid:")
    );
    assert!(!error.to_string().contains("bad"));
    assert!(!error.to_string().contains("secret"));

    Ok(())
}

#[test]
fn secrets_config_rejects_empty_header_value() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.projects.headers.x-api-key is invalid: empty value"
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_whitespace_only_header_value() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "c1ac6c9bad0a391759c36f9d435d04db39e6f8957809b907c5cf14d113cb5faa"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = { projects = [{ method = "get", path = "*" }] }

[apis.projects]
base_url = "https://projects.internal.example"
headers = { x-api-key = "   \t" }
timeout_ms = 5000
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(
        error.to_string(),
        "apis.projects.headers.x-api-key is invalid: empty value"
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

#[test]
fn secrets_config_loads_explicit_server_settings() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[server]
bind = "0.0.0.0"
port = 9999

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    let config = SecretsConfig::load_from_file(&secrets_file)?;

    assert_eq!(config.server.bind, "0.0.0.0");
    assert_eq!(config.server.port, 9999);

    Ok(())
}

#[test]
fn secrets_config_rejects_server_with_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[server]
bind = "127.0.0.1"
port = 8787
host = "localhost"

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(error.to_string().contains("unknown field `host`"));
    assert!(error.to_string().contains("expected `bind` or `port`"));

    Ok(())
}

#[test]
fn secrets_config_rejects_blank_server_bind() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[server]
bind = "   "

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(error.to_string(), "server.bind cannot be empty");

    Ok(())
}

#[test]
fn secrets_config_rejects_unbindable_server_bind() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[server]
bind = "bad host name"

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("server.bind is invalid: server bind address 'bad host name' is invalid:")
    );

    Ok(())
}

#[test]
fn secrets_config_rejects_zero_server_port() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[server]
port = 0

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(error.to_string(), "server.port must be between 1 and 65535");

    Ok(())
}

#[test]
fn secrets_config_rejects_server_port_above_u16_range() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(
        r#"
[server]
port = 65536

[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2026-10-08T12:00:00Z"
api_access = {}

[apis]
"#,
    )?;

    let error = SecretsConfig::load_from_file(&secrets_file).unwrap_err();

    assert_eq!(error.to_string(), "server.port must be between 1 and 65535");

    Ok(())
}
