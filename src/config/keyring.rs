use std::path::{Path, PathBuf};

use super::ConfigError;

const SERVICE_NAME: &str = "gate-agent";
const TEST_KEYRING_FILE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_FILE";
const TEST_KEYRING_STORE_FAILURE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_STORE_FAILURE";

#[derive(Debug)]
pub enum KeyringReadOutcome {
    Found(String),
    Missing,
    #[allow(dead_code)]
    SoftFailure(ConfigError),
}

#[derive(Debug)]
pub enum KeyringStoreOutcome {
    Stored,
    SoftFailure(ConfigError),
}

#[derive(Debug)]
pub enum KeyringDeleteOutcome {
    Deleted,
    Missing,
    #[allow(dead_code)]
    SoftFailure(ConfigError),
}

pub struct ConfigKeyring<B = SystemKeyringBackend> {
    backend: B,
}

impl ConfigKeyring {
    pub fn new() -> Self {
        Self {
            backend: SystemKeyringBackend,
        }
    }
}

impl Default for ConfigKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> ConfigKeyring<B>
where
    B: KeyringBackend,
{
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn with_backend(backend: B) -> Self {
        Self { backend }
    }

    pub fn read_password(&self, config_path: &Path) -> KeyringReadOutcome {
        let entry = match self.entry_for(config_path) {
            Ok(entry) => entry,
            Err(error) => return KeyringReadOutcome::SoftFailure(error),
        };

        match entry.get_password() {
            Ok(password) => KeyringReadOutcome::Found(password),
            Err(keyring::Error::NoEntry) => KeyringReadOutcome::Missing,
            Err(error) => KeyringReadOutcome::SoftFailure(read_error(config_path, error)),
        }
    }

    pub fn store_password(&self, config_path: &Path, password: &str) -> KeyringStoreOutcome {
        let entry = match self.entry_for(config_path) {
            Ok(entry) => entry,
            Err(error) => return KeyringStoreOutcome::SoftFailure(error),
        };

        match entry.set_password(password) {
            Ok(()) => KeyringStoreOutcome::Stored,
            Err(error) => KeyringStoreOutcome::SoftFailure(store_error(config_path, error)),
        }
    }

    pub fn delete_credential(&self, config_path: &Path) -> KeyringDeleteOutcome {
        let entry = match self.entry_for(config_path) {
            Ok(entry) => entry,
            Err(error) => return KeyringDeleteOutcome::SoftFailure(error),
        };

        match entry.delete_credential() {
            Ok(()) => KeyringDeleteOutcome::Deleted,
            Err(keyring::Error::NoEntry) => KeyringDeleteOutcome::Missing,
            Err(error) => KeyringDeleteOutcome::SoftFailure(delete_error(config_path, error)),
        }
    }

    fn entry_for(&self, config_path: &Path) -> Result<B::Entry, ConfigError> {
        let resolved_path = resolve_config_path(config_path)?;
        let user = entry_key(&resolved_path);

        self.backend
            .new_entry(SERVICE_NAME, &user)
            .map_err(|error| entry_error(config_path, error))
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn backend(&self) -> &B {
        &self.backend
    }
}

pub(crate) trait KeyringBackend {
    type Entry: KeyringEntry;

    fn new_entry(&self, service: &str, user: &str) -> Result<Self::Entry, keyring::Error>;
}

pub(crate) trait KeyringEntry {
    fn get_password(&self) -> Result<String, keyring::Error>;
    fn set_password(&self, password: &str) -> Result<(), keyring::Error>;
    fn delete_credential(&self) -> Result<(), keyring::Error>;
}

pub struct SystemKeyringBackend;

impl KeyringBackend for SystemKeyringBackend {
    type Entry = SystemKeyringEntry;

    fn new_entry(&self, service: &str, user: &str) -> Result<Self::Entry, keyring::Error> {
        match std::env::var(TEST_KEYRING_FILE_ENV_VAR) {
            Ok(path) => Ok(SystemKeyringEntry::Test {
                entry: TestKeyringEntry::new(
                    PathBuf::from(path),
                    service.to_owned(),
                    user.to_owned(),
                ),
            }),
            Err(_) => keyring::Entry::new(service, user).map(SystemKeyringEntry::System),
        }
    }
}

pub(crate) enum SystemKeyringEntry {
    System(keyring::Entry),
    Test { entry: TestKeyringEntry },
}

impl KeyringEntry for SystemKeyringEntry {
    fn get_password(&self) -> Result<String, keyring::Error> {
        match self {
            Self::System(entry) => keyring::Entry::get_password(entry),
            Self::Test { entry } => entry.get_password(),
        }
    }

    fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
        match self {
            Self::System(entry) => keyring::Entry::set_password(entry, password),
            Self::Test { entry } => entry.set_password(password),
        }
    }

    fn delete_credential(&self) -> Result<(), keyring::Error> {
        match self {
            Self::System(entry) => keyring::Entry::delete_credential(entry),
            Self::Test { entry } => entry.delete_credential(),
        }
    }
}

pub(crate) struct TestKeyringEntry {
    path: PathBuf,
    service: String,
    user: String,
}

impl TestKeyringEntry {
    fn new(path: PathBuf, service: String, user: String) -> Self {
        Self {
            path,
            service,
            user,
        }
    }

    fn entry_key(&self) -> String {
        format!("{}::{}", self.service, self.user)
    }

    fn read_store(&self) -> Result<std::collections::BTreeMap<String, String>, keyring::Error> {
        if !self.path.exists() {
            return Ok(std::collections::BTreeMap::new());
        }

        let contents = std::fs::read_to_string(&self.path).map_err(io_to_keyring_error)?;
        serde_json::from_str(&contents)
            .map_err(|error| keyring::Error::PlatformFailure(Box::new(error)))
    }

    fn write_store(
        &self,
        store: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), keyring::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(io_to_keyring_error)?;
        }

        let contents = serde_json::to_string(store)
            .map_err(|error| keyring::Error::PlatformFailure(Box::new(error)))?;
        std::fs::write(&self.path, contents).map_err(io_to_keyring_error)
    }
}

impl KeyringEntry for TestKeyringEntry {
    fn get_password(&self) -> Result<String, keyring::Error> {
        let store = self.read_store()?;
        store
            .get(&self.entry_key())
            .cloned()
            .ok_or(keyring::Error::NoEntry)
    }

    fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
        if let Ok(message) = std::env::var(TEST_KEYRING_STORE_FAILURE_ENV_VAR) {
            return Err(keyring::Error::PlatformFailure(Box::new(
                std::io::Error::other(message),
            )));
        }

        let mut store = self.read_store()?;
        store.insert(self.entry_key(), password.to_owned());
        self.write_store(&store)
    }

    fn delete_credential(&self) -> Result<(), keyring::Error> {
        let mut store = self.read_store()?;
        store
            .remove(&self.entry_key())
            .ok_or(keyring::Error::NoEntry)?;
        self.write_store(&store)
    }
}

fn io_to_keyring_error(error: std::io::Error) -> keyring::Error {
    keyring::Error::PlatformFailure(Box::new(error))
}

fn entry_key(config_path: &Path) -> String {
    format!("config:{}", config_path.display())
}

fn resolve_config_path(config_path: &Path) -> Result<PathBuf, ConfigError> {
    config_path.canonicalize().map_err(|error| {
        ConfigError::new(format!(
            "failed to resolve encrypted config path '{}' for system keyring lookup: {error}",
            config_path.display()
        ))
    })
}

fn entry_error(config_path: &Path, error: keyring::Error) -> ConfigError {
    ConfigError::new(format!(
        "failed to open system keyring entry for encrypted config '{}': {error}",
        config_path.display()
    ))
}

fn read_error(config_path: &Path, error: keyring::Error) -> ConfigError {
    ConfigError::new(format!(
        "failed to read password from system keyring for encrypted config '{}': {error}",
        config_path.display()
    ))
}

fn store_error(config_path: &Path, error: keyring::Error) -> ConfigError {
    ConfigError::new(format!(
        "failed to store password in system keyring for encrypted config '{}': {error}",
        config_path.display()
    ))
}

fn delete_error(config_path: &Path, error: keyring::Error) -> ConfigError {
    ConfigError::new(format!(
        "failed to delete password from system keyring for encrypted config '{}': {error}",
        config_path.display()
    ))
}
