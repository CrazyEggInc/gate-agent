use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod config {
    pub use gate_agent::config::ConfigError;

    pub mod keyring {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/config/keyring.rs"
        ));
    }
}

use config::keyring::{
    ConfigKeyring, KeyringBackend, KeyringDeleteOutcome, KeyringEntry, KeyringReadOutcome,
    KeyringStoreOutcome,
};

#[derive(Default)]
struct BackendState {
    calls: Vec<(String, String)>,
}

struct TestBackend {
    state: Arc<Mutex<BackendState>>,
    results: Mutex<VecDeque<Result<TestEntry, keyring::Error>>>,
}

impl TestBackend {
    fn new(results: impl IntoIterator<Item = Result<TestEntry, keyring::Error>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(BackendState::default())),
            results: Mutex::new(results.into_iter().collect()),
        }
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .expect("backend state mutex poisoned")
            .calls
            .clone()
    }
}

impl KeyringBackend for TestBackend {
    type Entry = TestEntry;

    fn new_entry(&self, service: &str, user: &str) -> Result<Self::Entry, keyring::Error> {
        self.state
            .lock()
            .expect("backend state mutex poisoned")
            .calls
            .push((service.to_owned(), user.to_owned()));

        self.results
            .lock()
            .expect("backend results mutex poisoned")
            .pop_front()
            .expect("test backend requires a configured result")
    }
}

#[derive(Default)]
struct EntryState {
    delete_attempts: usize,
    store_attempts: Vec<String>,
}

struct TestEntry {
    state: Arc<Mutex<EntryState>>,
    get_result: Mutex<Option<Result<String, keyring::Error>>>,
    set_result: Mutex<Option<Result<(), keyring::Error>>>,
    delete_result: Mutex<Option<Result<(), keyring::Error>>>,
}

impl TestEntry {
    fn found(password: &str) -> Self {
        Self {
            state: Arc::new(Mutex::new(EntryState::default())),
            get_result: Mutex::new(Some(Ok(password.to_owned()))),
            set_result: Mutex::new(Some(Ok(()))),
            delete_result: Mutex::new(Some(Ok(()))),
        }
    }

    fn missing() -> Self {
        Self {
            state: Arc::new(Mutex::new(EntryState::default())),
            get_result: Mutex::new(Some(Err(keyring::Error::NoEntry))),
            set_result: Mutex::new(Some(Ok(()))),
            delete_result: Mutex::new(Some(Err(keyring::Error::NoEntry))),
        }
    }

    fn store_failure(error: keyring::Error) -> (Self, Arc<Mutex<EntryState>>) {
        let state = Arc::new(Mutex::new(EntryState::default()));

        (
            Self {
                state: Arc::clone(&state),
                get_result: Mutex::new(Some(Ok(String::new()))),
                set_result: Mutex::new(Some(Err(error))),
                delete_result: Mutex::new(Some(Ok(()))),
            },
            state,
        )
    }

    fn delete_failure(error: keyring::Error) -> (Self, Arc<Mutex<EntryState>>) {
        let state = Arc::new(Mutex::new(EntryState::default()));

        (
            Self {
                state: Arc::clone(&state),
                get_result: Mutex::new(Some(Ok(String::new()))),
                set_result: Mutex::new(Some(Ok(()))),
                delete_result: Mutex::new(Some(Err(error))),
            },
            state,
        )
    }
}

impl KeyringEntry for TestEntry {
    fn get_password(&self) -> Result<String, keyring::Error> {
        self.get_result
            .lock()
            .expect("entry get mutex poisoned")
            .take()
            .expect("test entry get result already consumed")
    }

    fn set_password(&self, password: &str) -> Result<(), keyring::Error> {
        self.state
            .lock()
            .expect("entry state mutex poisoned")
            .store_attempts
            .push(password.to_owned());

        self.set_result
            .lock()
            .expect("entry set mutex poisoned")
            .take()
            .expect("test entry set result already consumed")
    }

    fn delete_credential(&self) -> Result<(), keyring::Error> {
        self.state
            .lock()
            .expect("entry state mutex poisoned")
            .delete_attempts += 1;

        self.delete_result
            .lock()
            .expect("entry delete mutex poisoned")
            .take()
            .expect("test entry delete result already consumed")
    }
}

#[test]
fn derives_service_and_entry_key_from_absolute_config_path() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let path_a = tempdir.path().join("config-a.toml");
    let path_b = tempdir.path().join("config-b.toml");
    fs::write(&path_a, "a").expect("config a should be created");
    fs::write(&path_b, "b").expect("config b should be created");
    let canonical_a = path_a.canonicalize().expect("config a should canonicalize");
    let canonical_b = path_b.canonicalize().expect("config b should canonicalize");
    let backend = TestBackend::new([
        Ok(TestEntry::found("alpha-secret")),
        Ok(TestEntry::found("beta-secret")),
    ]);
    let keyring = ConfigKeyring::with_backend(backend);

    match keyring.read_password(&path_a) {
        KeyringReadOutcome::Found(password) => assert_eq!(password, "alpha-secret"),
        outcome => panic!("expected found outcome, got {outcome:?}"),
    }

    match keyring.read_password(&path_b) {
        KeyringReadOutcome::Found(password) => assert_eq!(password, "beta-secret"),
        outcome => panic!("expected found outcome, got {outcome:?}"),
    }

    let calls = keyring.backend().calls();

    assert_eq!(
        calls,
        vec![
            (
                "gate-agent".to_owned(),
                format!("config:{}", canonical_a.display())
            ),
            (
                "gate-agent".to_owned(),
                format!("config:{}", canonical_b.display())
            ),
        ]
    );
    assert_ne!(calls[0].1, calls[1].1);
}

#[test]
fn canonicalizes_relative_config_path_before_building_entry_key() {
    let cwd = std::env::current_dir().expect("current dir should resolve");
    let tempdir = tempfile::tempdir_in(&cwd).expect("tempdir should be created under cwd");
    let config_path = tempdir.path().join("encrypted.toml");
    fs::write(&config_path, "[server]\nbind = \"127.0.0.1:8080\"\n")
        .expect("config file should be created");

    let relative_path = config_path
        .strip_prefix(&cwd)
        .expect("config path should live under cwd")
        .to_path_buf();
    let canonical_path = config_path
        .canonicalize()
        .expect("config path should canonicalize");
    let backend = TestBackend::new([Ok(TestEntry::found("relative-secret"))]);
    let keyring = ConfigKeyring::with_backend(backend);

    match keyring.read_password(&relative_path) {
        KeyringReadOutcome::Found(password) => assert_eq!(password, "relative-secret"),
        outcome => panic!("expected found outcome, got {outcome:?}"),
    }

    assert_eq!(
        keyring.backend().calls(),
        vec![(
            "gate-agent".to_owned(),
            format!("config:{}", canonical_path.display())
        )]
    );
}

#[test]
fn maps_missing_entry_to_missing_outcome() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("missing.toml");
    fs::write(&config_path, "missing").expect("config file should be created");
    let keyring = ConfigKeyring::with_backend(TestBackend::new([Ok(TestEntry::missing())]));

    let outcome = keyring.read_password(&config_path);

    assert!(matches!(outcome, KeyringReadOutcome::Missing));
}

#[test]
fn maps_store_failures_to_soft_failure_outcome() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let path = tempdir.path().join("encrypted.toml");
    fs::write(&path, "encrypted").expect("config file should be created");
    let (entry, state) = TestEntry::store_failure(keyring::Error::NoStorageAccess(
        std::io::Error::other("store locked").into(),
    ));
    let keyring = ConfigKeyring::with_backend(TestBackend::new([Ok(entry)]));

    let outcome = keyring.store_password(&path, "top-secret");

    match outcome {
        KeyringStoreOutcome::SoftFailure(error) => {
            assert!(
                error
                    .to_string()
                    .contains("failed to store password in system keyring")
            );
            assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
            assert!(error.to_string().contains("store locked"));
        }
        other => panic!("expected soft failure outcome, got {other:?}"),
    }

    assert_eq!(
        state
            .lock()
            .expect("entry state mutex poisoned")
            .store_attempts,
        vec!["top-secret".to_owned()]
    );
}

#[test]
fn deletes_existing_password_from_keyring() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let path = tempdir.path().join("encrypted.toml");
    fs::write(&path, "encrypted").expect("config file should be created");
    let keyring =
        ConfigKeyring::with_backend(TestBackend::new([Ok(TestEntry::found("top-secret"))]));

    let outcome = keyring.delete_credential(&path);

    assert!(matches!(outcome, KeyringDeleteOutcome::Deleted));
}

#[test]
fn maps_delete_failures_to_soft_failure_outcome() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let path = tempdir.path().join("encrypted.toml");
    fs::write(&path, "encrypted").expect("config file should be created");
    let (entry, state) = TestEntry::delete_failure(keyring::Error::NoStorageAccess(
        std::io::Error::other("delete locked").into(),
    ));
    let keyring = ConfigKeyring::with_backend(TestBackend::new([Ok(entry)]));

    let outcome = keyring.delete_credential(&path);

    match outcome {
        KeyringDeleteOutcome::SoftFailure(error) => {
            assert!(
                error
                    .to_string()
                    .contains("failed to delete password from system keyring")
            );
            assert!(error.to_string().contains("delete locked"));
        }
        other => panic!("expected soft failure outcome, got {other:?}"),
    }

    assert_eq!(
        state
            .lock()
            .expect("entry state mutex poisoned")
            .delete_attempts,
        1
    );
}

#[test]
fn maps_path_resolution_failures_to_soft_failure_outcome() {
    let path = PathBuf::from("missing/../config.toml");
    let keyring = ConfigKeyring::with_backend(TestBackend::new([]));

    let outcome = keyring.read_password(&path);

    match outcome {
        KeyringReadOutcome::SoftFailure(error) => {
            assert!(
                error
                    .to_string()
                    .contains("failed to resolve encrypted config path")
            );
            assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
        }
        other => panic!("expected soft failure outcome, got {other:?}"),
    }

    assert!(keyring.backend().calls().is_empty());
}
