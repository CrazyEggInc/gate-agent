use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use secrecy::{ExposeSecret, SecretString};
use tempfile::tempdir;

mod config {
    pub use gate_agent::config::ConfigError;

    #[allow(dead_code)]
    pub mod keyring {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/config/keyring.rs"
        ));
    }

    #[allow(dead_code)]
    pub mod password {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/config/password.rs"
        ));
    }
}

use config::keyring::{ConfigKeyring, KeyringReadOutcome, KeyringStoreOutcome};
use config::password::{
    PASSWORD_ENV_VAR, PasswordArgs, PasswordSource, ResolvedPassword,
    forget_keyring_password_if_present, remember_password_if_needed, resolve_for_encrypted_create,
    resolve_for_encrypted_read_with_source,
};

const TEST_PROMPT_PASSWORD_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_PASSWORD";
const TEST_PROMPT_CONFIRM_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_CONFIRM";
const TEST_KEYRING_FILE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_FILE";
const TEST_KEYRING_STORE_FAILURE_ENV_VAR: &str = "GATE_AGENT_TEST_KEYRING_STORE_FAILURE";

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
    }
}

fn write_existing_config_file(
    name: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join(name);
    fs::write(&config_path, "placeholder")?;
    Ok((temp_dir, config_path))
}

fn write_keyring_store_file(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, contents)?;
    Ok(())
}

fn seed_keyring_password(
    config_path: &Path,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match ConfigKeyring::default().store_password(config_path, password) {
        KeyringStoreOutcome::Stored => Ok(()),
        outcome => Err(format!("expected stored outcome, got {outcome:?}").into()),
    }
}

#[test]
fn encrypted_read_prefers_flag_then_env_then_keyring_then_prompt()
-> Result<(), Box<dyn std::error::Error>> {
    struct Case {
        name: &'static str,
        flag_password: Option<&'static str>,
        env_password: Option<&'static str>,
        keyring_password: Option<&'static str>,
        prompt_password: Option<&'static str>,
        expected_password: &'static str,
        expected_source: PasswordSource,
    }

    let cases = [
        Case {
            name: "flag beats env, keyring, and prompt",
            flag_password: Some("flag-passphrase"),
            env_password: Some("env-passphrase"),
            keyring_password: Some("keyring-passphrase"),
            prompt_password: Some("prompt-passphrase"),
            expected_password: "flag-passphrase",
            expected_source: PasswordSource::Flag,
        },
        Case {
            name: "env beats keyring and prompt",
            flag_password: None,
            env_password: Some("env-passphrase"),
            keyring_password: Some("keyring-passphrase"),
            prompt_password: Some("prompt-passphrase"),
            expected_password: "env-passphrase",
            expected_source: PasswordSource::Env,
        },
        Case {
            name: "keyring beats prompt",
            flag_password: None,
            env_password: None,
            keyring_password: Some("keyring-passphrase"),
            prompt_password: Some("prompt-passphrase"),
            expected_password: "keyring-passphrase",
            expected_source: PasswordSource::Keyring,
        },
        Case {
            name: "prompt used when higher-priority sources are absent",
            flag_password: None,
            env_password: None,
            keyring_password: None,
            prompt_password: Some("prompt-passphrase"),
            expected_password: "prompt-passphrase",
            expected_source: PasswordSource::Prompt,
        },
    ];

    for case in cases {
        let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
        let keyring_path = config_path.with_extension("keyring.json");
        let keyring_path_value = keyring_path.to_string_lossy().into_owned();
        let _env_guard = PasswordEnvGuard::set(&[
            (PASSWORD_ENV_VAR, case.env_password),
            (TEST_PROMPT_PASSWORD_ENV_VAR, case.prompt_password),
            (TEST_PROMPT_CONFIRM_ENV_VAR, case.prompt_password),
            (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
            (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
        ]);

        if let Some(password) = case.keyring_password {
            seed_keyring_password(&config_path, password)?;
        }

        let resolved = resolve_for_encrypted_read_with_source(
            &PasswordArgs {
                password: case.flag_password.map(str::to_owned),
            },
            &config_path,
        )?;

        assert_eq!(
            resolved.password.expose_secret(),
            case.expected_password,
            "case {}",
            case.name
        );
        assert_eq!(resolved.source, case.expected_source, "case {}", case.name);
    }

    Ok(())
}

#[test]
fn encrypted_read_uses_prompt_after_keyring_soft_failure() -> Result<(), Box<dyn std::error::Error>>
{
    let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
    let keyring_path = config_path.with_extension("keyring.json");
    let keyring_path_value = keyring_path.to_string_lossy().into_owned();
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_PASSWORD_ENV_VAR, Some("prompt-passphrase")),
        (TEST_PROMPT_CONFIRM_ENV_VAR, Some("prompt-passphrase")),
        (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
    ]);

    write_keyring_store_file(&keyring_path, "not-json")?;

    let resolved =
        resolve_for_encrypted_read_with_source(&PasswordArgs { password: None }, &config_path)?;

    assert_eq!(resolved.source, PasswordSource::Prompt);
    assert_eq!(resolved.password.expose_secret(), "prompt-passphrase");

    Ok(())
}

#[test]
fn encrypted_create_prefers_flag_then_env_then_prompt() -> Result<(), Box<dyn std::error::Error>> {
    struct Case {
        name: &'static str,
        flag_password: Option<&'static str>,
        env_password: Option<&'static str>,
        prompt_password: Option<&'static str>,
        expected_password: &'static str,
        expected_source: PasswordSource,
    }

    let cases = [
        Case {
            name: "flag beats env and prompt",
            flag_password: Some("flag-passphrase"),
            env_password: Some("env-passphrase"),
            prompt_password: Some("prompt-passphrase"),
            expected_password: "flag-passphrase",
            expected_source: PasswordSource::Flag,
        },
        Case {
            name: "env beats prompt",
            flag_password: None,
            env_password: Some("env-passphrase"),
            prompt_password: Some("prompt-passphrase"),
            expected_password: "env-passphrase",
            expected_source: PasswordSource::Env,
        },
        Case {
            name: "prompt used when flag and env are absent",
            flag_password: None,
            env_password: None,
            prompt_password: Some("prompt-passphrase"),
            expected_password: "prompt-passphrase",
            expected_source: PasswordSource::Prompt,
        },
    ];

    for case in cases {
        let temp_dir = tempdir()?;
        let config_path = temp_dir.path().join("new-config.toml");
        let _env_guard = PasswordEnvGuard::set(&[
            (PASSWORD_ENV_VAR, case.env_password),
            (TEST_PROMPT_PASSWORD_ENV_VAR, case.prompt_password),
            (TEST_PROMPT_CONFIRM_ENV_VAR, case.prompt_password),
            (TEST_KEYRING_FILE_ENV_VAR, None),
            (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
        ]);

        let resolved = resolve_for_encrypted_create(
            &PasswordArgs {
                password: case.flag_password.map(str::to_owned),
            },
            &config_path,
        )?;

        assert_eq!(
            resolved.password.expose_secret(),
            case.expected_password,
            "case {}",
            case.name
        );
        assert_eq!(resolved.source, case.expected_source, "case {}", case.name);
    }

    Ok(())
}

#[test]
fn rejects_empty_flag_env_and_keyring_passwords() -> Result<(), Box<dyn std::error::Error>> {
    let flag_error = resolve_for_encrypted_create(
        &PasswordArgs {
            password: Some("   ".to_owned()),
        },
        Path::new("new-config.toml"),
    )
    .unwrap_err();
    assert_eq!(flag_error.to_string(), "--password cannot be empty");

    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, Some("   ")),
        (TEST_PROMPT_PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_CONFIRM_ENV_VAR, None),
        (TEST_KEYRING_FILE_ENV_VAR, None),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
    ]);
    let env_error = resolve_for_encrypted_create(
        &PasswordArgs { password: None },
        Path::new("new-config.toml"),
    )
    .unwrap_err();
    assert_eq!(env_error.to_string(), "GATE_AGENT_PASSWORD cannot be empty");
    drop(_env_guard);

    let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
    let keyring_path = config_path.with_extension("keyring.json");
    let keyring_path_value = keyring_path.to_string_lossy().into_owned();
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_CONFIRM_ENV_VAR, None),
        (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
    ]);
    seed_keyring_password(&config_path, "")?;

    let keyring_error =
        resolve_for_encrypted_read_with_source(&PasswordArgs { password: None }, &config_path)
            .unwrap_err();
    assert_eq!(keyring_error.to_string(), "system keyring cannot be empty");

    Ok(())
}

#[test]
fn encrypted_create_rejects_prompt_confirmation_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_PASSWORD_ENV_VAR, Some("first-passphrase")),
        (TEST_PROMPT_CONFIRM_ENV_VAR, Some("second-passphrase")),
        (TEST_KEYRING_FILE_ENV_VAR, None),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
    ]);

    let error = resolve_for_encrypted_create(
        &PasswordArgs { password: None },
        Path::new("new-config.toml"),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "passwords do not match");

    Ok(())
}

#[test]
fn encrypted_read_and_create_fail_in_non_interactive_mode_without_other_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
    let keyring_path = config_path.with_extension("keyring.json");
    let keyring_path_value = keyring_path.to_string_lossy().into_owned();
    let _env_guard = PasswordEnvGuard::set(&[
        (PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_CONFIRM_ENV_VAR, None),
        (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
    ]);

    let read_error =
        resolve_for_encrypted_read_with_source(&PasswordArgs { password: None }, &config_path)
            .unwrap_err();
    assert_eq!(
        read_error.to_string(),
        "encrypted config requires a password; use --password, GATE_AGENT_PASSWORD, or a stored system keyring entry in non-interactive sessions"
    );

    let create_error = resolve_for_encrypted_create(
        &PasswordArgs { password: None },
        Path::new("new-config.toml"),
    )
    .unwrap_err();
    assert_eq!(
        create_error.to_string(),
        "encrypted config requires a password; use --password or GATE_AGENT_PASSWORD in non-interactive sessions"
    );

    Ok(())
}

#[test]
fn remember_password_only_backfills_when_source_is_not_keyring()
-> Result<(), Box<dyn std::error::Error>> {
    struct Case {
        name: &'static str,
        source: PasswordSource,
        password: &'static str,
    }

    let cases = [
        Case {
            name: "flag source",
            source: PasswordSource::Flag,
            password: "flag-passphrase",
        },
        Case {
            name: "env source",
            source: PasswordSource::Env,
            password: "env-passphrase",
        },
        Case {
            name: "prompt source",
            source: PasswordSource::Prompt,
            password: "prompt-passphrase",
        },
    ];

    for case in cases {
        let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
        let keyring_path = config_path.with_extension("keyring.json");
        let keyring_path_value = keyring_path.to_string_lossy().into_owned();
        let _env_guard = PasswordEnvGuard::set(&[
            (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
            (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
            (PASSWORD_ENV_VAR, None),
            (TEST_PROMPT_PASSWORD_ENV_VAR, None),
            (TEST_PROMPT_CONFIRM_ENV_VAR, None),
        ]);

        remember_password_if_needed(
            &config_path,
            &ResolvedPassword {
                password: SecretString::from(case.password.to_owned()),
                source: case.source.clone(),
            },
        );

        match ConfigKeyring::default().read_password(&config_path) {
            KeyringReadOutcome::Found(password) => {
                assert_eq!(password, case.password, "case {}", case.name)
            }
            outcome => panic!("case {} expected found outcome, got {outcome:?}", case.name),
        }
    }

    let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
    let keyring_path = config_path.with_extension("keyring.json");
    let keyring_path_value = keyring_path.to_string_lossy().into_owned();
    let _env_guard = PasswordEnvGuard::set(&[
        (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
        (PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_CONFIRM_ENV_VAR, None),
    ]);
    seed_keyring_password(&config_path, "existing-keyring-passphrase")?;

    remember_password_if_needed(
        &config_path,
        &ResolvedPassword {
            password: SecretString::from("replacement-passphrase".to_owned()),
            source: PasswordSource::Keyring,
        },
    );

    match ConfigKeyring::default().read_password(&config_path) {
        KeyringReadOutcome::Found(password) => {
            assert_eq!(password, "existing-keyring-passphrase")
        }
        outcome => panic!("expected found outcome, got {outcome:?}"),
    }

    Ok(())
}

#[test]
fn forget_keyring_password_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, config_path) = write_existing_config_file("encrypted.toml")?;
    let keyring_path = config_path.with_extension("keyring.json");
    let keyring_path_value = keyring_path.to_string_lossy().into_owned();
    let _env_guard = PasswordEnvGuard::set(&[
        (TEST_KEYRING_FILE_ENV_VAR, Some(keyring_path_value.as_str())),
        (TEST_KEYRING_STORE_FAILURE_ENV_VAR, None),
        (PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_PASSWORD_ENV_VAR, None),
        (TEST_PROMPT_CONFIRM_ENV_VAR, None),
    ]);
    seed_keyring_password(&config_path, "stored-passphrase")?;

    forget_keyring_password_if_present(&config_path);

    assert!(matches!(
        ConfigKeyring::default().read_password(&config_path),
        KeyringReadOutcome::Missing
    ));

    forget_keyring_password_if_present(&config_path);

    assert!(matches!(
        ConfigKeyring::default().read_password(&config_path),
        KeyringReadOutcome::Missing
    ));

    Ok(())
}
