use std::env;
use std::io::IsTerminal;
use std::path::Path;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use tracing::debug;

use super::ConfigError;
use super::keyring::{
    ConfigKeyring, KeyringDeleteOutcome, KeyringReadOutcome, KeyringStoreOutcome,
};

pub const PASSWORD_ENV_VAR: &str = "GATE_AGENT_PASSWORD";
const TEST_PROMPT_PASSWORD_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_PASSWORD";
const TEST_PROMPT_CONFIRM_ENV_VAR: &str = "GATE_AGENT_TEST_PROMPT_CONFIRM";
const DISABLE_INTERACTIVE_ENV_VAR: &str = "GATE_AGENT_DISABLE_INTERACTIVE";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordArgs {
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordSource {
    Flag,
    Env,
    Keyring,
    Prompt,
}

#[derive(Clone, Debug)]
pub struct ResolvedPassword {
    pub password: SecretString,
    pub source: PasswordSource,
}

pub fn resolve_for_encrypted_read(
    args: &PasswordArgs,
    path: &Path,
) -> Result<SecretString, ConfigError> {
    Ok(resolve_for_encrypted_read_with_source(args, path)?.password)
}

pub fn resolve_for_encrypted_read_with_source(
    args: &PasswordArgs,
    path: &Path,
) -> Result<ResolvedPassword, ConfigError> {
    if let Some(password) = resolve_flag_password(args)? {
        return Ok(ResolvedPassword {
            password,
            source: PasswordSource::Flag,
        });
    }

    if let Some(password) = resolve_env_password()? {
        return Ok(ResolvedPassword {
            password,
            source: PasswordSource::Env,
        });
    }

    match ConfigKeyring::default().read_password(path) {
        KeyringReadOutcome::Found(password) => {
            debug!(config_path = %path.display(), "loaded encrypted config password from system keyring");
            return Ok(ResolvedPassword {
                password: validated_password("system keyring", &password)?,
                source: PasswordSource::Keyring,
            });
        }
        KeyringReadOutcome::Missing => {
            debug!(config_path = %path.display(), "no system keyring password found for encrypted config");
        }
        KeyringReadOutcome::SoftFailure(error) => {
            debug!(config_path = %path.display(), error = %error, "failed to read encrypted config password from system keyring");
        }
    }

    Ok(ResolvedPassword {
        password: prompt_password(
            &format!("Enter password for encrypted config '{}': ", path.display()),
            false,
            "encrypted config requires a password; use --password, GATE_AGENT_PASSWORD, or a stored system keyring entry in non-interactive sessions",
        )?,
        source: PasswordSource::Prompt,
    })
}

pub fn resolve_for_encrypted_create(
    args: &PasswordArgs,
    path: &Path,
) -> Result<ResolvedPassword, ConfigError> {
    if let Some(password) = resolve_flag_password(args)? {
        return Ok(ResolvedPassword {
            password,
            source: PasswordSource::Flag,
        });
    }

    if let Some(password) = resolve_env_password()? {
        return Ok(ResolvedPassword {
            password,
            source: PasswordSource::Env,
        });
    }

    let password = prompt_password(
        &format!(
            "Enter password for new encrypted config '{}': ",
            path.display()
        ),
        true,
        &format!(
            "encrypted config requires a password; use --password or {PASSWORD_ENV_VAR} in non-interactive sessions"
        ),
    )?;

    Ok(ResolvedPassword {
        password,
        source: PasswordSource::Prompt,
    })
}

pub fn remember_password_if_needed(path: &Path, resolved: &ResolvedPassword) {
    if matches!(resolved.source, PasswordSource::Keyring) {
        return;
    }

    match ConfigKeyring::default().store_password(path, resolved.password.expose_secret()) {
        KeyringStoreOutcome::Stored | KeyringStoreOutcome::SoftFailure(_) => {}
    }
}

pub fn forget_keyring_password_if_present(path: &Path) {
    match ConfigKeyring::default().delete_credential(path) {
        KeyringDeleteOutcome::Deleted
        | KeyringDeleteOutcome::Missing
        | KeyringDeleteOutcome::SoftFailure(_) => {}
    }
}

fn resolve_flag_password(args: &PasswordArgs) -> Result<Option<SecretString>, ConfigError> {
    args.password
        .as_deref()
        .map(|password| validated_password("--password", password))
        .transpose()
}

fn resolve_env_password() -> Result<Option<SecretString>, ConfigError> {
    env::var(PASSWORD_ENV_VAR)
        .ok()
        .map(|password| validated_password(PASSWORD_ENV_VAR, &password))
        .transpose()
}

fn prompt_password(
    prompt: &str,
    confirm: bool,
    non_interactive_message: &str,
) -> Result<SecretString, ConfigError> {
    if let Ok(password) = env::var(TEST_PROMPT_PASSWORD_ENV_VAR) {
        let first = validated_password("prompted password", &password)?;

        if !confirm {
            return Ok(first);
        }

        let second_value = env::var(TEST_PROMPT_CONFIRM_ENV_VAR).unwrap_or(password);
        let second = validated_password("password confirmation", &second_value)?;

        if secrecy::ExposeSecret::expose_secret(&first)
            != secrecy::ExposeSecret::expose_secret(&second)
        {
            return Err(ConfigError::new("passwords do not match"));
        }

        return Ok(first);
    }

    if env::var_os(DISABLE_INTERACTIVE_ENV_VAR).is_some()
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        return Err(ConfigError::new(non_interactive_message));
    }

    let first = rpassword::prompt_password(prompt).map_err(|error| {
        ConfigError::new(format!("failed to read password from terminal: {error}"))
    })?;
    let first = validated_password("prompted password", &first)?;

    if !confirm {
        return Ok(first);
    }

    let second = rpassword::prompt_password("Confirm password: ").map_err(|error| {
        ConfigError::new(format!("failed to read password confirmation: {error}"))
    })?;
    let second = validated_password("password confirmation", &second)?;

    if secrecy::ExposeSecret::expose_secret(&first) != secrecy::ExposeSecret::expose_secret(&second)
    {
        return Err(ConfigError::new("passwords do not match"));
    }

    Ok(first)
}

fn validated_password(source: &str, value: &str) -> Result<SecretString, ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::new(format!("{source} cannot be empty")));
    }

    Ok(SecretString::from(value.to_owned()))
}
