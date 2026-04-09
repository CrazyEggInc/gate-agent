use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor};
use secrecy::SecretString;

use super::ConfigError;

const AGE_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFileFormat {
    PlaintextToml,
    AgeEncryptedToml,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedConfigText {
    pub path: PathBuf,
    pub format: ConfigFileFormat,
    pub toml: String,
}

pub fn detect_format(contents: &str) -> ConfigFileFormat {
    if contents.starts_with(AGE_HEADER) {
        ConfigFileFormat::AgeEncryptedToml
    } else {
        ConfigFileFormat::PlaintextToml
    }
}

pub fn load_config_text(
    path: &Path,
    password: Option<&SecretString>,
) -> Result<LoadedConfigText, ConfigError> {
    let contents = fs::read_to_string(path).map_err(|error| {
        ConfigError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })?;

    let format = detect_format(&contents);
    let toml = match format {
        ConfigFileFormat::PlaintextToml => contents,
        ConfigFileFormat::AgeEncryptedToml => {
            let password = password.ok_or_else(|| {
                ConfigError::new(format!(
                    "encrypted config '{}' requires a password",
                    path.display()
                ))
            })?;
            decrypt_string(&contents, password, path)?
        }
    };

    Ok(LoadedConfigText {
        path: path.to_path_buf(),
        format,
        toml,
    })
}

pub fn encrypt_string(plaintext: &str, password: &SecretString) -> Result<String, ConfigError> {
    let encryptor = Encryptor::with_user_passphrase(password.clone());
    let mut output = Vec::new();
    let armored = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
        .map_err(|error| ConfigError::new(format!("failed to start age armor writer: {error}")))?;
    let mut writer = encryptor
        .wrap_output(armored)
        .map_err(|error| ConfigError::new(format!("failed to start config encryption: {error}")))?;

    writer
        .write_all(plaintext.as_bytes())
        .map_err(|error| ConfigError::new(format!("failed to encrypt config: {error}")))?;

    let armored = writer.finish().map_err(|error| {
        ConfigError::new(format!("failed to finish config encryption: {error}"))
    })?;
    armored.finish().map_err(|error| {
        ConfigError::new(format!("failed to finish armored config output: {error}"))
    })?;

    String::from_utf8(output)
        .map_err(|error| ConfigError::new(format!("encrypted config output is not utf-8: {error}")))
}

pub fn decrypt_string(
    ciphertext: &str,
    password: &SecretString,
    path: &Path,
) -> Result<String, ConfigError> {
    let armored = ArmoredReader::new(ciphertext.as_bytes());
    let decryptor = Decryptor::new_buffered(armored).map_err(|error| {
        ConfigError::new(format!(
            "failed to parse encrypted config file '{}': {error}",
            path.display()
        ))
    })?;

    if !decryptor.is_scrypt() {
        return Err(ConfigError::new(format!(
            "config file '{}' is encrypted with an unsupported age mode",
            path.display()
        )));
    }

    let identity = age::scrypt::Identity::new(password.clone());
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| {
            ConfigError::new(format!(
                "invalid password for config file '{}'",
                path.display()
            ))
        })?;

    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext).map_err(|error| {
        ConfigError::new(format!(
            "failed to decrypt config file '{}': {error}",
            path.display()
        ))
    })?;

    Ok(plaintext)
}

pub fn serialize_for_format(
    format: &ConfigFileFormat,
    plaintext: &str,
    password: Option<&SecretString>,
) -> Result<String, ConfigError> {
    match format {
        ConfigFileFormat::PlaintextToml => Ok(plaintext.to_owned()),
        ConfigFileFormat::AgeEncryptedToml => {
            let password = password
                .ok_or_else(|| ConfigError::new("encrypted config write requires a password"))?;
            encrypt_string(plaintext, password)
        }
    }
}

pub fn write_config_file_atomic(path: &Path, contents: &str) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            ConfigError::new(format!(
                "failed to create config directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        ConfigError::new(format!(
            "failed to create temporary config file near '{}': {error}",
            path.display()
        ))
    })?;
    temp_file.write_all(contents.as_bytes()).map_err(|error| {
        ConfigError::new(format!(
            "failed to write temporary config file near '{}': {error}",
            path.display()
        ))
    })?;
    temp_file.flush().map_err(|error| {
        ConfigError::new(format!(
            "failed to flush temporary config file near '{}': {error}",
            path.display()
        ))
    })?;

    temp_file.persist(path).map_err(|error| {
        ConfigError::new(format!(
            "failed to replace config file '{}': {}",
            path.display(),
            error.error
        ))
    })?;

    Ok(())
}
