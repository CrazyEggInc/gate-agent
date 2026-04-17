use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor};
use secrecy::SecretString;

use super::ConfigError;

const AGE_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const MAX_SCRYPT_WORK_FACTOR: u8 = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFileFormat {
    PlaintextToml,
    AgeEncryptedToml,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectedConfigFormat {
    PlaintextToml,
    AgeEncryptedToml,
    InvalidNonUtf8,
}

impl From<ConfigFileFormat> for DetectedConfigFormat {
    fn from(value: ConfigFileFormat) -> Self {
        match value {
            ConfigFileFormat::PlaintextToml => Self::PlaintextToml,
            ConfigFileFormat::AgeEncryptedToml => Self::AgeEncryptedToml,
        }
    }
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

pub fn detect_format_from_bytes(contents: &[u8]) -> DetectedConfigFormat {
    match std::str::from_utf8(contents) {
        Ok(contents) => detect_format(contents).into(),
        Err(_) => detect_binary_age_format(contents),
    }
}

pub fn invalid_non_utf8_config_error(path: &Path) -> ConfigError {
    ConfigError::new(format!(
        "config file '{}' is not valid utf-8 and is not a supported age-encrypted file",
        path.display()
    ))
}

pub fn resolve_format_from_bytes(
    path: &Path,
    contents: &[u8],
) -> Result<ConfigFileFormat, ConfigError> {
    match detect_format_from_bytes(contents) {
        DetectedConfigFormat::PlaintextToml => Ok(ConfigFileFormat::PlaintextToml),
        DetectedConfigFormat::AgeEncryptedToml => Ok(ConfigFileFormat::AgeEncryptedToml),
        DetectedConfigFormat::InvalidNonUtf8 => Err(invalid_non_utf8_config_error(path)),
    }
}

fn detect_binary_age_format(contents: &[u8]) -> DetectedConfigFormat {
    match Decryptor::new_buffered(Cursor::new(contents)) {
        Ok(_) => DetectedConfigFormat::AgeEncryptedToml,
        Err(_) => DetectedConfigFormat::InvalidNonUtf8,
    }
}

pub fn load_config_text(
    path: &Path,
    password: Option<&SecretString>,
) -> Result<LoadedConfigText, ConfigError> {
    let contents = fs::read(path).map_err(|error| {
        ConfigError::new(format!(
            "failed to read config file '{}': {error}",
            path.display()
        ))
    })?;

    let format = resolve_format_from_bytes(path, &contents)?;
    let toml = match format {
        ConfigFileFormat::PlaintextToml => String::from_utf8(contents).map_err(|error| {
            ConfigError::new(format!(
                "plaintext config file '{}' is not valid utf-8: {error}",
                path.display()
            ))
        })?,
        ConfigFileFormat::AgeEncryptedToml => {
            let password = password.ok_or_else(|| {
                ConfigError::new(format!(
                    "encrypted config '{}' requires a password",
                    path.display()
                ))
            })?;
            decrypt_bytes(&contents, password, path)?
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
    decrypt_bytes(ciphertext.as_bytes(), password, path)
}

pub fn decrypt_bytes(
    ciphertext: &[u8],
    password: &SecretString,
    path: &Path,
) -> Result<String, ConfigError> {
    if let Ok(decryptor) = Decryptor::new_buffered(ArmoredReader::new(ciphertext)) {
        return decrypt_with_decryptor(decryptor, password, path);
    }

    let decryptor = Decryptor::new_buffered(Cursor::new(ciphertext)).map_err(|error| {
        ConfigError::new(format!(
            "failed to parse encrypted config file '{}': {error}",
            path.display()
        ))
    })?;

    decrypt_with_decryptor(decryptor, password, path)
}

fn decrypt_with_decryptor<R: Read>(
    decryptor: Decryptor<R>,
    password: &SecretString,
    path: &Path,
) -> Result<String, ConfigError> {
    if !decryptor.is_scrypt() {
        return Err(ConfigError::new(format!(
            "config file '{}' is encrypted with an unsupported age mode",
            path.display()
        )));
    }

    let mut identity = age::scrypt::Identity::new(password.clone());
    identity.set_max_work_factor(MAX_SCRYPT_WORK_FACTOR);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|error| map_decrypt_error(error, path))?;

    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext).map_err(|error| {
        ConfigError::new(format!(
            "failed to decrypt config file '{}': {error}",
            path.display()
        ))
    })?;

    Ok(plaintext)
}

fn map_decrypt_error(error: age::DecryptError, path: &Path) -> ConfigError {
    match error {
        age::DecryptError::DecryptionFailed
        | age::DecryptError::KeyDecryptionFailed
        | age::DecryptError::NoMatchingKeys => ConfigError::new(format!(
            "invalid password for config file '{}'",
            path.display()
        )),
        age::DecryptError::ExcessiveWork { required, .. } => ConfigError::new(format!(
            "config file '{}' requires scrypt work factor {required}, maximum supported is {MAX_SCRYPT_WORK_FACTOR}",
            path.display()
        )),
        age::DecryptError::InvalidHeader | age::DecryptError::InvalidMac => {
            ConfigError::new(format!(
                "encrypted config file '{}' is malformed or corrupted: {error}",
                path.display()
            ))
        }
        age::DecryptError::UnknownFormat => ConfigError::new(format!(
            "encrypted config file '{}' uses an unknown or unsupported age format: {error}",
            path.display()
        )),
        other => ConfigError::new(format!(
            "failed to decrypt config file '{}': {other}",
            path.display()
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;

    fn encrypt_binary(
        plaintext: &str,
        password: &SecretString,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let encryptor = Encryptor::with_user_passphrase(password.clone());
        let mut output = Vec::new();
        let mut writer = encryptor.wrap_output(&mut output)?;
        writer.write_all(plaintext.as_bytes())?;
        writer.finish()?;

        Ok(output)
    }

    fn encrypt_armored_with_work_factor(
        plaintext: &str,
        password: &SecretString,
        work_factor: u8,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut recipient = age::scrypt::Recipient::new(password.clone());
        recipient.set_work_factor(work_factor);

        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as _))?;
        let mut output = Vec::new();
        let armored = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)?;
        let mut writer = encryptor.wrap_output(armored)?;
        writer.write_all(plaintext.as_bytes())?;
        let armored = writer.finish()?;
        armored.finish()?;

        Ok(String::from_utf8(output)?)
    }

    fn encrypt_armored_with_x25519_recipient(
        plaintext: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as _))?;
        let mut output = Vec::new();
        let armored = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)?;
        let mut writer = encryptor.wrap_output(armored)?;
        writer.write_all(plaintext.as_bytes())?;
        let armored = writer.finish()?;
        armored.finish()?;

        Ok(String::from_utf8(output)?)
    }

    #[test]
    fn detect_format_from_bytes_classifies_plaintext_utf8() {
        assert_eq!(
            detect_format_from_bytes(b"[server]\nport = 8787\n"),
            DetectedConfigFormat::PlaintextToml
        );
    }

    #[test]
    fn detect_format_from_bytes_classifies_armored_age_utf8()
    -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretString::from("top-secret-password".to_owned());
        let ciphertext = encrypt_string("[server]\nport = 8787\n", &password)?;

        assert_eq!(
            detect_format_from_bytes(ciphertext.as_bytes()),
            DetectedConfigFormat::AgeEncryptedToml
        );

        Ok(())
    }

    #[test]
    fn detect_format_from_bytes_classifies_binary_age_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretString::from("top-secret-password".to_owned());
        let ciphertext = encrypt_binary("[server]\nport = 8787\n", &password)?;

        assert_eq!(
            detect_format_from_bytes(&ciphertext),
            DetectedConfigFormat::AgeEncryptedToml
        );

        Ok(())
    }

    #[test]
    fn detect_format_from_bytes_rejects_arbitrary_non_utf8_bytes() {
        assert_eq!(
            detect_format_from_bytes(&[0xff, 0xfe, 0x00, 0x80]),
            DetectedConfigFormat::InvalidNonUtf8
        );
    }

    #[test]
    fn load_config_text_rejects_arbitrary_non_utf8_non_age_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("gate-agent.bin");
        fs::write(&path, [0xff, 0xfe, 0x00, 0x80])?;

        let error = load_config_text(&path, None).expect_err("invalid bytes should fail");

        assert_eq!(
            error.to_string(),
            format!(
                "config file '{}' is not valid utf-8 and is not a supported age-encrypted file",
                path.display()
            )
        );

        Ok(())
    }

    #[test]
    fn load_config_text_decrypts_binary_age_config() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("gate-agent.age");
        let password = SecretString::from("top-secret-password".to_owned());
        let plaintext = r#"
[clients.default]
bearer_token_id = "0011223344556677"
bearer_token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = { projects = "read" }

[groups]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#;

        let encryptor = Encryptor::with_user_passphrase(password.clone());
        let mut output = Vec::new();
        let mut writer = encryptor.wrap_output(&mut output)?;
        writer.write_all(plaintext.as_bytes())?;
        writer.finish()?;
        fs::write(&path, &output)?;

        let loaded = load_config_text(&path, Some(&password))?;

        assert_eq!(loaded.format, ConfigFileFormat::AgeEncryptedToml);
        assert_eq!(loaded.toml, plaintext);

        Ok(())
    }

    #[test]
    fn decrypt_string_accepts_scrypt_work_factor_eighteen() -> Result<(), Box<dyn std::error::Error>>
    {
        let password = SecretString::from("top-secret-password".to_owned());
        let plaintext = "[clients.default]\napi_access = { projects = \"read\" }\n";
        let ciphertext = encrypt_armored_with_work_factor(plaintext, &password, 18)?;

        let decrypted = decrypt_string(&ciphertext, &password, Path::new("config.age"))?;

        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn decrypt_string_keeps_invalid_password_message() -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretString::from("top-secret-password".to_owned());
        let wrong_password = SecretString::from("wrong-password".to_owned());
        let plaintext = "[clients.default]\napi_access = { projects = \"read\" }\n";
        let ciphertext = encrypt_string(plaintext, &password)?;

        let error = decrypt_string(&ciphertext, &wrong_password, Path::new("config.age"))
            .expect_err("wrong password should fail");

        assert_eq!(
            error.to_string(),
            "invalid password for config file 'config.age'"
        );

        Ok(())
    }

    #[test]
    fn decrypt_string_rejects_x25519_age_mode_with_exact_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretString::from("top-secret-password".to_owned());
        let plaintext = "[clients.default]\napi_access = { projects = \"read\" }\n";
        let ciphertext = encrypt_armored_with_x25519_recipient(plaintext)?;

        let error = decrypt_string(&ciphertext, &password, Path::new("config.age"))
            .expect_err("x25519 mode should fail");

        assert_eq!(
            error.to_string(),
            "config file 'config.age' is encrypted with an unsupported age mode"
        );

        Ok(())
    }

    #[test]
    fn decrypt_string_reports_parse_error_for_malformed_input() {
        let password = SecretString::from("top-secret-password".to_owned());
        let ciphertext =
            "-----BEGIN AGE ENCRYPTED FILE-----\nnot-age\n-----END AGE ENCRYPTED FILE-----\n";

        let error = decrypt_string(ciphertext, &password, Path::new("config.age"))
            .expect_err("malformed input should fail");

        let message = error.to_string();
        assert!(
            message.starts_with("failed to parse encrypted config file 'config.age':"),
            "unexpected error: {message}"
        );
        assert_ne!(message, "invalid password for config file 'config.age'");
    }

    #[test]
    fn decrypt_string_reports_corrupted_ciphertext_not_invalid_password()
    -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretString::from("top-secret-password".to_owned());
        let plaintext = "[clients.default]\napi_access = { projects = \"read\" }\n";
        let ciphertext = encrypt_string(plaintext, &password)?;
        let mut lines: Vec<String> = ciphertext.lines().map(str::to_owned).collect();
        let payload_line = lines
            .iter_mut()
            .find(|line| !line.starts_with("-----") && !line.is_empty())
            .expect("armored ciphertext should contain payload");
        let replacement = if payload_line.starts_with('A') {
            "B"
        } else {
            "A"
        };
        payload_line.replace_range(0..1, replacement);
        let corrupted = format!("{}\n", lines.join("\n"));

        let error = decrypt_string(&corrupted, &password, Path::new("config.age"))
            .expect_err("corrupted ciphertext should fail");

        let message = error.to_string();
        assert!(
            message.contains("malformed or corrupted")
                || message.starts_with("failed to parse encrypted config file 'config.age':"),
            "unexpected error: {message}"
        );
        assert_ne!(message, "invalid password for config file 'config.age'");

        Ok(())
    }

    #[test]
    fn decrypt_error_surfaces_excessive_work_factor() {
        let error = map_decrypt_error(
            age::DecryptError::ExcessiveWork {
                required: 31,
                target: 18,
            },
            Path::new("config.age"),
        );

        let message = error.to_string();
        assert!(
            message.contains("work factor"),
            "unexpected error: {message}"
        );
        assert!(message.contains("30"), "unexpected error: {message}");
        assert!(
            !message.contains("invalid password"),
            "unexpected error: {message}"
        );
    }
}
