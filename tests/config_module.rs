use std::error::Error as _;
use std::fs;

use gate_agent::config::{ConfigError, app_config, password, path, secrets, write};

#[test]
fn config_module_exports_expected_public_surface() {
    let _ = std::any::type_name::<app_config::AppConfig>();
    let _ = std::any::type_name::<secrets::SecretsConfig>();
    let _ = std::any::type_name::<path::ResolvedConfigPath>();
    let _ = std::any::type_name::<write::ApiUpsert>();
    let _ = std::any::type_name::<password::PasswordArgs>();

    assert_eq!(password::PASSWORD_ENV_VAR, "GATE_AGENT_PASSWORD");
}

#[test]
fn config_module_keeps_keyring_internal_to_config() {
    let mod_rs = fs::read_to_string(format!("{}/src/config/mod.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("config mod should be readable");

    assert!(mod_rs.contains("pub(crate) mod keyring;"));
    assert!(!mod_rs.contains("pub mod keyring;"));
}

#[test]
fn config_error_is_fail_fast_and_displayable() {
    let error = ConfigError::new("config exploded");

    assert_eq!(error.to_string(), "config exploded");
    assert!(error.source().is_none());
}
