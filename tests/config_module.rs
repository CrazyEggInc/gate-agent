use std::error::Error as _;

use gate_agent::config::{ConfigError, app_config, path, secrets, write};

#[test]
fn config_module_exports_expected_public_surface() {
    let _ = std::any::type_name::<app_config::AppConfig>();
    let _ = std::any::type_name::<secrets::SecretsConfig>();
    let _ = std::any::type_name::<path::ResolvedConfigPath>();
    let _ = std::any::type_name::<write::ApiUpsert>();
}

#[test]
fn config_error_is_fail_fast_and_displayable() {
    let error = ConfigError::new("config exploded");

    assert_eq!(error.to_string(), "config exploded");
    assert!(error.source().is_none());
}
