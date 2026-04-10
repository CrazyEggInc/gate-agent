use gate_agent::auth::{AccessLevel, bearer};

#[test]
fn auth_module_exposes_bearer_surface_only() {
    fn accepts_access_level(_: Option<AccessLevel>) {}
    fn accepts_authorization_validator(
        _: fn(
            &str,
            &gate_agent::config::secrets::SecretsConfig,
        ) -> Result<bearer::AuthorizedRequest, gate_agent::error::AppError>,
    ) {
    }
    fn accepts_token_validator(
        _: fn(
            &str,
            &gate_agent::config::secrets::SecretsConfig,
        ) -> Result<bearer::AuthorizedRequest, gate_agent::error::AppError>,
    ) {
    }

    accepts_access_level(None);
    accepts_authorization_validator(bearer::validate_bearer_authorized_request);
    accepts_token_validator(bearer::validate_token);
}
