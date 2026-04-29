use gate_agent::auth::{ApiAccessMethod, ApiAccessRule, bearer};

#[test]
fn auth_module_exposes_bearer_surface_only() {
    fn accepts_api_access_method(_: Option<ApiAccessMethod>) {}
    fn accepts_api_access_rule(_: Option<ApiAccessRule>) {}
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

    accepts_api_access_method(None);
    accepts_api_access_rule(None);
    accepts_authorization_validator(bearer::validate_bearer_authorized_request);
    accepts_token_validator(bearer::validate_token);
}
