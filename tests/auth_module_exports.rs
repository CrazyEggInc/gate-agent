use gate_agent::auth::{JwtClaims, exchange, jwt};

#[test]
fn auth_module_exposes_exchange_and_jwt_modules() {
    fn accepts_claims_type(_: Option<JwtClaims>) {}
    fn accepts_exchange_request(_: Option<exchange::ExchangeRequest>) {}
    fn accepts_exchange_response(_: Option<exchange::ExchangeResponse>) {}
    fn accepts_jwt_validator(
        _: fn(
            &str,
            &gate_agent::config::secrets::SecretsConfig,
        ) -> Result<JwtClaims, gate_agent::error::AppError>,
    ) {
    }

    accepts_claims_type(None);
    accepts_exchange_request(None);
    accepts_exchange_response(None);
    accepts_jwt_validator(jwt::validate_token);
}
