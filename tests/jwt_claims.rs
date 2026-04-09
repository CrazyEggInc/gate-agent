use gate_agent::auth::JwtClaims;
use serde_json::json;

#[test]
fn jwt_claims_serialize_with_updated_contract_and_sorted_apis() {
    let claims = JwtClaims::new(
        "client-a",
        [
            "zeta".to_owned(),
            "alpha".to_owned(),
            "billing".to_owned(),
            "alpha".to_owned(),
        ],
        "gate-agent-dev",
        "gate-agent-clients",
        1_700_000_000,
        1_700_000_300,
    );

    let serialized = serde_json::to_value(&claims).expect("claims serialize");

    assert_eq!(
        serialized,
        json!({
            "sub": "client-a",
            "apis": ["alpha", "billing", "zeta"],
            "iss": "gate-agent-dev",
            "aud": "gate-agent-clients",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300
        })
    );
}

#[test]
fn jwt_claims_deserialize_from_updated_contract_shape() {
    let claims: JwtClaims = serde_json::from_value(json!({
        "sub": "client-a",
        "apis": ["projects", "billing", "projects"],
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect("claims deserialize");

    assert_eq!(claims.sub, "client-a");
    assert_eq!(claims.apis(), vec!["billing", "projects"]);
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");
    assert_eq!(claims.iat, 1_700_000_000);
    assert_eq!(claims.exp, 1_700_000_300);
}

#[test]
fn jwt_claims_reject_unknown_single_api_wire_field() {
    let error = serde_json::from_value::<JwtClaims>(json!({
        "sub": "client-a",
        "api": "projects",
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect_err("unknown api field should be rejected");

    assert!(error.to_string().contains("unknown field `api`"));
}
