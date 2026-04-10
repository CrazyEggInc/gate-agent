use gate_agent::auth::{AccessLevel, JwtClaims};
use serde::Deserialize;
use serde_json::Deserializer;
use serde_json::json;

#[test]
fn jwt_claims_serialize_with_updated_contract_and_sorted_api_access() {
    let claims = JwtClaims::new(
        "client-a",
        [
            ("billing".to_owned(), AccessLevel::Write),
            ("Alpha".to_owned(), AccessLevel::Read),
            ("alpha".to_owned(), AccessLevel::Read),
        ],
        "gate-agent-dev",
        "gate-agent-clients",
        1_700_000_000,
        1_700_000_300,
    )
    .expect("claims build");

    let serialized = serde_json::to_value(&claims).expect("claims serialize");

    assert_eq!(
        serialized,
        json!({
            "sub": "client-a",
            "apis": {
                "alpha": "read",
                "billing": "write"
            },
            "iss": "gate-agent-dev",
            "aud": "gate-agent-clients",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300
        })
    );
}

#[test]
fn jwt_claims_constructor_keeps_strongest_access_regardless_of_duplicate_order() {
    let read_then_write = JwtClaims::new(
        "client-a",
        [
            ("Projects".to_owned(), AccessLevel::Read),
            ("projects".to_owned(), AccessLevel::Write),
        ],
        "gate-agent-dev",
        "gate-agent-clients",
        1_700_000_000,
        1_700_000_300,
    )
    .expect("claims build");
    let write_then_read = JwtClaims::new(
        "client-a",
        [
            ("projects".to_owned(), AccessLevel::Write),
            ("Projects".to_owned(), AccessLevel::Read),
        ],
        "gate-agent-dev",
        "gate-agent-clients",
        1_700_000_000,
        1_700_000_300,
    )
    .expect("claims build");

    let expected = [("projects".to_owned(), AccessLevel::Write)]
        .into_iter()
        .collect();

    assert_eq!(read_then_write.apis, expected);
    assert_eq!(write_then_read.apis, expected);
}

#[test]
fn jwt_claims_deserialize_from_updated_contract_shape() {
    let claims: JwtClaims = serde_json::from_value(json!({
        "sub": "client-a",
        "apis": {
            "projects": "read",
            "billing": "write"
        },
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect("claims deserialize");

    assert_eq!(claims.sub, "client-a");
    assert_eq!(
        claims.apis,
        [
            ("billing".to_owned(), AccessLevel::Write),
            ("projects".to_owned(), AccessLevel::Read),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");
    assert_eq!(claims.iat, 1_700_000_000);
    assert_eq!(claims.exp, 1_700_000_300);
}

#[test]
fn jwt_claims_reject_uppercase_api_slug() {
    let error = serde_json::from_value::<JwtClaims>(json!({
        "sub": "client-a",
        "apis": {
            "Projects": "write"
        },
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect_err("uppercase api slug should be rejected");

    assert!(
        error
            .to_string()
            .contains("invalid api slug `Projects` in jwt claims")
    );
}

#[test]
fn jwt_claims_reject_api_slug_with_trailing_space() {
    let error = serde_json::from_value::<JwtClaims>(json!({
        "sub": "client-a",
        "apis": {
            "projects ": "write"
        },
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect_err("api slug with trailing space should be rejected");

    assert!(
        error
            .to_string()
            .contains("invalid api slug `projects ` in jwt claims")
    );
}

#[test]
fn jwt_claims_reject_blank_api_slug() {
    let error = serde_json::from_value::<JwtClaims>(json!({
        "sub": "client-a",
        "apis": {
            "   ": "read"
        },
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect_err("blank api slug should be rejected");

    assert!(
        error
            .to_string()
            .contains("invalid api slug `   ` in jwt claims")
    );
}

#[test]
fn jwt_claims_reject_old_array_payload() {
    let error = serde_json::from_value::<JwtClaims>(json!({
        "sub": "client-a",
        "apis": ["projects"],
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect_err("array payload should be rejected");

    assert!(error.to_string().contains("invalid type: sequence"));
}

#[test]
fn jwt_claims_reject_unknown_access_level() {
    let error = serde_json::from_value::<JwtClaims>(json!({
        "sub": "client-a",
        "apis": {
            "projects": "admin"
        },
        "iss": "gate-agent-dev",
        "aud": "gate-agent-clients",
        "iat": 1_700_000_000,
        "exp": 1_700_000_300
    }))
    .expect_err("unknown access level should be rejected");

    assert!(error.to_string().contains("unknown variant `admin`"));
}

#[test]
fn jwt_claims_reject_duplicate_api_keys_in_raw_payload() {
    let error = JwtClaims::deserialize(&mut Deserializer::from_str(
        r#"{
            "sub":"client-a",
            "apis":{"projects":"read","projects":"write"},
            "iss":"gate-agent-dev",
            "aud":"gate-agent-clients",
            "iat":1700000000,
            "exp":1700000300
        }"#,
    ))
    .expect_err("duplicate api keys should be rejected");

    assert!(
        error
            .to_string()
            .contains("duplicate api slug `projects` in jwt claims")
    );
}

#[test]
fn jwt_claims_constructor_rejects_invalid_api_slug_after_normalization() {
    let error = JwtClaims::new(
        "client-a",
        [("projects/api".to_owned(), AccessLevel::Write)],
        "gate-agent-dev",
        "gate-agent-clients",
        1_700_000_000,
        1_700_000_300,
    )
    .expect_err("invalid api slug should fail construction");

    assert_eq!(
        error.to_string(),
        "jwt claims api access contains blank or invalid api slugs"
    );
}

#[test]
fn jwt_claims_constructor_rejects_empty_api_access_after_normalization() {
    let error = JwtClaims::new(
        "client-a",
        [("   ".to_owned(), AccessLevel::Read)],
        "gate-agent-dev",
        "gate-agent-clients",
        1_700_000_000,
        1_700_000_300,
    )
    .expect_err("empty api access should fail construction");

    assert_eq!(
        error.to_string(),
        "jwt claims api access contains blank or invalid api slugs"
    );
}
