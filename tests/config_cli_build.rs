use std::collections::BTreeSet;

use toml::{Table, Value};

fn dependencies_table() -> Table {
    std::fs::read_to_string("Cargo.toml")
        .expect("Cargo.toml should be readable")
        .parse::<Value>()
        .expect("Cargo.toml should parse as TOML")
        .get("dependencies")
        .and_then(Value::as_table)
        .cloned()
        .expect("Cargo.toml should include a [dependencies] table")
}

fn dependency_features(dependencies: &Table, name: &str) -> BTreeSet<String> {
    dependencies
        .get(name)
        .and_then(Value::as_table)
        .and_then(|entry| entry.get("features"))
        .and_then(Value::as_array)
        .map(|features| {
            features
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn dependency_bool(dependencies: &Table, name: &str, key: &str) -> Option<bool> {
    dependencies
        .get(name)
        .and_then(Value::as_table)
        .and_then(|entry| entry.get(key))
        .and_then(Value::as_bool)
}

#[test]
fn cargo_toml_includes_bearer_hashing_and_config_dependencies() {
    let dependencies = dependencies_table();

    assert!(
        dependencies.contains_key("dirs"),
        "expected dirs for config path resolution"
    );
    assert!(
        dependencies.contains_key("toml_edit"),
        "expected toml_edit for config upserts"
    );
    assert!(
        dependencies.contains_key("rand"),
        "expected rand for secure secret generation"
    );
    assert!(
        dependencies.contains_key("sha2"),
        "expected sha2 for persisted bearer token hashing"
    );
    assert!(
        dependencies.contains_key("time"),
        "expected time for RFC3339 parsing and formatting"
    );
    assert!(
        !dependencies.contains_key("jsonwebtoken"),
        "did not expect jsonwebtoken in the direct bearer-token runtime"
    );
    assert!(
        dependencies.contains_key("age"),
        "expected age for encrypted config support"
    );
    assert!(
        dependencies.contains_key("rpassword"),
        "expected rpassword for interactive password prompts"
    );
    assert!(
        dependencies.contains_key("keyring"),
        "expected keyring for encrypted config password persistence"
    );
    assert!(
        dependencies.contains_key("tempfile"),
        "expected tempfile for safe config editing and atomic writes"
    );

    let time_features = dependency_features(&dependencies, "time");
    assert!(
        time_features.contains("formatting"),
        "expected time to enable formatting"
    );
    assert!(
        time_features.contains("parsing"),
        "expected time to enable parsing"
    );
    assert!(
        time_features.contains("serde"),
        "expected time to enable serde"
    );

    let keyring_features = dependency_features(&dependencies, "keyring");
    assert_eq!(
        dependency_bool(&dependencies, "keyring", "default-features"),
        Some(false),
        "expected keyring default features to be disabled so backend selection stays explicit"
    );
    for feature in ["apple-native", "linux-native"] {
        assert!(
            keyring_features.contains(feature),
            "expected keyring feature {feature}"
        );
    }

    for unexpected_dep in ["chrono", "ring", "openssl"] {
        assert!(
            !dependencies.contains_key(unexpected_dep),
            "did not expect extra crypto/runtime dependency {unexpected_dep}"
        );
    }

    for unexpected_dep in ["secret-service", "keyutils", "security-framework"] {
        assert!(
            !dependencies.contains_key(unexpected_dep),
            "did not expect direct secret-store dependency {unexpected_dep}"
        );
    }
}
