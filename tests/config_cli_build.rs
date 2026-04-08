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

#[test]
fn cargo_toml_includes_plan_dependencies_for_config_and_exchange() {
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
        dependencies.contains_key("time"),
        "expected time for RFC3339 parsing and formatting"
    );
    assert!(
        dependencies.contains_key("jsonwebtoken"),
        "expected jsonwebtoken for auth exchange JWT issuance"
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

    let jsonwebtoken_features = dependency_features(&dependencies, "jsonwebtoken");
    assert!(
        jsonwebtoken_features.contains("rust_crypto"),
        "expected jsonwebtoken to use rust_crypto"
    );

    for unexpected_dep in ["chrono", "ring", "openssl"] {
        assert!(
            !dependencies.contains_key(unexpected_dep),
            "did not expect auth dependency {unexpected_dep}"
        );
    }
}
