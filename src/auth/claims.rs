use std::collections::BTreeMap;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::config::secrets::{AccessLevel, is_valid_slug};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwtClaimsBuildError {
    message: String,
}

impl JwtClaimsBuildError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for JwtClaimsBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JwtClaimsBuildError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    #[serde(deserialize_with = "deserialize_api_access")]
    pub apis: BTreeMap<String, AccessLevel>,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
}

pub trait IntoApiAccessEntry {
    fn into_api_access_entry(self) -> Option<(String, AccessLevel)>;
}

impl IntoApiAccessEntry for (String, AccessLevel) {
    fn into_api_access_entry(self) -> Option<(String, AccessLevel)> {
        let api = self.0.trim().to_ascii_lowercase();
        if api.is_empty() || !is_valid_slug(&api) {
            return None;
        }

        Some((api, self.1))
    }
}

impl JwtClaims {
    pub fn new<Entry>(
        sub: impl Into<String>,
        apis: impl IntoIterator<Item = Entry>,
        iss: impl Into<String>,
        aud: impl Into<String>,
        iat: u64,
        exp: u64,
    ) -> Result<Self, JwtClaimsBuildError>
    where
        Entry: IntoApiAccessEntry,
    {
        Ok(Self {
            sub: sub.into(),
            apis: normalize_api_access(apis)?,
            iss: iss.into(),
            aud: aud.into(),
            iat,
            exp,
        })
    }
}

fn normalize_api_access<Entry>(
    apis: impl IntoIterator<Item = Entry>,
) -> Result<BTreeMap<String, AccessLevel>, JwtClaimsBuildError>
where
    Entry: IntoApiAccessEntry,
{
    let mut normalized = BTreeMap::new();
    let mut saw_invalid_entry = false;

    for entry in apis {
        if let Some((api, level)) = entry.into_api_access_entry() {
            normalized
                .entry(api)
                .and_modify(|current: &mut AccessLevel| *current = (*current).max(level))
                .or_insert(level);
        } else {
            saw_invalid_entry = true;
        }
    }

    if saw_invalid_entry {
        return Err(JwtClaimsBuildError::new(
            "jwt claims api access contains blank or invalid api slugs",
        ));
    }

    if normalized.is_empty() {
        return Err(JwtClaimsBuildError::new(
            "jwt claims api access cannot be empty",
        ));
    }

    Ok(normalized)
}

fn deserialize_api_access<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AccessLevel>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ApiAccessVisitor;

    impl<'de> Visitor<'de> for ApiAccessVisitor {
        type Value = BTreeMap<String, AccessLevel>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map of api slugs to access levels")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut api_access = BTreeMap::new();

            while let Some((api, level)) = map.next_entry::<String, AccessLevel>()? {
                if api.is_empty() {
                    return Err(de::Error::custom("api slug cannot be blank"));
                }

                if !is_valid_slug(&api) {
                    return Err(de::Error::custom(format!(
                        "invalid api slug `{api}` in jwt claims"
                    )));
                }

                if api_access.contains_key(&api) {
                    return Err(de::Error::custom(format!(
                        "duplicate api slug `{api}` in jwt claims"
                    )));
                }

                api_access.insert(api, level);
            }

            Ok(api_access)
        }
    }

    deserializer.deserialize_map(ApiAccessVisitor)
}
