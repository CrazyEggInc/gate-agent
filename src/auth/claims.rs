use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwtClaims {
    pub sub: String,
    pub(crate) apis: Vec<String>,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
}

impl JwtClaims {
    pub fn new(
        sub: impl Into<String>,
        apis: impl IntoIterator<Item = String>,
        iss: impl Into<String>,
        aud: impl Into<String>,
        iat: u64,
        exp: u64,
    ) -> Self {
        Self {
            sub: sub.into(),
            apis: normalize_apis(apis),
            iss: iss.into(),
            aud: aud.into(),
            iat,
            exp,
        }
    }

    pub fn apis(&self) -> Vec<String> {
        self.apis.clone()
    }
}

impl Serialize for JwtClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("JwtClaims", 6)?;
        state.serialize_field("sub", &self.sub)?;
        state.serialize_field("apis", &self.apis)?;
        state.serialize_field("iss", &self.iss)?;
        state.serialize_field("aud", &self.aud)?;
        state.serialize_field("iat", &self.iat)?;
        state.serialize_field("exp", &self.exp)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for JwtClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Sub,
            Apis,
            Iss,
            Aud,
            Iat,
            Exp,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a JWT claims field")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "sub" => Ok(Field::Sub),
                            "apis" => Ok(Field::Apis),
                            "iss" => Ok(Field::Iss),
                            "aud" => Ok(Field::Aud),
                            "iat" => Ok(Field::Iat),
                            "exp" => Ok(Field::Exp),
                            _ => Err(de::Error::unknown_field(
                                value,
                                &["sub", "apis", "iss", "aud", "iat", "exp"],
                            )),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct JwtClaimsVisitor;

        impl<'de> Visitor<'de> for JwtClaimsVisitor {
            type Value = JwtClaims;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JWT claims")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut sub = None;
                let mut apis = None;
                let mut iss = None;
                let mut aud = None;
                let mut iat = None;
                let mut exp = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Sub => sub = Some(map.next_value()?),
                        Field::Apis => apis = Some(map.next_value::<Vec<String>>()?),
                        Field::Iss => iss = Some(map.next_value()?),
                        Field::Aud => aud = Some(map.next_value()?),
                        Field::Iat => iat = Some(map.next_value()?),
                        Field::Exp => exp = Some(map.next_value()?),
                    }
                }

                let apis = apis
                    .map(normalize_apis)
                    .ok_or_else(|| de::Error::missing_field("apis"))?;

                Ok(JwtClaims {
                    sub: sub.ok_or_else(|| de::Error::missing_field("sub"))?,
                    apis,
                    iss: iss.ok_or_else(|| de::Error::missing_field("iss"))?,
                    aud: aud.ok_or_else(|| de::Error::missing_field("aud"))?,
                    exp: exp.ok_or_else(|| de::Error::missing_field("exp"))?,
                    iat: iat.ok_or_else(|| de::Error::missing_field("iat"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "JwtClaims",
            &["sub", "apis", "iss", "aud", "iat", "exp"],
            JwtClaimsVisitor,
        )
    }
}

fn normalize_apis(apis: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut apis = apis
        .into_iter()
        .filter(|api| !api.is_empty())
        .collect::<Vec<_>>();
    apis.sort();
    apis.dedup();
    apis
}
