use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    pub api: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
}
