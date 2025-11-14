use serde::{Deserialize, Serialize};

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user_id)
    pub sub: String,
    
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    
    /// Issued at (Unix timestamp)
    pub iat: i64,
    
    /// JWT ID (unique identifier for this token)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}
