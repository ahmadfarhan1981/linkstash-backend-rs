use jsonwebtoken::errors::Error;
use thiserror::Error;

// #[derive(Error, Debug)]
// pub enum JWTValidationError {
//     #[error("JWT has expired: {source}")]
//     Expired {
//         #[source]
//         source: jsonwebtoken::errors::Error,
//     },

//     #[error("JWT signature is invalid - possible tampering: {source}")]
//     InvalidSignature {
//         #[source]
//         source: jsonwebtoken::errors::Error,
//     },

//     #[error("JWT uses invalid algorithm - possible algorithm confusion attack: {source}")]
//     InvalidAlgorithm {
//         #[source]
//         source: jsonwebtoken::errors::Error,
//     },

//     #[error("JWT is missing required claims: {missing_claims} - {source}")]
//     MissingRequiredClaims {
//         missing_claims: String,
//         #[source]
//         source: jsonwebtoken::errors::Error,
//     },

//     #[error("JWT is not yet valid - possible clock skew or future token: {source}")]
//     ImmatureSignature {
//         #[source]
//         source: jsonwebtoken::errors::Error,
//     },

//     #[error("JWT structure is malformed: {source}")]
//     Malformed {
//         #[source]
//         source: jsonwebtoken::errors::Error,
//     },
// }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtFailClass {
    /// No Authorization header / no bearer token
    Missing,

    /// Token is not structurally a JWT or cannot be decoded
    Malformed,

    /// Token is structurally valid but cryptographic verification failed
    Invalid,

    /// Token verified but rejected by claim validation (exp, nbf, aud, iss, etc.)
    ClaimsRejected,

    /// Token uses unsupported / disallowed algorithm or key format
    Unsupported,

    /// Internal error during validation (key store, config, crypto infra)
    Internal,
}

#[derive(Debug, Clone)]
pub struct JwtErrorInfo {
    pub token_len: u16,
    pub segment_count: u8,
    pub source_message: String,
}


#[derive(Debug, Error)]
#[error("JWT validation failed: {class:?}")]
pub struct JwtValidationError {
    pub class: JwtFailClass,
    pub info: JwtErrorInfo,

    #[source]
    pub source: Option<jsonwebtoken::errors::Error>,
}
impl JwtValidationError {
    pub fn new(class: JwtFailClass, info: JwtErrorInfo, source:Option<jsonwebtoken::errors::Error>) ->Self{
        Self { class, info, source }
    }

    pub fn from_error(err: jsonwebtoken::errors::Error,
    token: &str)-> Self{
        use jsonwebtoken::errors::ErrorKind;

    let token_len = token.len().min(u16::MAX as usize) as u16;
    let segment_count =
        token.as_bytes().iter().filter(|&&b| b == b'.').count().saturating_add(1) as u8;

    let class = match err.kind() {
        // Not a JWT / undecodable
        ErrorKind::InvalidToken
        | ErrorKind::Base64(_)
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_) => JwtFailClass::Malformed,

        // Crypto verification failures
        ErrorKind::InvalidSignature
        | ErrorKind::InvalidAlgorithm => JwtFailClass::Invalid,

        // Claims rejected (time, audience, issuer, etc.)
        ErrorKind::ExpiredSignature
        | ErrorKind::ImmatureSignature
        | ErrorKind::InvalidAudience
        | ErrorKind::InvalidIssuer
        | ErrorKind::InvalidSubject
        | ErrorKind::MissingRequiredClaim(_) => JwtFailClass::ClaimsRejected,

        // Unsupported / config issues
        ErrorKind::MissingAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::InvalidKeyFormat => JwtFailClass::Unsupported,

        // Everything else
        _ => JwtFailClass::Internal,
    };

    let info = JwtErrorInfo {
        token_len,
        segment_count,
        source_message: err.to_string(),
    };

    JwtValidationError::new(class, info, Some(err)) 

    }
    
}

// fn classify_jwt_error(
//     err: jsonwebtoken::errors::Error,
//     token: &str,
// ) -> JwtValidationError {
//     use jsonwebtoken::errors::ErrorKind;

//     let token_len = token.len().min(u16::MAX as usize) as u16;
//     let segment_count =
//         token.as_bytes().iter().filter(|&&b| b == b'.').count().saturating_add(1) as u8;

//     let class = match err.kind() {
//         // Not a JWT / undecodable
//         ErrorKind::InvalidToken
//         | ErrorKind::Base64(_)
//         | ErrorKind::Json(_)
//         | ErrorKind::Utf8(_) => JwtFailClass::Malformed,

//         // Crypto verification failures
//         ErrorKind::InvalidSignature
//         | ErrorKind::InvalidAlgorithm => JwtFailClass::Invalid,

//         // Claims rejected (time, audience, issuer, etc.)
//         ErrorKind::ExpiredSignature
//         | ErrorKind::ImmatureSignature
//         | ErrorKind::InvalidAudience
//         | ErrorKind::InvalidIssuer
//         | ErrorKind::InvalidSubject
//         | ErrorKind::MissingRequiredClaim(_) => JwtFailClass::ClaimsRejected,

//         // Unsupported / config issues
//         ErrorKind::MissingAlgorithm
//         | ErrorKind::InvalidAlgorithmName
//         | ErrorKind::InvalidKeyFormat => JwtFailClass::Unsupported,

//         // Everything else
//         _ => JwtFailClass::Internal,
//     };

//     let info = JwtErrorInfo {
//         token_len,
//         segment_count,
//         source_message: err.to_string(),
//     };

//     JwtValidationError::new(class, info, Some(err)) 
// }
