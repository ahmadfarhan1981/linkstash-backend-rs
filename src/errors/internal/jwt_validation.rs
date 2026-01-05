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
#[derive(Debug, Default, Clone)]
pub struct JwtErrorInfo {
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub typ: Option<String>,

    /// Small, stable hint like "expired", "aud", "iss", "sig", "malformed"
    pub note: Option<&'static str>,
}


#[derive(Debug, Error)]
#[error("JWT validation failed: {class:?}")]
pub struct JwtValidationError {
    pub class: JwtFailClass,
    pub info: JwtErrorInfo,

    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}


fn classify_jwt_error(err: &jsonwebtoken::errors::Error) -> (JwtFailClass, JwtErrorInfo) {
    use jsonwebtoken::errors::ErrorKind::*;

    match err.kind() {
        // Not a JWT / undecodable
        InvalidToken | Base64(_) | Json(_) | Utf8(_) => (
            JwtFailClass::Malformed,
            JwtErrorInfo { note: Some("malformed"), ..Default::default() },
        ),

        // Crypto / verification
        InvalidSignature | InvalidAlgorithm => (
            JwtFailClass::Invalid,
            JwtErrorInfo { note: Some("signature"), ..Default::default() },
        ),

        // Claims rejected
        ExpiredSignature
        | ImmatureSignature
        | InvalidAudience
        | InvalidIssuer
        | InvalidSubject
        | MissingRequiredClaim(_) => (
            JwtFailClass::ClaimsRejected,
            JwtErrorInfo { note: Some("claims"), ..Default::default() },
        ),

        // Algo / key support
        MissingAlgorithm
        | InvalidAlgorithmName
        | InvalidKeyFormat => (
            JwtFailClass::Unsupported,
            JwtErrorInfo { note: Some("algorithm"), ..Default::default() },
        ),

        // Everything else
        _ => (
            JwtFailClass::Internal,
            JwtErrorInfo { note: Some("internal"), ..Default::default() },
        ),
    }
}
