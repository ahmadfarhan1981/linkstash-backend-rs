use thiserror::Error;

#[derive(Error, Debug)]
pub enum JWTValidationError {
    #[error("JWT has expired: {source}")]
    Expired {
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    #[error("JWT signature is invalid - possible tampering: {source}")]
    InvalidSignature {
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    #[error("JWT uses invalid algorithm - possible algorithm confusion attack: {source}")]
    InvalidAlgorithm {
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    #[error("JWT is missing required claims: {missing_claims} - {source}")]
    MissingRequiredClaims {
        missing_claims: String,
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    #[error("JWT is not yet valid - possible clock skew or future token: {source}")]
    ImmatureSignature {
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    #[error("JWT structure is malformed: {source}")]
    Malformed {
        #[source]
        source: jsonwebtoken::errors::Error,
    },
}
