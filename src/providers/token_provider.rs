use crate::config::SecretManager;
use crate::errors::internal::jwt_validation::JwtValidationError;
use crate::types::db::AccessToken;
use crate::types::internal::action_outcome::ActionOutcome;
use crate::errors::InternalError;
use crate::errors::internal::{CredentialError};
use crate::providers::CryptoProvider;
use crate::stores::user_store::UserForJWT;
use crate::types::internal::auth::Claims;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use poem_openapi::auth::Bearer;
use rand::prelude::*;
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;


const SECONDS_IN_MINUTES: i64=60;

/// Provides JWT token generation, validation, and refresh token operations
///
/// Migrated from TokenService as part of service layer refactor.
/// Contains all business logic for token operations while maintaining
/// identical functionality and method signatures.
pub struct TokenProvider {
    secret_manager: Arc<SecretManager>,
    jwt_expiration_minutes: i64,
    refresh_expiration_days: i64,
    // audit_store: Arc<AuditStore>,
    crypto_provider: Arc<CryptoProvider>,
    // audit_logger: Arc<AuditLogger>
}
pub struct GeneratedJWT {
    pub jwt: String,
    pub jti: String,
    pub expires_in: i64,
    pub token_type: String,
}
impl GeneratedJWT {
    pub fn new( jwt: &str, jti: &str, expires_in: i64)-> Self{
        Self { jwt: jwt.to_owned(), jti: jti.to_owned(), expires_in, token_type: "Bearer".to_owned() }
    }
}

pub struct GeneratedRT {
    pub token: String,
    pub token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
}
impl TokenProvider {
    /// Create a new TokenProvider with the given SecretManager and audit store
    pub fn new(secret_manager: Arc<SecretManager>, crypto_provider: Arc<CryptoProvider>) -> Self {
        Self {
            secret_manager,
            jwt_expiration_minutes: 15, // 15 minutes as per requirements
            refresh_expiration_days: 7, // 7 days as per requirements
            // audit_store,
            crypto_provider,
        }
    }

    /// Generate a JWT for the given user with admin roles
    ///
    /// Logs JWT issuance to audit database at point of action.
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `user_id` - The UUID of the user (target of the JWT)
    /// * `is_owner` - Owner role flag
    /// * `is_system_admin` - System Admin role flag
    /// * `is_role_admin` - Role Admin role flag
    /// * `app_roles` - Application roles (list of role names)
    /// * `password_change_required` - Password change required flag
    ///
    /// # Returns
    /// * `Result<(String, String), InternalError>` - Tuple of (encoded JWT, JWT ID) or an error
    pub async fn generate_jwt(
        &self,
        // ctx: &crate::types::internal::context::RequestContext,
        user: &UserForJWT,
    ) -> Result<ActionOutcome<GeneratedJWT>, InternalError> {
        let now = Utc::now().timestamp();
        let expiration = now + (self.jwt_expiration_minutes * 60);

        // Validate expiration timestamp before creating JWT
        let expiration_dt =
            DateTime::from_timestamp(expiration, 0).ok_or_else(|| InternalError::Parse {
                value_type: "timestamp".to_string(),
                message: format!("Invalid expiration timestamp: {}", expiration),
            })?;

        // Generate unique JWT ID
        let jti = Uuid::new_v4().to_string();
        let UserForJWT {
            id,
            is_owner,
            is_system_admin,
            is_role_admin,
            app_roles,
            password_change_required,
            ..
        } = user.clone();
        let claims = Claims {
            sub: id,
            exp: expiration,
            iat: now,
            jti: jti.clone(),
            is_owner,
            is_system_admin,
            is_role_admin,
            app_roles: serde_json::from_str::<Vec<String>>(&app_roles).unwrap_or_else(|_| vec![]),
            password_change_required,
        };

        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret_manager.jwt_secret().as_bytes()),
        )
        .map_err(|e| InternalError::Crypto {
            operation: "jwt_generation".to_string(),
            message: format!("Failed to generate JWT: {}", e),
        })?;

        // Log JWT issuance at point of action (expiration_dt already validated above)
        // if let Err(audit_err) = audit_logger::log_jwt_issued(
        //     &self.audit_store,
        //     ctx,
        //     user_id.to_string(),
        //     jti.clone(),
        //     expiration_dt,
        // ).await {
        //     tracing::error!("Failed to log JWT issuance: {:?}", audit_err);
        // }


        let generated_jwt = GeneratedJWT::new(&jwt, &jti, self.jwt_expiration_minutes * SECONDS_IN_MINUTES) ;
        Ok(ActionOutcome{ value: generated_jwt, audit: Vec::new() })
    }

    /// Validate a JWT and return the claims
    ///
    /// Logs validation failures to audit database at point of action.
    ///
    /// # Arguments
    /// * `token` - The JWT to validate
    ///
    /// # Returns
    /// * `Result<Claims, InternalError>` - The decoded claims or an error
    pub fn validate_jwt(&self, auth: &Bearer) -> Result<Claims, InternalError> {
        let validation = Validation::new(Algorithm::HS256);
        let token = auth.token.as_str();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret_manager.jwt_secret().as_bytes()),
            &validation,
        )
        .map_err(|e| {
            InternalError::JWTValidation(JwtValidationError::from_error(e, token) )

        });
        // TODO audit intent
        token_data.map(|td| td.claims)
                
    
    }
    /// Extract claims from JWT without validation (for audit logging only)
    fn extract_unverified_claims(&self, token: &str) -> Result<Claims, InternalError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;

        let token_data = decode::<Claims>(token, &DecodingKey::from_secret(b"dummy"), &validation)
            .map_err(|_| {
                InternalError::from(CredentialError::InvalidToken {
                    token_type: "jwt".to_string(),
                    reason: "malformed".to_string(),
                })
            })?;

        Ok(token_data.claims)
    }

    /// Generate a cryptographically secure refresh token
    ///
    /// # Returns
    /// * `String` - A base64-encoded random token (32 bytes)
    pub fn generate_refresh_token(&self) -> Result<ActionOutcome<GeneratedRT>, InternalError> {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        let token = general_purpose::STANDARD.encode(random_bytes);
        let token_hash = self.hash_refresh_token(&token);
        let created_at = Utc::now().timestamp();
        let expires_at = self.get_refresh_expiration(created_at);

        Ok(ActionOutcome {
            value: GeneratedRT {
                token,
                token_hash,
                created_at,
                expires_at,
            },
            audit: Vec::new(),
        })
    }

    /// Hash a refresh token using HMAC-SHA256
    ///
    /// # Arguments
    /// * `token` - The plaintext refresh token to hash
    ///
    /// # Returns
    /// * `String` - The hex-encoded HMAC-SHA256 hash
    pub fn hash_refresh_token(&self, token: &str) -> String {
        self.crypto_provider
            .hmac_sha256_token(self.secret_manager.refresh_token_secret(), token)
    }

    /// Get the expiration timestamp for a refresh token (7 days from now)
    ///
    /// # Returns
    /// * `i64` - Unix timestamp for `refresh_expiration_days` days from now
    pub fn get_refresh_expiration(&self, created: i64) -> i64 {
        created + (self.refresh_expiration_days * 24 * 60 * 60)
    }
}

impl fmt::Debug for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenProvider")
            .field("secret_manager", &"<redacted>")
            .field("jwt_expiration_minutes", &self.jwt_expiration_minutes)
            .field("refresh_expiration_days", &self.refresh_expiration_days)
            .field("audit_store", &"<audit_store>")
            .finish()
    }
}

impl fmt::Display for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TokenProvider {{ jwt_expiration: {}min, refresh_expiration: {}days }}",
            self.jwt_expiration_minutes, self.refresh_expiration_days
        )
    }
}
