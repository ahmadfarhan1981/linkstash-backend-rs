use crate::errors::internal::{CredentialError, InternalError, SystemConfigError};
use poem_openapi::{ApiResponse, Object, payload::Json};
use std::fmt;

/// Standardized error response for admin endpoints
#[derive(Object, Debug)]
pub struct AdminErrorResponse {
    /// Error code identifier
    pub error: String,

    /// Human-readable error message
    pub message: String,

    /// HTTP status code
    pub status_code: u16,
}

/// Admin operation error types
#[derive(ApiResponse, Debug)]
pub enum AdminError {
    /// System has already been bootstrapped
    #[oai(status = 409)]
    AlreadyBootstrapped(Json<AdminErrorResponse>),

    /// Owner account not found
    #[oai(status = 404)]
    OwnerNotFound(Json<AdminErrorResponse>),

    /// User not found
    #[oai(status = 404)]
    UserNotFound(Json<AdminErrorResponse>),

    /// Owner role required
    #[oai(status = 403)]
    OwnerRequired(Json<AdminErrorResponse>),

    /// System Admin role required
    #[oai(status = 403)]
    SystemAdminRequired(Json<AdminErrorResponse>),

    /// Role Admin role required
    #[oai(status = 403)]
    RoleAdminRequired(Json<AdminErrorResponse>),

    /// Owner or System Admin role required
    #[oai(status = 403)]
    OwnerOrSystemAdminRequired(Json<AdminErrorResponse>),

    /// Cannot modify your own admin roles
    #[oai(status = 403)]
    SelfModificationDenied(Json<AdminErrorResponse>),

    /// Password validation failed
    #[oai(status = 400)]
    PasswordValidationFailed(Json<AdminErrorResponse>),

    /// Password change required
    #[oai(status = 403)]
    PasswordChangeRequired(Json<AdminErrorResponse>),

    /// Internal server error
    #[oai(status = 500)]
    InternalError(Json<AdminErrorResponse>),
}

impl AdminError {
    /// Create an AlreadyBootstrapped error
    pub fn already_bootstrapped() -> Self {
        AdminError::AlreadyBootstrapped(Json(AdminErrorResponse {
            error: "already_bootstrapped".to_string(),
            message: "System already bootstrapped".to_string(),
            status_code: 409,
        }))
    }

    /// Create an OwnerNotFound error
    pub fn owner_not_found() -> Self {
        AdminError::OwnerNotFound(Json(AdminErrorResponse {
            error: "owner_not_found".to_string(),
            message: "Owner account not found".to_string(),
            status_code: 404,
        }))
    }

    /// Create a UserNotFound error
    pub fn user_not_found(user_id: String) -> Self {
        AdminError::UserNotFound(Json(AdminErrorResponse {
            error: "user_not_found".to_string(),
            message: format!("User not found: {}", user_id),
            status_code: 404,
        }))
    }

    /// Create an OwnerRequired error
    pub fn owner_required() -> Self {
        AdminError::OwnerRequired(Json(AdminErrorResponse {
            error: "owner_required".to_string(),
            message: "Owner role required".to_string(),
            status_code: 403,
        }))
    }

    /// Create a SystemAdminRequired error
    pub fn system_admin_required() -> Self {
        AdminError::SystemAdminRequired(Json(AdminErrorResponse {
            error: "system_admin_required".to_string(),
            message: "System Admin role required".to_string(),
            status_code: 403,
        }))
    }

    /// Create a RoleAdminRequired error
    pub fn role_admin_required() -> Self {
        AdminError::RoleAdminRequired(Json(AdminErrorResponse {
            error: "role_admin_required".to_string(),
            message: "Role Admin role required".to_string(),
            status_code: 403,
        }))
    }

    /// Create an OwnerOrSystemAdminRequired error
    pub fn owner_or_system_admin_required() -> Self {
        AdminError::OwnerOrSystemAdminRequired(Json(AdminErrorResponse {
            error: "owner_or_system_admin_required".to_string(),
            message: "Owner or System Admin role required".to_string(),
            status_code: 403,
        }))
    }

    /// Create a SelfModificationDenied error
    pub fn self_modification_denied() -> Self {
        AdminError::SelfModificationDenied(Json(AdminErrorResponse {
            error: "self_modification_denied".to_string(),
            message: "Cannot modify your own admin roles".to_string(),
            status_code: 403,
        }))
    }

    /// Create a PasswordValidationFailed error
    pub fn password_validation_failed(reason: String) -> Self {
        AdminError::PasswordValidationFailed(Json(AdminErrorResponse {
            error: "password_validation_failed".to_string(),
            message: format!("Password validation failed: {}", reason),
            status_code: 400,
        }))
    }

    /// Create a PasswordChangeRequired error
    pub fn password_change_required() -> Self {
        AdminError::PasswordChangeRequired(Json(AdminErrorResponse {
            error: "password_change_required".to_string(),
            message:
                "Password change required. Please change your password at /auth/change-password"
                    .to_string(),
            status_code: 403,
        }))
    }

    /// Convert InternalError to AdminError
    ///
    /// This is the explicit conversion point from internal errors to API errors.
    /// Internal error details are logged but not exposed to clients.
    pub fn from_internal_error(err: InternalError) -> Self {
        match &err {
            // Infrastructure errors - always log and return generic error
            // InternalError::Database { operation, .. } => {
            //     tracing::error!("Database error in {}: {}", operation, err);
            //     Self::internal_server_error()
            // }
            // InternalError::Transaction { operation, .. } => {
            //     tracing::error!("Transaction error in {}: {}", operation, err);
            //     Self::internal_server_error()
            // }
            InternalError::Parse { value_type, .. } => {
                tracing::error!("Parse error for {}: {}", value_type, err);
                Self::internal_server_error()
            }
            InternalError::Crypto { operation, .. } => {
                tracing::error!("Crypto error in {}: {}", operation, err);
                Self::internal_server_error()
            }

            // Credential domain errors
            InternalError::Credential(CredentialError::UserNotFound(user_id)) => {
                Self::user_not_found(user_id.clone())
            }
            InternalError::Credential(CredentialError::DuplicateUsername(username)) => {
                tracing::warn!("Duplicate username in admin operation: {}", username);
                Self::internal_server_error() // Shouldn't happen in admin context
            }

            // SystemConfig domain errors
            InternalError::SystemConfig(SystemConfigError::OwnerAlreadyExists) => {
                Self::already_bootstrapped()
            }
            InternalError::SystemConfig(SystemConfigError::OwnerNotFound) => {
                Self::owner_not_found()
            }

            // Other domain errors
            _ => {
                tracing::error!("Unexpected error in admin operation: {}", err);
                Self::internal_server_error()
            }
        }
    }

    /// Create a generic internal server error
    ///
    /// This replaces the old internal_error() method. It always returns
    /// a generic message without exposing internal details.
    fn internal_server_error() -> Self {
        AdminError::InternalError(Json(AdminErrorResponse {
            error: "internal_error".to_string(),
            message: "An internal error occurred".to_string(),
            status_code: 500,
        }))
    }

    /// Get the error message from the error variant
    pub fn message(&self) -> String {
        match self {
            AdminError::AlreadyBootstrapped(json) => json.0.message.clone(),
            AdminError::OwnerNotFound(json) => json.0.message.clone(),
            AdminError::UserNotFound(json) => json.0.message.clone(),
            AdminError::OwnerRequired(json) => json.0.message.clone(),
            AdminError::SystemAdminRequired(json) => json.0.message.clone(),
            AdminError::RoleAdminRequired(json) => json.0.message.clone(),
            AdminError::OwnerOrSystemAdminRequired(json) => json.0.message.clone(),
            AdminError::SelfModificationDenied(json) => json.0.message.clone(),
            AdminError::PasswordValidationFailed(json) => json.0.message.clone(),
            AdminError::PasswordChangeRequired(json) => json.0.message.clone(),
            AdminError::InternalError(json) => json.0.message.clone(),
        }
    }

    /// Get the HTTP status code from the error variant
    pub fn status_code(&self) -> u16 {
        match self {
            AdminError::AlreadyBootstrapped(json) => json.0.status_code,
            AdminError::OwnerNotFound(json) => json.0.status_code,
            AdminError::UserNotFound(json) => json.0.status_code,
            AdminError::OwnerRequired(json) => json.0.status_code,
            AdminError::SystemAdminRequired(json) => json.0.status_code,
            AdminError::RoleAdminRequired(json) => json.0.status_code,
            AdminError::OwnerOrSystemAdminRequired(json) => json.0.status_code,
            AdminError::SelfModificationDenied(json) => json.0.status_code,
            AdminError::PasswordValidationFailed(json) => json.0.status_code,
            AdminError::PasswordChangeRequired(json) => json.0.status_code,
            AdminError::InternalError(json) => json.0.status_code,
        }
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}
