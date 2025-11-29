#[cfg(test)]
mod tests {
    use crate::errors::AuthError;
    use crate::errors::internal::{InternalError, CredentialError, SystemConfigError};
    use sea_orm::DbErr;

    #[test]
    fn test_database_error_converts_to_internal_server_error() {
        let db_err = DbErr::RecordNotFound("test".to_string());
        let internal_err = InternalError::database("get_user", db_err);
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_transaction_error_converts_to_internal_server_error() {
        let db_err = DbErr::RecordNotFound("test".to_string());
        let internal_err = InternalError::transaction("update_user", db_err);
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_parse_error_converts_to_internal_server_error() {
        let internal_err = InternalError::parse("UUID", "invalid format");
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_crypto_error_converts_to_internal_server_error() {
        let internal_err = InternalError::crypto("argon2_init", "invalid secret");
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_invalid_credentials_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::InvalidCredentials);
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "Invalid username or password");
    }

    #[test]
    fn test_duplicate_username_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::DuplicateUsername("testuser".to_string()));
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "Username already exists");
    }

    #[test]
    fn test_invalid_jwt_token_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::invalid_token("jwt", "signature invalid"));
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "Invalid or malformed JWT");
    }

    #[test]
    fn test_invalid_refresh_token_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::invalid_token("refresh_token", "not found"));
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "Invalid refresh token");
    }

    #[test]
    fn test_expired_jwt_token_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::ExpiredToken("jwt".to_string()));
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "JWT has expired");
    }

    #[test]
    fn test_expired_refresh_token_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::ExpiredToken("refresh_token".to_string()));
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "Refresh token has expired");
    }

    #[test]
    fn test_unexpected_domain_error_converts_to_internal_server_error() {
        // SystemConfigError shouldn't appear in auth context
        let internal_err = InternalError::SystemConfig(SystemConfigError::OwnerAlreadyExists);
        let auth_err = AuthError::from_internal_error(internal_err);
        
        assert_eq!(auth_err.message(), "An internal error occurred");
    }

}
