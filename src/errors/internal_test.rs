#[cfg(test)]
mod tests {
    use crate::errors::internal::{InternalError, CredentialError, SystemConfigError, AuditError};
    use sea_orm::DbErr;

    #[test]
    fn test_database_error_includes_operation() {
        let db_err = DbErr::RecordNotFound("test record".to_string());
        let error = InternalError::database("create_user", db_err);
        
        let error_string = error.to_string();
        assert!(error_string.contains("create_user"));
        assert!(error_string.contains("Database error"));
    }

    #[test]
    fn test_transaction_error_includes_operation() {
        let db_err = DbErr::RecordNotFound("test".to_string());
        let error = InternalError::transaction("update_user", db_err);
        
        let error_string = error.to_string();
        assert!(error_string.contains("update_user"));
        assert!(error_string.contains("Transaction error"));
    }

    #[test]
    fn test_parse_error_includes_value_type() {
        let error = InternalError::parse("UUID", "invalid format");
        
        let error_string = error.to_string();
        assert!(error_string.contains("UUID"));
        assert!(error_string.contains("invalid format"));
        assert!(error_string.contains("Parse error"));
    }

    #[test]
    fn test_crypto_error_includes_operation() {
        let error = InternalError::crypto("argon2_init", "invalid secret length");
        
        let error_string = error.to_string();
        assert!(error_string.contains("argon2_init"));
        assert!(error_string.contains("invalid secret length"));
        assert!(error_string.contains("Crypto error"));
    }

    #[test]
    fn test_credential_error_invalid_credentials() {
        let error = CredentialError::InvalidCredentials;
        assert_eq!(error.to_string(), "Invalid credentials");
    }

    #[test]
    fn test_credential_error_duplicate_username() {
        let error = CredentialError::DuplicateUsername("testuser".to_string());
        assert_eq!(error.to_string(), "User already exists: testuser");
    }

    #[test]
    fn test_credential_error_user_not_found() {
        let error = CredentialError::UserNotFound("user-123".to_string());
        assert_eq!(error.to_string(), "User not found: user-123");
    }

    #[test]
    fn test_credential_error_password_hashing_failed() {
        let error = CredentialError::PasswordHashingFailed("hash error".to_string());
        assert_eq!(error.to_string(), "Password hashing failed: hash error");
    }

    #[test]
    fn test_credential_error_invalid_token() {
        let error = CredentialError::invalid_token("jwt", "signature invalid");
        assert_eq!(error.to_string(), "Invalid token: jwt - signature invalid");
    }

    #[test]
    fn test_credential_error_expired_token() {
        let error = CredentialError::ExpiredToken("refresh_token".to_string());
        assert_eq!(error.to_string(), "Expired token: refresh_token");
    }

    #[test]
    fn test_system_config_error_config_not_found() {
        let error = SystemConfigError::ConfigNotFound;
        assert_eq!(error.to_string(), "System config not found");
    }

    #[test]
    fn test_system_config_error_owner_already_exists() {
        let error = SystemConfigError::OwnerAlreadyExists;
        assert_eq!(error.to_string(), "Owner already exists");
    }

    #[test]
    fn test_system_config_error_owner_not_found() {
        let error = SystemConfigError::OwnerNotFound;
        assert_eq!(error.to_string(), "Owner not found");
    }

    #[test]
    fn test_audit_error_log_write_failed() {
        let error = AuditError::LogWriteFailed("database connection lost".to_string());
        assert_eq!(error.to_string(), "Failed to write audit log: database connection lost");
    }

    #[test]
    fn test_credential_error_auto_converts_to_internal_error() {
        let cred_error = CredentialError::InvalidCredentials;
        let internal_error: InternalError = cred_error.into();
        
        assert!(internal_error.to_string().contains("Invalid credentials"));
    }

    #[test]
    fn test_system_config_error_auto_converts_to_internal_error() {
        let config_error = SystemConfigError::OwnerAlreadyExists;
        let internal_error: InternalError = config_error.into();
        
        assert!(internal_error.to_string().contains("Owner already exists"));
    }

    #[test]
    fn test_audit_error_auto_converts_to_internal_error() {
        let audit_error = AuditError::LogWriteFailed("test".to_string());
        let internal_error: InternalError = audit_error.into();
        
        assert!(internal_error.to_string().contains("Failed to write audit log"));
    }
}
