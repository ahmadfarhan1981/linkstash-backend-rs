#[cfg(test)]
mod tests {
    use crate::errors::AdminError;
    use crate::errors::internal::{InternalError, CredentialError, SystemConfigError, AuditError};
    use sea_orm::DbErr;

    #[test]
    fn test_database_error_converts_to_internal_server_error() {
        let db_err = DbErr::RecordNotFound("test".to_string());
        let internal_err = InternalError::database("get_user", db_err);
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_transaction_error_converts_to_internal_server_error() {
        let db_err = DbErr::RecordNotFound("test".to_string());
        let internal_err = InternalError::transaction("update_privileges", db_err);
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_parse_error_converts_to_internal_server_error() {
        let internal_err = InternalError::parse("UUID", "invalid format");
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_crypto_error_converts_to_internal_server_error() {
        let internal_err = InternalError::crypto("password_hash", "invalid secret");
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_user_not_found_converts_correctly() {
        let internal_err = InternalError::Credential(CredentialError::UserNotFound("user-123".to_string()));
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "User not found: user-123");
    }

    #[test]
    fn test_duplicate_username_converts_to_internal_server_error() {
        // Duplicate username shouldn't happen in admin context
        let internal_err = InternalError::Credential(CredentialError::DuplicateUsername("testuser".to_string()));
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_owner_already_exists_converts_correctly() {
        let internal_err = InternalError::SystemConfig(SystemConfigError::OwnerAlreadyExists);
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "System already bootstrapped");
    }

    #[test]
    fn test_owner_not_found_converts_correctly() {
        let internal_err = InternalError::SystemConfig(SystemConfigError::OwnerNotFound);
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "Owner account not found");
    }

    #[test]
    fn test_unexpected_domain_error_converts_to_internal_server_error() {
        // AuditError shouldn't appear in admin context
        let internal_err = InternalError::Audit(AuditError::LogWriteFailed("test".to_string()));
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

    #[test]
    fn test_invalid_credentials_converts_to_internal_server_error() {
        // InvalidCredentials shouldn't appear in admin context
        let internal_err = InternalError::Credential(CredentialError::InvalidCredentials);
        let admin_err = AdminError::from_internal_error(internal_err);
        
        assert_eq!(admin_err.message(), "An internal error occurred");
    }

}
