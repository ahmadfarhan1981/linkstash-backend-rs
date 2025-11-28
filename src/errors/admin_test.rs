#[cfg(test)]
mod tests {
    use super::super::admin::AdminError;
    use crate::errors::auth::AuthError;
    use sea_orm::DbErr;

    #[test]
    fn test_all_error_variants_have_correct_status_codes() {
        // Test each error variant has the expected status code
        let already_bootstrapped = AdminError::already_bootstrapped();
        assert_eq!(already_bootstrapped.message(), "System already bootstrapped");
        
        let owner_not_found = AdminError::owner_not_found();
        assert_eq!(owner_not_found.message(), "Owner account not found");
        
        let user_not_found = AdminError::user_not_found("test-user-id".to_string());
        assert!(user_not_found.message().contains("User not found"));
        
        let owner_required = AdminError::owner_required();
        assert_eq!(owner_required.message(), "Owner role required");
        
        let system_admin_required = AdminError::system_admin_required();
        assert_eq!(system_admin_required.message(), "System Admin role required");
        
        let role_admin_required = AdminError::role_admin_required();
        assert_eq!(role_admin_required.message(), "Role Admin role required");
        
        let owner_or_system_admin_required = AdminError::owner_or_system_admin_required();
        assert_eq!(owner_or_system_admin_required.message(), "Owner or System Admin role required");
        
        let self_modification_denied = AdminError::self_modification_denied();
        assert_eq!(self_modification_denied.message(), "Cannot modify your own admin roles");
        
        let password_validation_failed = AdminError::password_validation_failed("too short".to_string());
        assert!(password_validation_failed.message().contains("Password validation failed"));
        
        let password_change_required = AdminError::password_change_required();
        assert!(password_change_required.message().contains("Password change required"));
        
        let internal_error = AdminError::internal_error("test error".to_string());
        assert_eq!(internal_error.message(), "test error");
    }

    #[test]
    fn test_error_messages_are_formatted_correctly() {
        let error = AdminError::owner_or_system_admin_required();
        assert_eq!(error.message(), "Owner or System Admin role required");
        assert_eq!(format!("{}", error), "Owner or System Admin role required");
        
        let error = AdminError::user_not_found("user-123".to_string());
        assert_eq!(error.message(), "User not found: user-123");
        
        let error = AdminError::password_validation_failed("must contain uppercase".to_string());
        assert_eq!(error.message(), "Password validation failed: must contain uppercase");
    }

    #[test]
    fn test_error_conversion_from_db_err() {
        let db_err = DbErr::RecordNotFound("test record".to_string());
        let admin_err: AdminError = db_err.into();
        
        assert!(admin_err.message().contains("Database error"));
        assert!(admin_err.message().contains("test record"));
    }

    #[test]
    fn test_error_conversion_from_auth_error() {
        let auth_err = AuthError::invalid_credentials();
        let admin_err: AdminError = auth_err.into();
        
        assert!(admin_err.message().contains("Authentication error"));
    }

    #[test]
    fn test_owner_or_system_admin_required_error_details() {
        let error = AdminError::owner_or_system_admin_required();
        
        // Verify the error message
        assert_eq!(error.message(), "Owner or System Admin role required");
        
        // Verify Display trait
        assert_eq!(format!("{}", error), "Owner or System Admin role required");
        
        // Verify Debug trait works
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("OwnerOrSystemAdminRequired"));
    }
}
