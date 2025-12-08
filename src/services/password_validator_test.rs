#[cfg(test)]
mod tests {
    use crate::services::{PasswordValidator, PasswordValidationError};
    use crate::test::utils::setup_test_stores;
    use crate::stores::{CommonPasswordStore, HibpCacheStore, SystemConfigStore};
    use std::sync::Arc;

    async fn setup_validator() -> PasswordValidator {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        let common_password_store = Arc::new(CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(SystemConfigStore::new(db.clone(), audit_store));
        let hibp_cache_store = Arc::new(HibpCacheStore::new(db.clone(), system_config_store));
        
        PasswordValidator::new(common_password_store, hibp_cache_store)
    }

    #[tokio::test]
    async fn test_password_too_short() {
        let validator = setup_validator().await;
        let result = validator.validate("short", None).await;
        
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordValidationError::TooShort(min) => assert_eq!(min, 15),
            _ => panic!("Expected TooShort error"),
        }
    }

    #[tokio::test]
    async fn test_password_too_long() {
        let validator = setup_validator().await;
        let long_password = "a".repeat(129);
        let result = validator.validate(&long_password, None).await;
        
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordValidationError::TooLong(max) => assert_eq!(max, 128),
            _ => panic!("Expected TooLong error"),
        }
    }

    #[tokio::test]
    async fn test_valid_password_length() {
        let validator = setup_validator().await;
        // This password is 15 characters and should pass length validation
        // It may fail HIBP check if it's compromised, but that's expected
        let result = validator.validate("ValidPassword15", None).await;
        
        // We expect either Ok or CompromisedPassword error (not length errors)
        match result {
            Ok(_) => {},
            Err(PasswordValidationError::CompromisedPassword) => {},
            Err(e) => panic!("Expected Ok or CompromisedPassword, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_known_compromised_password() {
        let validator = setup_validator().await;
        // "password1234567" is a well-known compromised password
        let result = validator.validate("password1234567", None).await;
        
        // Should fail with CompromisedPassword
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordValidationError::CompromisedPassword => {
                // Expected - this password is in HIBP database
            },
            e => panic!("Expected CompromisedPassword error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_generate_secure_password() {
        let validator = setup_validator().await;
        let password = validator.generate_secure_password();
        
        // Generated password should be 20 characters
        assert_eq!(password.len(), 20);
        
        // Should pass validation
        let result = validator.validate(&password, None).await;
        assert!(result.is_ok() || matches!(result, Err(PasswordValidationError::CompromisedPassword)));
    }

    #[tokio::test]
    async fn test_hibp_cache_is_populated() {
        let (db, _audit_db, _credential_store, audit_store) = setup_test_stores().await;
        let common_password_store = Arc::new(CommonPasswordStore::new(db.clone()));
        let system_config_store = Arc::new(SystemConfigStore::new(db.clone(), audit_store));
        let hibp_cache_store = Arc::new(HibpCacheStore::new(db.clone(), system_config_store));
        
        let validator = PasswordValidator::new(common_password_store, hibp_cache_store.clone());
        
        // Validate a password (this will call HIBP API and cache the result)
        let password = "test-password-123";
        let _ = validator.validate(password, None).await;
        
        // Compute the hash prefix that should be cached
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = format!("{:X}", hasher.finalize());
        let prefix = &hash[..5];
        
        // Verify the cache was populated
        let cached = hibp_cache_store.get_cached_response(prefix).await;
        assert!(cached.is_ok());
        assert!(cached.unwrap().is_some(), "Cache should contain HIBP response after validation");
        
        // Validate the same password again (should use cache, not API)
        // We can't directly verify no API call was made, but we can verify it still works
        let result2 = validator.validate(password, None).await;
        assert!(result2.is_ok() || matches!(result2, Err(PasswordValidationError::CompromisedPassword)));
    }

    #[tokio::test]
    async fn test_secure_password_not_in_hibp() {
        let validator = setup_validator().await;
        // Use a cryptographically random password that's extremely unlikely to be in HIBP
        // Format: "SecurePass" + UUID (guaranteed unique, 15+ chars)
        use uuid::Uuid;
        let unique_password = format!("SecurePass-{}", Uuid::new_v4());
        
        let result = validator.validate(&unique_password, None).await;
        
        // Should pass validation (not compromised)
        assert!(result.is_ok(), "Unique secure password should pass HIBP check");
    }
}
