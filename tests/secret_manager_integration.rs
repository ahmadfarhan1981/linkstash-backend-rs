mod common;

use std::sync::Arc;
use linkstash_backend::config::{SecretManager, SecretError};
use linkstash_backend::services::TokenService;
use uuid::Uuid;

#[test]
fn test_application_startup_with_valid_secrets() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Initialize SecretManager (simulating application startup)
    let result = SecretManager::init();
    assert!(result.is_ok(), "SecretManager should initialize successfully with valid secrets");

    let secret_manager = Arc::new(result.unwrap());
    
    // Verify secrets are accessible
    assert_eq!(secret_manager.jwt_secret(), "this-is-a-valid-jwt-secret-with-32-characters");
    assert_eq!(secret_manager.password_pepper(), "valid-pepper-16ch");
    assert_eq!(secret_manager.refresh_token_secret(), "this-is-a-valid-refresh-token-secret-32");
    
    // Verify SecretManager can be shared across threads (Arc)
    let secret_manager_clone = Arc::clone(&secret_manager);
    assert_eq!(secret_manager_clone.jwt_secret(), "this-is-a-valid-jwt-secret-with-32-characters");
}

#[test]
fn test_application_fails_gracefully_with_missing_jwt_secret() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set only PASSWORD_PEPPER and REFRESH_TOKEN_SECRET, missing JWT_SECRET
    unsafe {
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Attempt to initialize SecretManager
    let result = SecretManager::init();
    
    assert!(result.is_err(), "SecretManager should fail when JWT_SECRET is missing");
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    match err {
        SecretError::Missing { secret_name } => {
            assert_eq!(secret_name, "JWT_SECRET");
            assert_eq!(err_msg, "Required secret 'JWT_SECRET' is missing");
        }
        _ => panic!("Expected Missing error for JWT_SECRET"),
    }
}

#[test]
fn test_application_fails_gracefully_with_missing_password_pepper() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set only JWT_SECRET and REFRESH_TOKEN_SECRET, missing PASSWORD_PEPPER
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Attempt to initialize SecretManager
    let result = SecretManager::init();
    
    assert!(result.is_err(), "SecretManager should fail when PASSWORD_PEPPER is missing");
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    match err {
        SecretError::Missing { secret_name } => {
            assert_eq!(secret_name, "PASSWORD_PEPPER");
            assert_eq!(err_msg, "Required secret 'PASSWORD_PEPPER' is missing");
        }
        _ => panic!("Expected Missing error for PASSWORD_PEPPER"),
    }
}

#[test]
fn test_application_fails_gracefully_with_invalid_jwt_secret_length() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set JWT_SECRET that's too short
    unsafe {
        std::env::set_var("JWT_SECRET", "too-short");
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Attempt to initialize SecretManager
    let result = SecretManager::init();
    
    assert!(result.is_err(), "SecretManager should fail when JWT_SECRET is too short");
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    match err {
        SecretError::InvalidLength { secret_name, expected, actual } => {
            assert_eq!(secret_name, "JWT_SECRET");
            assert_eq!(expected, 32);
            assert_eq!(actual, 9);
            assert_eq!(err_msg, "Secret 'JWT_SECRET' must be at least 32 characters, got 9");
        }
        _ => panic!("Expected InvalidLength error for JWT_SECRET"),
    }
}

#[test]
fn test_application_fails_gracefully_with_invalid_password_pepper_length() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set PASSWORD_PEPPER that's too short
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PASSWORD_PEPPER", "short");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Attempt to initialize SecretManager
    let result = SecretManager::init();
    
    assert!(result.is_err(), "SecretManager should fail when PASSWORD_PEPPER is too short");
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    match err {
        SecretError::InvalidLength { secret_name, expected, actual } => {
            assert_eq!(secret_name, "PASSWORD_PEPPER");
            assert_eq!(expected, 16);
            assert_eq!(actual, 5);
            assert_eq!(err_msg, "Secret 'PASSWORD_PEPPER' must be at least 16 characters, got 5");
        }
        _ => panic!("Expected InvalidLength error for PASSWORD_PEPPER"),
    }
}

#[tokio::test]
async fn test_token_service_integration_with_secret_manager() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create audit store for TokenService
    let audit_store = common::create_test_audit_store().await;
    
    // Create TokenService with JWT secret and refresh token secret from SecretManager
    let token_service = Arc::new(TokenService::new(
        secret_manager.jwt_secret().to_string(),
        secret_manager.refresh_token_secret().to_string(),
        audit_store,
    ));
    
    // Verify TokenService was created successfully
    let user_id = Uuid::new_v4();
    let ctx = linkstash_backend::types::internal::context::RequestContext::new();
    let jwt_result = token_service.generate_jwt(&ctx, &user_id, false, false, false, vec![], false).await;
    
    assert!(jwt_result.is_ok(), "TokenService should generate JWT successfully");
}

#[tokio::test]
async fn test_jwt_generation_works_with_secrets_from_secret_manager() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create audit store for TokenService
    let audit_store = common::create_test_audit_store().await;
    
    // Create TokenService with JWT secret and refresh token secret from SecretManager
    let token_service = Arc::new(TokenService::new(
        secret_manager.jwt_secret().to_string(),
        secret_manager.refresh_token_secret().to_string(),
        audit_store,
    ));
    
    // Generate JWT
    let user_id = Uuid::new_v4();
    let ctx = linkstash_backend::types::internal::context::RequestContext::new();
    let (jwt, jwt_id) = token_service.generate_jwt(&ctx, &user_id, false, false, false, vec![], false).await.expect("JWT generation should succeed");
    
    // Verify JWT is not empty
    assert!(!jwt.is_empty(), "Generated JWT should not be empty");
    assert!(!jwt_id.is_empty(), "JWT ID should not be empty");
    
    // Verify JWT can be validated
    let claims_result = token_service.validate_jwt(&jwt).await;
    assert!(claims_result.is_ok(), "Generated JWT should be valid");
    
    let claims = claims_result.unwrap();
    assert_eq!(claims.sub, user_id.to_string(), "JWT should contain correct user_id");
}

#[tokio::test]
async fn test_jwt_validation_works_with_secrets_from_secret_manager() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create audit store for TokenService
    let audit_store = common::create_test_audit_store().await;
    
    // Create TokenService with JWT secret and refresh token secret from SecretManager
    let token_service = Arc::new(TokenService::new(
        secret_manager.jwt_secret().to_string(),
        secret_manager.refresh_token_secret().to_string(),
        audit_store,
    ));
    
    // Generate and validate JWT
    let user_id = Uuid::new_v4();
    let ctx = linkstash_backend::types::internal::context::RequestContext::new();
    let (jwt, _jwt_id) = token_service.generate_jwt(&ctx, &user_id, false, false, false, vec![], false).await.unwrap();
    let claims = token_service.validate_jwt(&jwt).await.unwrap();
    
    // Verify claims
    assert_eq!(claims.sub, user_id.to_string());
    assert!(claims.exp > claims.iat);
    assert_eq!(claims.exp - claims.iat, 900); // 15 minutes = 900 seconds
}

#[tokio::test]
async fn test_multiple_token_services_can_share_secret_manager() {
    let _lock = common::ENV_TEST_MUTEX.lock().unwrap();
    let _guard = common::EnvGuard::new(vec!["JWT_SECRET", "PASSWORD_PEPPER", "REFRESH_TOKEN_SECRET"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PASSWORD_PEPPER", "valid-pepper-16ch");
        std::env::set_var("REFRESH_TOKEN_SECRET", "this-is-a-valid-refresh-token-secret-32");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create audit stores for TokenServices
    let audit_store1 = common::create_test_audit_store().await;
    let audit_store2 = common::create_test_audit_store().await;
    
    // Create multiple TokenService instances with the same secret
    let token_service1 = Arc::new(TokenService::new(
        secret_manager.jwt_secret().to_string(),
        secret_manager.refresh_token_secret().to_string(),
        audit_store1,
    ));
    let token_service2 = Arc::new(TokenService::new(
        secret_manager.jwt_secret().to_string(),
        secret_manager.refresh_token_secret().to_string(),
        audit_store2,
    ));
    
    // Generate JWT with first service
    let user_id = Uuid::new_v4();
    let ctx = linkstash_backend::types::internal::context::RequestContext::new();
    let (jwt, _jwt_id) = token_service1.generate_jwt(&ctx, &user_id, false, false, false, vec![], false).await.unwrap();
    
    // Validate JWT with second service (should work because they share the same secret)
    let claims = token_service2.validate_jwt(&jwt).await.unwrap();
    assert_eq!(claims.sub, user_id.to_string());
}
