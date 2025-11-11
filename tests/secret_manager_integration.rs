use std::sync::{Arc, Mutex};

// Import from the main crate
use linkstash_backend::config::{SecretManager, SecretError};
use linkstash_backend::services::TokenService;
use uuid::Uuid;

// Global mutex to ensure tests run serially (environment variables are global)
static TEST_MUTEX: Mutex<()> = Mutex::new(());

// Helper to clean up environment variables after each test
struct EnvGuard {
    vars: Vec<String>,
}

impl EnvGuard {
    fn new(vars: Vec<&str>) -> Self {
        // Clean up before setting new values
        for var in &vars {
            unsafe {
                std::env::remove_var(var);
            }
        }
        Self {
            vars: vars.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for var in &self.vars {
            unsafe {
                std::env::remove_var(var);
            }
        }
    }
}

#[test]
fn test_application_startup_with_valid_secrets() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PEPPER", "valid-pepper-16ch");
    }

    // Initialize SecretManager (simulating application startup)
    let result = SecretManager::init();
    assert!(result.is_ok(), "SecretManager should initialize successfully with valid secrets");

    let secret_manager = Arc::new(result.unwrap());
    
    // Verify secrets are accessible
    assert_eq!(secret_manager.jwt_secret(), "this-is-a-valid-jwt-secret-with-32-characters");
    assert_eq!(secret_manager.pepper(), "valid-pepper-16ch");
    
    // Verify SecretManager can be shared across threads (Arc)
    let secret_manager_clone = Arc::clone(&secret_manager);
    assert_eq!(secret_manager_clone.jwt_secret(), "this-is-a-valid-jwt-secret-with-32-characters");
}

#[test]
fn test_application_fails_gracefully_with_missing_jwt_secret() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set only PEPPER, missing JWT_SECRET
    unsafe {
        std::env::set_var("PEPPER", "valid-pepper-16ch");
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
fn test_application_fails_gracefully_with_missing_pepper() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set only JWT_SECRET, missing PEPPER
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
    }

    // Attempt to initialize SecretManager
    let result = SecretManager::init();
    
    assert!(result.is_err(), "SecretManager should fail when PEPPER is missing");
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    match err {
        SecretError::Missing { secret_name } => {
            assert_eq!(secret_name, "PEPPER");
            assert_eq!(err_msg, "Required secret 'PEPPER' is missing");
        }
        _ => panic!("Expected Missing error for PEPPER"),
    }
}

#[test]
fn test_application_fails_gracefully_with_invalid_jwt_secret_length() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set JWT_SECRET that's too short
    unsafe {
        std::env::set_var("JWT_SECRET", "too-short");
        std::env::set_var("PEPPER", "valid-pepper-16ch");
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
fn test_application_fails_gracefully_with_invalid_pepper_length() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set PEPPER that's too short
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PEPPER", "short");
    }

    // Attempt to initialize SecretManager
    let result = SecretManager::init();
    
    assert!(result.is_err(), "SecretManager should fail when PEPPER is too short");
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    match err {
        SecretError::InvalidLength { secret_name, expected, actual } => {
            assert_eq!(secret_name, "PEPPER");
            assert_eq!(expected, 16);
            assert_eq!(actual, 5);
            assert_eq!(err_msg, "Secret 'PEPPER' must be at least 16 characters, got 5");
        }
        _ => panic!("Expected InvalidLength error for PEPPER"),
    }
}

#[test]
fn test_token_service_integration_with_secret_manager() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PEPPER", "valid-pepper-16ch");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create TokenService with JWT secret from SecretManager
    let token_service = Arc::new(TokenService::new(secret_manager.jwt_secret().to_string()));
    
    // Verify TokenService was created successfully
    let user_id = Uuid::new_v4();
    let jwt_result = token_service.generate_jwt(&user_id);
    
    assert!(jwt_result.is_ok(), "TokenService should generate JWT successfully");
}

#[test]
fn test_jwt_generation_works_with_secrets_from_secret_manager() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PEPPER", "valid-pepper-16ch");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create TokenService with JWT secret from SecretManager
    let token_service = Arc::new(TokenService::new(secret_manager.jwt_secret().to_string()));
    
    // Generate JWT
    let user_id = Uuid::new_v4();
    let jwt = token_service.generate_jwt(&user_id).expect("JWT generation should succeed");
    
    // Verify JWT is not empty
    assert!(!jwt.is_empty(), "Generated JWT should not be empty");
    
    // Verify JWT can be validated
    let claims_result = token_service.validate_jwt(&jwt);
    assert!(claims_result.is_ok(), "Generated JWT should be valid");
    
    let claims = claims_result.unwrap();
    assert_eq!(claims.sub, user_id.to_string(), "JWT should contain correct user_id");
}

#[test]
fn test_jwt_validation_works_with_secrets_from_secret_manager() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PEPPER", "valid-pepper-16ch");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create TokenService with JWT secret from SecretManager
    let token_service = Arc::new(TokenService::new(secret_manager.jwt_secret().to_string()));
    
    // Generate and validate JWT
    let user_id = Uuid::new_v4();
    let jwt = token_service.generate_jwt(&user_id).unwrap();
    let claims = token_service.validate_jwt(&jwt).unwrap();
    
    // Verify claims
    assert_eq!(claims.sub, user_id.to_string());
    assert!(claims.exp > claims.iat);
    assert_eq!(claims.exp - claims.iat, 900); // 15 minutes = 900 seconds
}

#[test]
fn test_multiple_token_services_can_share_secret_manager() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let _guard = EnvGuard::new(vec!["JWT_SECRET", "PEPPER"]);
    
    // Set valid environment variables
    unsafe {
        std::env::set_var("JWT_SECRET", "this-is-a-valid-jwt-secret-with-32-characters");
        std::env::set_var("PEPPER", "valid-pepper-16ch");
    }

    // Initialize SecretManager
    let secret_manager = Arc::new(SecretManager::init().unwrap());
    
    // Create multiple TokenService instances with the same secret
    let token_service1 = Arc::new(TokenService::new(secret_manager.jwt_secret().to_string()));
    let token_service2 = Arc::new(TokenService::new(secret_manager.jwt_secret().to_string()));
    
    // Generate JWT with first service
    let user_id = Uuid::new_v4();
    let jwt = token_service1.generate_jwt(&user_id).unwrap();
    
    // Validate JWT with second service (should work because they share the same secret)
    let claims = token_service2.validate_jwt(&jwt).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
}
