use poem_openapi::{payload::Json, OpenApi, Tags, SecurityScheme, auth::Bearer};
use poem::Request;
use crate::services::{AuthService, TokenService};
use crate::types::dto::auth::{LoginRequest, TokenResponse, WhoAmIResponse, RefreshRequest, RefreshResponse, LogoutRequest, LogoutResponse};
use crate::errors::auth::AuthError;
use std::sync::Arc;

/// Authentication API endpoints
pub struct AuthApi {
    auth_service: Arc<AuthService>,
    token_service: Arc<TokenService>,
}

impl AuthApi {
    /// Create a new AuthApi with the given AuthService and TokenService
    pub fn new(
        auth_service: Arc<AuthService>,
        token_service: Arc<TokenService>,
    ) -> Self {
        Self { 
            auth_service,
            token_service,
        }
    }
    
    /// Extract IP address from request headers
    /// 
    /// Checks X-Forwarded-For, X-Real-IP, and falls back to remote address
    fn extract_ip_address(req: &Request) -> Option<String> {
        // Check X-Forwarded-For header (proxy/load balancer)
        if let Some(forwarded) = req.header("X-Forwarded-For") {
            if let Some(ip) = forwarded.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
        
        // Check X-Real-IP header (nginx)
        if let Some(real_ip) = req.header("X-Real-IP") {
            return Some(real_ip.to_string());
        }
        
        // Fall back to remote address
        req.remote_addr()
            .as_socket_addr()
            .map(|addr| addr.ip().to_string())
    }
}

/// JWT Bearer token authentication
#[derive(SecurityScheme)]
#[oai(
    ty = "bearer",
    key_name = "Authorization",
    key_in = "header",
    bearer_format = "JWT"
)]
pub struct BearerAuth(Bearer);

/// API tags for authentication endpoints
#[derive(Tags)]
enum AuthTags {
    /// Authentication endpoints
    Authentication,
}

#[OpenApi(prefix_path = "/auth")]
impl AuthApi {
    /// Login with username and password to receive authentication tokens
    #[oai(path = "/login", method = "post", tag = "AuthTags::Authentication")]
    async fn login(&self, req: &Request, body: Json<LoginRequest>) -> Result<Json<TokenResponse>, AuthError> {
        // Extract IP address from request
        let ip_address = Self::extract_ip_address(req);
        
        // Delegate to AuthService for complete login flow with audit logging
        let (access_token, refresh_token) = self.auth_service
            .login(body.username.clone(), body.password.clone(), ip_address)
            .await?;
        
        // Return tokens
        Ok(Json(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 900, // 15 minutes in seconds
        }))
    }
    
    /// Verify JWT and return user information
    #[oai(path = "/whoami", method = "get", tag = "AuthTags::Authentication")]
    async fn whoami(&self, auth: BearerAuth) -> Result<Json<WhoAmIResponse>, AuthError> {
        // Validate JWT with audit logging
        let claims = self.auth_service.validate_jwt_with_audit(&auth.0.token).await?;
        
        // Return user info
        Ok(Json(WhoAmIResponse {
            user_id: claims.sub,
            expires_at: claims.exp,
        }))
    }
    
    /// Refresh access token using a refresh token
    #[oai(path = "/refresh", method = "post", tag = "AuthTags::Authentication")]
    async fn refresh(&self, body: Json<RefreshRequest>) -> Result<Json<RefreshResponse>, AuthError> {
        // Delegate to AuthService for refresh flow with audit logging
        let access_token = self.auth_service
            .refresh(body.refresh_token.clone())
            .await?;
        
        // Return new JWT (keep same refresh token)
        Ok(Json(RefreshResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 900, // 15 minutes in seconds
        }))
    }
    
    /// Logout and revoke refresh token
    #[oai(path = "/logout", method = "post", tag = "AuthTags::Authentication")]
    async fn logout(&self, auth: BearerAuth, body: Json<LogoutRequest>) -> Result<Json<LogoutResponse>, AuthError> {
        // Validate JWT to get authenticated user
        let claims = self.token_service.validate_jwt(&auth.0.token)?;
        
        // Delegate to AuthService for logout flow with audit logging
        self.auth_service
            .logout(body.refresh_token.clone(), claims.sub, claims.jti)
            .await?;
        
        // Return success message
        Ok(Json(LogoutResponse {
            message: "Logged out successfully".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poem_openapi::payload::Json;
    use sea_orm::{Database, DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter};
    use migration::{Migrator, MigratorTrait};
    use crate::services::AuthService;
    use crate::stores::{AuditStore, CredentialStore};

    async fn setup_test_db() -> (DatabaseConnection, DatabaseConnection, Arc<AuthService>, Arc<TokenService>, Arc<CredentialStore>) {
        
        // Create in-memory SQLite database for testing
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        // Run migrations
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        // Create in-memory audit database for testing
        let audit_db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create audit test database");
        
        // Run migrations on audit database
        Migrator::up(&audit_db, None)
            .await
            .expect("Failed to run audit migrations");
        
        // Create credential store with test password pepper
        let password_pepper = "test-pepper-for-api-tests".to_string();
        let credential_store = Arc::new(CredentialStore::new(db.clone(), password_pepper));
        
        // Create token manager with test secret and refresh token secret
        let token_service = Arc::new(TokenService::new(
            "test-secret-key-minimum-32-characters-long".to_string(),
            "test-refresh-secret-minimum-32-chars".to_string(),
        ));
        
        // Create audit store
        let audit_store = Arc::new(AuditStore::new(audit_db.clone()));
        
        // Create auth service
        let auth_service = Arc::new(AuthService::new(
            credential_store.clone(),
            token_service.clone(),
            audit_store.clone(),
        ));
        
        // Add test user
        credential_store
            .add_user("testuser".to_string(), "testpass".to_string())
            .await
            .expect("Failed to create test user");
        
        (db, audit_db, auth_service, token_service, credential_store)
    }

    #[tokio::test]
    async fn test_login_with_valid_credentials() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        // JWT should no longer be placeholder
        assert_ne!(response.access_token, "placeholder-jwt");
        assert!(!response.access_token.is_empty());
        // Refresh token should no longer be placeholder
        assert_ne!(response.refresh_token, "placeholder-rt");
        assert!(!response.refresh_token.is_empty());
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 900);
    }

    #[tokio::test]
    async fn test_login_with_invalid_credentials() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "wronguser".to_string(),
            password: "wrongpass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidCredentials(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_login_response_contains_required_fields() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Verify all required fields are present and non-empty
        assert!(!response.access_token.is_empty());
        assert!(!response.refresh_token.is_empty());
        assert!(!response.token_type.is_empty());
        assert!(response.expires_in > 0);
    }
    
    #[tokio::test]
    async fn test_login_with_nonexistent_user() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "nonexistent".to_string(),
            password: "somepass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidCredentials(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidCredentials error"),
        }
    }
    
    #[tokio::test]
    async fn test_login_returns_decodable_jwt() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Decode JWT and verify it contains expected claims
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false; // Don't validate expiration in test
        
        let decoded = decode::<Claims>(
            &response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        );
        
        assert!(decoded.is_ok());
        let claims = decoded.unwrap().claims;
        
        // Verify claims structure
        assert!(!claims.sub.is_empty()); // User ID should be present
        assert!(claims.exp > claims.iat); // Expiration should be after issuance
        assert_eq!(claims.exp - claims.iat, 900); // Should be 15 minutes (900 seconds)
    }

    #[tokio::test]
    async fn test_whoami_with_valid_jwt_returns_200_and_user_id() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service.clone(), token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get a valid JWT
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Call whoami
        let result = api.whoami(auth).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.user_id.is_empty());
        assert!(response.expires_at > 0);
    }

    // Test removed: poem-openapi automatically handles missing Authorization header
    // and returns 401 before reaching the handler

    #[tokio::test]
    async fn test_whoami_with_invalid_jwt_returns_401() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create BearerAuth with invalid JWT
        let auth = BearerAuth(Bearer { token: "invalid-jwt-token".to_string() });
        
        // Call whoami with invalid JWT
        let result = api.whoami(auth).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[tokio::test]
    async fn test_whoami_with_expired_jwt_returns_401() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create an expired JWT manually
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
        use chrono::Utc;
        use crate::types::internal::auth::Claims;
        
        let now = Utc::now().timestamp();
        let expired_claims = Claims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200, // Issued 2 hours ago
            jti: Some(uuid::Uuid::new_v4().to_string()),
        };
        
        let expired_token = encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
        ).unwrap();
        
        // Create BearerAuth with expired JWT
        let auth = BearerAuth(Bearer { token: expired_token });
        
        // Call whoami with expired JWT
        let result = api.whoami(auth).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::ExpiredToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredToken error"),
        }
    }

    // Test removed: poem-openapi automatically handles malformed Authorization header
    // and returns 401 before reaching the handler

    #[tokio::test]
    async fn test_login_refresh_token_is_not_placeholder() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Verify refresh token is not placeholder
        assert_ne!(response.refresh_token, "placeholder-rt");
        
        // Verify it's a base64-encoded string (should be 44 characters for 32 bytes)
        assert_eq!(response.refresh_token.len(), 44);
    }

    #[tokio::test]
    async fn test_login_stores_refresh_token_in_database() {
        let (db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(&req, request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Hash the returned refresh token
        let token_hash = token_service.hash_refresh_token(&response.refresh_token);
        
        // Verify token is stored in database
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let stored_token = RefreshToken::find()
            .filter(Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        
        assert!(stored_token.is_some());
        let stored_token = stored_token.unwrap();
        
        // Verify the stored token has correct properties
        assert_eq!(stored_token.token_hash, token_hash);
        assert!(!stored_token.user_id.is_empty());
        
        // Verify expiration is approximately 7 days from now
        let now = chrono::Utc::now().timestamp();
        let expected_expiration = now + (7 * 24 * 60 * 60);
        let diff = (stored_token.expires_at - expected_expiration).abs();
        assert!(diff < 5); // Within 5 seconds tolerance
    }

    #[tokio::test]
    async fn test_refresh_with_valid_token_returns_200_and_new_jwt() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Wait a moment to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Verify response contains new JWT
        assert!(!response.access_token.is_empty());
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 900);
        
        // Verify new JWT is different from original (due to different timestamps)
        assert_ne!(response.access_token, login_response.access_token);
    }

    #[tokio::test]
    async fn test_refresh_with_invalid_token_returns_401() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Try to refresh with invalid token
        let refresh_request = Json(RefreshRequest {
            refresh_token: "invalid-token-12345".to_string(),
        });
        let result = api.refresh(refresh_request).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidRefreshToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_refresh_with_expired_token_returns_401() {
        let (_db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service.clone(), token_service.clone());
        
        // Add a user
        let user_id = credential_store
            .add_user("expireduser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Create an expired refresh token
        let expired_token = token_service.generate_refresh_token();
        let token_hash = token_service.hash_refresh_token(&expired_token);
        let expires_at = chrono::Utc::now().timestamp() - 3600; // Expired 1 hour ago
        
        credential_store
            .store_refresh_token(token_hash, user_id, expires_at)
            .await
            .expect("Failed to store expired token");
        
        // Try to refresh with expired token
        let refresh_request = Json(RefreshRequest {
            refresh_token: expired_token,
        });
        let result = api.refresh(refresh_request).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::ExpiredRefreshToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_refresh_new_jwt_has_updated_expiration_time() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Wait a moment to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let refresh_response = api.refresh(refresh_request).await.unwrap();
        
        // Decode both JWTs and compare expiration times
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let original_claims = decode::<Claims>(
            &login_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        let new_claims = decode::<Claims>(
            &refresh_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // New JWT should have a later expiration time
        assert!(new_claims.exp > original_claims.exp);
        assert!(new_claims.iat > original_claims.iat);
    }

    #[tokio::test]
    async fn test_refresh_new_jwt_contains_correct_user_id() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let refresh_response = api.refresh(refresh_request).await.unwrap();
        
        // Decode both JWTs and verify user_id matches
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let original_claims = decode::<Claims>(
            &login_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        let new_claims = decode::<Claims>(
            &refresh_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Both JWTs should contain the same user_id
        assert_eq!(new_claims.sub, original_claims.sub);
        assert!(!new_claims.sub.is_empty());
    }

    #[tokio::test]
    async fn test_logout_with_valid_token_returns_200() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Logout with valid refresh token
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.logout(auth, logout_request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.message, "Logged out successfully");
    }

    #[tokio::test]
    async fn test_logout_removes_token_from_database() {
        let (db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Hash the refresh token to check database
        let token_hash = token_service.hash_refresh_token(&login_response.refresh_token);
        
        // Verify token exists in database
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let token_before = RefreshToken::find()
            .filter(Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_before.is_some());
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Logout
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        api.logout(auth, logout_request).await.unwrap();
        
        // Verify token is removed from database
        let token_after = RefreshToken::find()
            .filter(Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_after.is_none());
    }

    #[tokio::test]
    async fn test_logout_with_invalid_token_still_returns_200() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get a valid JWT
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Logout with invalid refresh token
        let logout_request = Json(LogoutRequest {
            refresh_token: "invalid-token-12345".to_string(),
        });
        let result = api.logout(auth, logout_request).await;
        
        // Should still return success
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.message, "Logged out successfully");
    }

    #[tokio::test]
    async fn test_refresh_fails_after_logout_with_401() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Logout
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        api.logout(auth, logout_request).await.unwrap();
        
        // Try to refresh with revoked token
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        
        // Should return 401 error
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidRefreshToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidRefreshToken error"),
        }
    }

    #[tokio::test]
    async fn test_logout_cannot_revoke_another_users_token() {
        let (db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service.clone(), token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Create a second user
        credential_store
            .add_user("user2".to_string(), "password2".to_string())
            .await
            .expect("Failed to create user2");
        
        // Login as testuser
        let login1_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login1_response = api.login(&req, login1_request).await.unwrap();
        
        // Login as user2
        let login2_request = Json(LoginRequest {
            username: "user2".to_string(),
            password: "password2".to_string(),
        });
        let login2_response = api.login(&req, login2_request).await.unwrap();
        
        // Try to logout user2's token using testuser's JWT
        let auth = BearerAuth(Bearer { token: login1_response.access_token.clone() });
        let logout_request = Json(LogoutRequest {
            refresh_token: login2_response.refresh_token.clone(),
        });
        api.logout(auth, logout_request).await.unwrap();
        
        // Verify user2's token still exists (wasn't deleted)
        let token_hash = token_service.hash_refresh_token(&login2_response.refresh_token);
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let token_after = RefreshToken::find()
            .filter(Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_after.is_some());
        
        // Verify user2 can still refresh
        let refresh_request = Json(RefreshRequest {
            refresh_token: login2_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        assert!(result.is_ok());
    }

    // ========== Audit Trail Tests ==========

    #[tokio::test]
    async fn test_login_success_creates_audit_trail() {
        let (_db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Perform login
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let result = api.login(&req, request).await;
        assert!(result.is_ok());
        
        // Query audit database to verify events were created
        use crate::types::db::audit_event::{Entity as AuditEvent, Column};
        use sea_orm::EntityTrait;
        
        // Connect to audit database (same connection pool in tests)
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 3 events: login_success, jwt_issued, refresh_token_issued
        assert_eq!(audit_events.len(), 3, "Expected 3 audit events");
        
        // Verify login_success event
        let login_event = audit_events.iter()
            .find(|e| e.event_type == "login_success")
            .expect("login_success event not found");
        assert!(login_event.user_id.len() > 0);
        // IP address is None in mock requests
        assert!(login_event.ip_address.is_none());
        
        // Verify jwt_issued event
        let jwt_event = audit_events.iter()
            .find(|e| e.event_type == "jwt_issued")
            .expect("jwt_issued event not found");
        assert!(jwt_event.jwt_id.is_some());
        
        // Verify refresh_token_issued event
        let refresh_event = audit_events.iter()
            .find(|e| e.event_type == "refresh_token_issued")
            .expect("refresh_token_issued event not found");
        assert!(refresh_event.jwt_id.is_some());
    }

    #[tokio::test]
    async fn test_login_failure_creates_audit_trail() {
        let (_db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Attempt login with wrong password
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
        });
        let result = api.login(&req, request).await;
        assert!(result.is_err());
        
        // Query audit database to verify login_failure event was created
        use crate::types::db::audit_event::{Entity as AuditEvent, Column};
        use sea_orm::EntityTrait;
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 event: login_failure
        assert_eq!(audit_events.len(), 1, "Expected 1 audit event");
        
        let login_failure = &audit_events[0];
        assert_eq!(login_failure.event_type, "login_failure");
        assert_eq!(login_failure.user_id, "unknown"); // No user_id for failed login
        // IP address is None in mock requests
        assert!(login_failure.ip_address.is_none());
        
        // Verify failure reason is in data
        let data: serde_json::Value = serde_json::from_str(&login_failure.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["failure_reason"], "invalid_credentials");
    }

    #[tokio::test]
    async fn test_refresh_creates_jwt_issued_audit_trail() {
        let (_db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // First, login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Clear audit events from login
        use crate::types::db::audit_event::{Entity as AuditEvent};
        use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};
        use crate::types::db::audit_event::Column;
        
        // Count events before refresh
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Now refresh the token
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        assert!(result.is_ok());
        
        // Query audit database to verify jwt_issued event was created
        let events_after = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 more event (jwt_issued from refresh)
        assert_eq!(events_after.len(), events_before + 1, "Expected 1 new audit event from refresh");
        
        // Verify the new event is jwt_issued
        let jwt_event = events_after.last().expect("No events found");
        assert_eq!(jwt_event.event_type, "jwt_issued");
        assert!(jwt_event.jwt_id.is_some());
    }

    #[tokio::test]
    async fn test_logout_creates_refresh_token_revoked_audit_trail() {
        let (_db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // First, login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(&req, login_request).await.unwrap();
        
        // Count events before logout
        use crate::types::db::audit_event::{Entity as AuditEvent};
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Logout
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.logout(auth, logout_request).await;
        assert!(result.is_ok());
        
        // Query audit database to verify refresh_token_revoked event was created
        let events_after = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 more event (refresh_token_revoked from logout)
        assert_eq!(events_after.len(), events_before + 1, "Expected 1 new audit event from logout");
        
        // Verify the new event is refresh_token_revoked
        let revoke_event = events_after.last().expect("No events found");
        assert_eq!(revoke_event.event_type, "refresh_token_revoked");
        assert!(revoke_event.jwt_id.is_some());
    }

    #[tokio::test]
    async fn test_whoami_with_expired_jwt_creates_validation_failure_audit_trail() {
        let (_db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create an expired JWT manually
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
        use chrono::Utc;
        use crate::types::internal::auth::Claims;
        
        let now = Utc::now().timestamp();
        let expired_claims = Claims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200, // Issued 2 hours ago
            jti: Some(uuid::Uuid::new_v4().to_string()),
        };
        
        let expired_token = encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
        ).unwrap();
        
        // Create BearerAuth with expired JWT
        let auth = BearerAuth(Bearer { token: expired_token });
        
        // Call whoami with expired JWT
        let result = api.whoami(auth).await;
        assert!(result.is_err());
        
        // Query audit database to verify jwt_validation_failure event was created
        use crate::types::db::audit_event::{Entity as AuditEvent};
        use sea_orm::EntityTrait;
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 event: jwt_validation_failure
        assert_eq!(audit_events.len(), 1, "Expected 1 audit event");
        
        let validation_failure = &audit_events[0];
        assert_eq!(validation_failure.event_type, "jwt_validation_failure");
        assert!(validation_failure.user_id.len() > 0);
        assert!(validation_failure.jwt_id.is_some());
        
        // Verify failure reason is in data
        let data: serde_json::Value = serde_json::from_str(&validation_failure.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["failure_reason"], "expired");
    }

    #[tokio::test]
    async fn test_whoami_with_tampered_jwt_creates_tampering_audit_trail() {
        let (_db, audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a JWT with wrong signature (tampered)
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
        use chrono::Utc;
        use crate::types::internal::auth::Claims;
        
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: now + 3600, // Valid expiration
            iat: now,
            jti: Some(uuid::Uuid::new_v4().to_string()),
        };
        
        // Sign with wrong secret (simulating tampering)
        let tampered_token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"wrong-secret-key-this-is-tampered"),
        ).unwrap();
        
        // Create BearerAuth with tampered JWT
        let auth = BearerAuth(Bearer { token: tampered_token.clone() });
        
        // Call whoami with tampered JWT
        let result = api.whoami(auth).await;
        assert!(result.is_err());
        
        // Query audit database to verify jwt_tampered event was created
        use crate::types::db::audit_event::{Entity as AuditEvent};
        use sea_orm::EntityTrait;
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 event: jwt_tampered
        assert_eq!(audit_events.len(), 1, "Expected 1 audit event");
        
        let tampered_event = &audit_events[0];
        assert_eq!(tampered_event.event_type, "jwt_tampered");
        assert!(tampered_event.user_id.len() > 0);
        assert!(tampered_event.jwt_id.is_some());
        
        // Verify failure reason and full JWT are in data
        let data: serde_json::Value = serde_json::from_str(&tampered_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["failure_reason"], "invalid_signature");
        assert_eq!(data["full_jwt"], tampered_token);
    }
}


