use poem_openapi::{payload::Json, OpenApi, Tags, SecurityScheme, auth::Bearer};
use poem::Request;
use crate::services::{AuthService, TokenService};
use crate::types::dto::auth::{
    LoginRequest, TokenResponse, WhoAmIResponse, RefreshRequest, RefreshResponse, 
    LogoutRequest, LogoutResponse, LoginApiResponse, WhoAmIApiResponse, 
    RefreshApiResponse, LogoutApiResponse, ErrorResponse
};
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
    
    /// Create RequestContext from request and optional authentication
    /// 
    /// This helper function should be called at the beginning of every endpoint.
    /// It creates a RequestContext with IP address and request_id, and if authentication
    /// is provided, validates the JWT and populates the claims.
    /// 
    /// # Arguments
    /// * `req` - The HTTP request
    /// * `auth` - Optional BearerAuth token (None for unauthenticated endpoints)
    /// 
    /// # Returns
    /// RequestContext with authenticated=true if JWT is valid, false otherwise
    async fn create_request_context(
        &self,
        req: &Request,
        auth: Option<BearerAuth>,
    ) -> crate::types::internal::context::RequestContext {
        // Extract IP address
        let ip_address = Self::extract_ip_address(req);
        
        // Create base context with IP and request_id
        let mut ctx = crate::types::internal::context::RequestContext::new()
            .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));
        
        // If auth is provided, validate JWT and populate claims
        if let Some(bearer) = auth {
            // Validate JWT (handles all audit logging automatically)
            match self.auth_service.validate_jwt(&bearer.0.token).await {
                Ok(claims) => {
                    // JWT is valid, set authenticated and claims
                    ctx = ctx.with_auth(claims);
                }
                Err(_) => {
                    // JWT validation failed (expired, invalid, tampered)
                    // validate_jwt already logged the failure
                    // Context remains with authenticated=false, claims=None
                }
            }
        }
        
        // Temporary trace log to verify context creation (will be removed later)
        tracing::trace!("Request context created: {:?}", ctx);
        
        ctx
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
    async fn login(&self, req: &Request, body: Json<LoginRequest>) -> LoginApiResponse {
        // Extract IP address from request
        let ip_address = Self::extract_ip_address(req);
        
        // Delegate to AuthService for complete login flow with audit logging
        match self.auth_service
            .login(body.username.clone(), body.password.clone(), ip_address)
            .await
        {
            Ok((access_token, refresh_token)) => {
                LoginApiResponse::Ok(Json(TokenResponse {
                    access_token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 900, // 15 minutes in seconds
                }))
            }
            Err(e) => {
                LoginApiResponse::Unauthorized(Json(ErrorResponse {
                    error: e.to_string(),
                }))
            }
        }
    }
    
    /// Verify JWT and return user information
    #[oai(path = "/whoami", method = "get", tag = "AuthTags::Authentication")]
    async fn whoami(&self, req: &Request, auth: BearerAuth) -> WhoAmIApiResponse {
        // Create request context with authentication
        let ctx = self.create_request_context(req, Some(auth)).await;
        
        // Check if authenticated
        if !ctx.authenticated {
            return WhoAmIApiResponse::Unauthorized(Json(ErrorResponse {
                error: "Unauthenticated".to_string(),
            }));
        }
        
        // Get claims from context (safe because authenticated=true)
        let claims = ctx.claims.unwrap();
        
        WhoAmIApiResponse::Ok(Json(WhoAmIResponse {
            user_id: claims.sub,
            expires_at: claims.exp,
        }))
    }
    
    /// Refresh access token using a refresh token
    #[oai(path = "/refresh", method = "post", tag = "AuthTags::Authentication")]
    async fn refresh(&self, body: Json<RefreshRequest>) -> RefreshApiResponse {
        // Delegate to AuthService for refresh flow with audit logging
        match self.auth_service
            .refresh(body.refresh_token.clone())
            .await
        {
            Ok(access_token) => {
                RefreshApiResponse::Ok(Json(RefreshResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 900, // 15 minutes in seconds
                }))
            }
            Err(e) => {
                RefreshApiResponse::Unauthorized(Json(ErrorResponse {
                    error: e.to_string(),
                }))
            }
        }
    }
    
    /// Logout and revoke refresh token
    /// 
    /// Always returns 200 OK to avoid information leakage about token validity.
    /// Authentication is optional - if provided, enables better audit logging.
    /// 
    /// # Arguments
    /// * `req` - HTTP request (used to extract optional Authorization header and IP address)
    /// * `body` - Logout request containing the refresh token to revoke
    /// 
    /// # Returns
    /// Always returns 200 OK with success message, regardless of outcome
    #[oai(path = "/logout", method = "post", tag = "AuthTags::Authentication")]
    async fn logout(&self, req: &Request, body: Json<LogoutRequest>) -> LogoutApiResponse {
        // Manual header extraction because poem-openapi doesn't support Option<BearerAuth>
        let auth = req.header("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|token| BearerAuth(Bearer { token: token.to_string() }));
        
        let ctx = self.create_request_context(req, auth).await;
        
        // Always return 200 to avoid leaking token validity information
        let _ = self.auth_service.logout(&ctx, body.refresh_token.clone()).await;
        
        LogoutApiResponse::Ok(Json(LogoutResponse {
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
    
    // Helper functions to extract values from ApiResponse enums
    fn unwrap_login_ok(response: LoginApiResponse) -> TokenResponse {
        match response {
            LoginApiResponse::Ok(json) => json.0,
            LoginApiResponse::Unauthorized(_) => panic!("Expected Ok response, got Unauthorized"),
        }
    }
    
    fn unwrap_whoami_ok(response: WhoAmIApiResponse) -> WhoAmIResponse {
        match response {
            WhoAmIApiResponse::Ok(json) => json.0,
            WhoAmIApiResponse::Unauthorized(_) => panic!("Expected Ok response, got Unauthorized"),
        }
    }
    
    fn unwrap_refresh_ok(response: RefreshApiResponse) -> RefreshResponse {
        match response {
            RefreshApiResponse::Ok(json) => json.0,
            RefreshApiResponse::Unauthorized(_) => panic!("Expected Ok response, got Unauthorized"),
        }
    }
    
    fn unwrap_logout_ok(response: LogoutApiResponse) -> LogoutResponse {
        match response {
            LogoutApiResponse::Ok(json) => json.0,
            LogoutApiResponse::Unauthorized(_) => panic!("Expected Ok response, got Unauthorized"),
        }
    }
    
    fn assert_login_unauthorized(response: LoginApiResponse) {
        match response {
            LoginApiResponse::Unauthorized(_) => {},
            LoginApiResponse::Ok(_) => panic!("Expected Unauthorized response, got Ok"),
        }
    }
    
    fn assert_whoami_unauthorized(response: WhoAmIApiResponse) {
        match response {
            WhoAmIApiResponse::Unauthorized(_) => {},
            WhoAmIApiResponse::Ok(_) => panic!("Expected Unauthorized response, got Ok"),
        }
    }
    
    fn assert_refresh_unauthorized(response: RefreshApiResponse) {
        match response {
            RefreshApiResponse::Unauthorized(_) => {},
            RefreshApiResponse::Ok(_) => panic!("Expected Unauthorized response, got Ok"),
        }
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
        
        match result {
            LoginApiResponse::Ok(response) => {
                // JWT should no longer be placeholder
                assert_ne!(response.access_token, "placeholder-jwt");
                assert!(!response.access_token.is_empty());
                // Refresh token should no longer be placeholder
                assert_ne!(response.refresh_token, "placeholder-rt");
                assert!(!response.refresh_token.is_empty());
                assert_eq!(response.token_type, "Bearer");
                assert_eq!(response.expires_in, 900);
            }
            LoginApiResponse::Unauthorized(_) => panic!("Expected successful login"),
        }
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
        
        match result {
            LoginApiResponse::Unauthorized(_) => {
                // Expected error type
            }
            LoginApiResponse::Ok(_) => panic!("Expected InvalidCredentials error"),
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
        let response = unwrap_login_ok(result);
        
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
        assert_login_unauthorized(result);
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
        let response = unwrap_login_ok(result);
        
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Create BearerAuth with the JWT
        let auth = BearerAuth(Bearer { token: login_response.access_token.clone() });
        
        // Call whoami
        let result = api.whoami(&req, auth).await;
        let response = unwrap_whoami_ok(result);
        assert!(!response.user_id.is_empty());
        assert!(response.expires_at > 0);
    }

    // Test removed: poem-openapi automatically handles missing Authorization header
    // and returns 401 before reaching the handler

    #[tokio::test]
    async fn test_whoami_with_invalid_jwt_returns_401() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Create BearerAuth with invalid JWT
        let auth = BearerAuth(Bearer { token: "invalid-jwt-token".to_string() });
        
        // Call whoami with invalid JWT
        let result = api.whoami(&req, auth).await;
        assert_whoami_unauthorized(result);
    }

    #[tokio::test]
    async fn test_whoami_with_expired_jwt_returns_401() {
        let (_db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
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
        let result = api.whoami(&req, auth).await;
        assert_whoami_unauthorized(result);
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
        let response = unwrap_login_ok(result);
        
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
        let response = unwrap_login_ok(result);
        
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Wait a moment to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        let response = unwrap_refresh_ok(result);
        
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
        assert_refresh_unauthorized(result);
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
        assert_refresh_unauthorized(result);
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Wait a moment to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let refresh_response = unwrap_refresh_ok(api.refresh(refresh_request).await);
        
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let refresh_response = unwrap_refresh_ok(api.refresh(refresh_request).await);
        
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Create request with Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        // Logout with valid refresh token
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.logout(&req_with_auth, logout_request).await;
        let response = unwrap_logout_ok(result);
        assert_eq!(response.message, "Logged out successfully");
    }

    #[tokio::test]
    async fn test_logout_removes_token_from_database() {
        let (db, _audit_db, auth_service, token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service, token_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
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
        
        // Create request with Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        // Logout
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        unwrap_logout_ok(api.logout(&req_with_auth, logout_request).await);
        
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Create request with Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        // Logout with invalid refresh token
        let logout_request = Json(LogoutRequest {
            refresh_token: "invalid-token-12345".to_string(),
        });
        let result = api.logout(&req_with_auth, logout_request).await;
        
        // Should still return success
        let response = unwrap_logout_ok(result);
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Create request with Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        // Logout
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        unwrap_logout_ok(api.logout(&req_with_auth, logout_request).await);
        
        // Try to refresh with revoked token
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        
        // Should return 401 error
        assert_refresh_unauthorized(result);
    }

    #[tokio::test]
    async fn test_logout_revokes_any_refresh_token() {
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
        let login1_response = unwrap_login_ok(api.login(&req, login1_request).await);
        
        // Login as user2
        let login2_request = Json(LoginRequest {
            username: "user2".to_string(),
            password: "password2".to_string(),
        });
        let login2_response = unwrap_login_ok(api.login(&req, login2_request).await);
        
        // Logout user2's token using testuser's JWT (or any JWT)
        // This works because RT is the authority, not the JWT
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login1_response.access_token))
            .finish();
        let logout_request = Json(LogoutRequest {
            refresh_token: login2_response.refresh_token.clone(),
        });
        unwrap_logout_ok(api.logout(&req_with_auth, logout_request).await);
        
        // Verify user2's token is deleted (RT is the authority)
        let token_hash = token_service.hash_refresh_token(&login2_response.refresh_token);
        use crate::types::db::refresh_token::{Entity as RefreshToken, Column};
        let token_after = RefreshToken::find()
            .filter(Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await
            .expect("Failed to query token");
        assert!(token_after.is_none());
        
        // Verify user2 cannot refresh anymore
        let refresh_request = Json(RefreshRequest {
            refresh_token: login2_response.refresh_token.clone(),
        });
        let result = api.refresh(refresh_request).await;
        // Should fail
        assert_refresh_unauthorized(result);
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
        unwrap_login_ok(result);
        
        // Query audit database to verify events were created
        use crate::types::db::audit_event::Entity as AuditEvent;
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
        assert_login_unauthorized(result);
        
        // Query audit database to verify login_failure event was created
        use crate::types::db::audit_event::Entity as AuditEvent;
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Clear audit events from login
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
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
        unwrap_refresh_ok(result);
        
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
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Count events before logout
        use crate::types::db::audit_event::{Entity as AuditEvent};
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Create request with Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        // Logout
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.logout(&req_with_auth, logout_request).await;
        unwrap_logout_ok(result);
        
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
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
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
        let result = api.whoami(&req, auth).await;
        assert_whoami_unauthorized(result);
        
        // Query audit database to verify jwt_validation_failure event was created
        use crate::types::db::audit_event::Entity as AuditEvent;
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
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
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
        let result = api.whoami(&req, auth).await;
        assert_whoami_unauthorized(result);
        
        // Query audit database to verify jwt_tampered event was created
        use crate::types::db::audit_event::Entity as AuditEvent;
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


