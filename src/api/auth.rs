use poem_openapi::{payload::Json, OpenApi, Tags, SecurityScheme, auth::Bearer};
use poem::Request;
use crate::services::AuthService;
use crate::types::dto::auth::{
    LoginRequest, TokenResponse, WhoAmIResponse, RefreshRequest, RefreshResponse, 
    LogoutRequest, LogoutResponse, LoginApiResponse, WhoAmIApiResponse, 
    RefreshApiResponse, LogoutApiResponse, ErrorResponse, ChangePasswordRequest,
    ChangePasswordResponse, ChangePasswordApiResponse
};
use crate::api::helpers;
use crate::errors::InternalError;
use std::sync::Arc;

/// Authentication API endpoints
pub struct AuthApi {
    auth_service: Arc<AuthService>
}

impl AuthApi {
    /// Create a new AuthApi with the given AuthService
    pub fn new(
        auth_service: Arc<AuthService>,
    ) -> Self {
        Self { 
            auth_service
        }
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
pub struct BearerAuth(pub Bearer);

/// API tags for authentication endpoints
#[derive(Tags)]
enum AuthTags {
    /// Authentication endpoints
    Authentication,
}

#[OpenApi(prefix_path = "/auth")]
impl AuthApi {
    /// Authenticate with username and password
    /// 
    /// Returns an access token (JWT) and refresh token for subsequent API requests.
    /// Access tokens expire after 15 minutes.
    #[oai(path = "/login", method = "post", tag = "AuthTags::Authentication")]
    async fn login(&self, req: &Request, body: Json<LoginRequest>) -> LoginApiResponse {
        // Manual header extraction because poem-openapi doesn't support Option<BearerAuth>
        let auth = req.header("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|token| Bearer { token: token.to_string() });
        
        // Login doesn't require password change check - extract context directly
        let ctx = helpers::create_request_context(req, auth, &self.auth_service.token_service()).await.into_context();
        
        match self.auth_service
            .login(&ctx, body.username.clone(), body.password.clone())
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
            Err(internal_error) => {
                let auth_error = crate::errors::AuthError::from_internal_error(internal_error);
                LoginApiResponse::Unauthorized(Json(ErrorResponse {
                    error: auth_error.to_string(),
                }))
            }
        }
    }
    
    /// Get current user information
    /// 
    /// Returns the authenticated user's ID and token expiration time.
    #[oai(path = "/whoami", method = "get", tag = "AuthTags::Authentication")]
    async fn whoami(&self, req: &Request, auth: BearerAuth) -> WhoAmIApiResponse {
        // Whoami should remain accessible even when password change is required
        // Extract context directly without checking password_change_required
        let ctx = helpers::create_request_context(req, Some(auth.0), &self.auth_service.token_service()).await.into_context();
        
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
    
    /// Obtain a new access token
    /// 
    /// Use your refresh token to get a new access token when the current one expires.
    #[oai(path = "/refresh", method = "post", tag = "AuthTags::Authentication")]
    async fn refresh(&self, req: &Request, body: Json<RefreshRequest>) -> RefreshApiResponse {
        // Manual header extraction because poem-openapi doesn't support Option<BearerAuth>
        let auth = req.header("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|token| Bearer { token: token.to_string() });
        
        // Refresh should be blocked if password change is required
        let ctx = match helpers::create_request_context(req, auth, &self.auth_service.token_service()).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return RefreshApiResponse::Unauthorized(Json(ErrorResponse {
                    error: auth_error.to_string(),
                }));
            }
        };
        
        match self.auth_service
            .refresh(&ctx, body.refresh_token.clone())
            .await
        {
            Ok(access_token) => {
                RefreshApiResponse::Ok(Json(RefreshResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 900, // 15 minutes in seconds
                }))
            }
            Err(internal_error) => {
                let auth_error = crate::errors::AuthError::from_internal_error(internal_error);
                RefreshApiResponse::Unauthorized(Json(ErrorResponse {
                    error: auth_error.to_string(),
                }))
            }
        }
    }
    
    /// Logout user and revoke tokens
    /// 
    /// Revokes the refresh token, ending the user's authenticated session.
    /// The token cannot be used for future authentication.
    #[oai(path = "/logout", method = "post", tag = "AuthTags::Authentication")]
    async fn logout(&self, req: &Request, body: Json<LogoutRequest>) -> LogoutApiResponse {
        // Manual header extraction because poem-openapi doesn't support Option<BearerAuth>
        let auth = req.header("Authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|token| Bearer { token: token.to_string() });
        
        // Logout doesn't require password change check - extract context directly
        let ctx = helpers::create_request_context(req, auth, &self.auth_service.token_service()).await.into_context();
        
        // Always return 200 to avoid leaking token validity information
        let _ = self.auth_service.logout(&ctx, body.refresh_token.clone()).await;
        
        LogoutApiResponse::Ok(Json(LogoutResponse {
            message: "Logged out successfully".to_string(),
        }))
    }
    
    /// Change user password
    /// 
    /// Changes the authenticated user's password. Requires the current password for verification.
    /// On success, all existing refresh tokens are invalidated and new tokens are issued.
    #[oai(path = "/change-password", method = "post", tag = "AuthTags::Authentication")]
    async fn change_password(&self, req: &Request, auth: BearerAuth, body: Json<ChangePasswordRequest>) -> ChangePasswordApiResponse {
        // Change password should remain accessible even when password change is required
        // Extract context directly without checking password_change_required
        let ctx = helpers::create_request_context(req, Some(auth.0), &self.auth_service.token_service()).await.into_context();
        
        // Check if authenticated
        if !ctx.authenticated {
            return ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
                error: "Unauthenticated".to_string(),
            }));
        }
        
        // Call auth service to change password
        match self.auth_service
            .change_password(&ctx, &body.old_password, &body.new_password)
            .await
        {
            Ok((access_token, refresh_token)) => {
                ChangePasswordApiResponse::Ok(Json(ChangePasswordResponse {
                    message: "Password changed successfully".to_string(),
                    access_token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 900, // 15 minutes in seconds
                }))
            }
            Err(internal_error) => {
                // Check if it's an invalid credentials error (incorrect old password)
                if matches!(internal_error, InternalError::Credential(crate::errors::internal::CredentialError::InvalidCredentials)) {
                    ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
                        error: "Current password is incorrect".to_string(),
                    }))
                } else {
                    // All other errors (validation, etc.) return 400
                    let auth_error = crate::errors::AuthError::from_internal_error(internal_error);
                    ChangePasswordApiResponse::BadRequest(Json(ErrorResponse {
                        error: auth_error.to_string(),
                    }))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poem_openapi::payload::Json;
    use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter};
    use crate::services::{AuthService, TokenService};
    use crate::stores::CredentialStore;
    use crate::test::utils::setup_test_auth_services;

    async fn setup_test_db() -> (DatabaseConnection, DatabaseConnection, Arc<AuthService>, Arc<TokenService>, Arc<CredentialStore>) {
        let (db, audit_db, credential_store, _audit_store, auth_service, token_service) = setup_test_auth_services().await;
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get a valid JWT
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
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
            is_owner: false,
            is_system_admin: false,
            is_role_admin: false,
            app_roles: vec![],
            password_change_required: false,
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Wait a moment to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let result = api.refresh(&req, refresh_request).await;
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Try to refresh with invalid token
        let refresh_request = Json(RefreshRequest {
            refresh_token: "invalid-token-12345".to_string(),
        });
        let result = api.refresh(&req, refresh_request).await;
        assert_refresh_unauthorized(result);
    }

    #[tokio::test]
    async fn test_refresh_with_expired_token_returns_401() {
        let (_db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Add a user
        let user_id = credential_store
            .add_user(&password_validator, "expireduser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Create an expired refresh token
        let expired_token = token_service.generate_refresh_token();
        let token_hash = token_service.hash_refresh_token(&expired_token);
        let expires_at = chrono::Utc::now().timestamp() - 3600; // Expired 1 hour ago
        let jwt_id = "test-jwt-id-1".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        credential_store
            .store_refresh_token_no_txn(&ctx, token_hash, user_id, expires_at, jwt_id)
            .await
            .expect("Failed to store expired token");
        
        // Try to refresh with expired token
        let refresh_request = Json(RefreshRequest {
            refresh_token: expired_token,
        });
        let result = api.refresh(&req, refresh_request).await;
        assert_refresh_unauthorized(result);
    }

    #[tokio::test]
    async fn test_refresh_new_jwt_has_updated_expiration_time() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Wait a moment to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let refresh_response = unwrap_refresh_ok(api.refresh(&req, refresh_request).await);
        
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Use refresh token to get new JWT
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        let refresh_response = unwrap_refresh_ok(api.refresh(&req, refresh_request).await);
        
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get a valid JWT
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let result = api.refresh(&req, refresh_request).await;
        
        // Should return 401 error
        assert_refresh_unauthorized(result);
    }

    #[tokio::test]
    async fn test_logout_revokes_any_refresh_token() {
        let (db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Create a second user
        credential_store
            .add_user(&password_validator, "user2".to_string(), "SecureTest-Pass-234567890".to_string())
            .await
            .expect("Failed to create user2");
        
        // Login as testuser
        let login1_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login1_response = unwrap_login_ok(api.login(&req, login1_request).await);
        
        // Login as user2
        let login2_request = Json(LoginRequest {
            username: "user2".to_string(),
            password: "SecureTest-Pass-234567890".to_string(),
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
        let result = api.refresh(&req, refresh_request).await;
        // Should fail
        assert_refresh_unauthorized(result);
    }

    // ========== Audit Trail Tests ==========

    #[tokio::test]
    async fn test_login_success_creates_audit_trail() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Perform login
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        // IP address is set to "unknown" when not available in request
        assert_eq!(login_event.ip_address, Some("unknown".to_string()));
        
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
        let (db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Verify testuser exists (no longer need user_id since actor is "unknown")
        use crate::types::db::user::{Entity as User, Column as UserColumn};
        use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};
        let _testuser = User::find()
            .filter(UserColumn::Username.eq("testuser"))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("testuser not found");
        
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
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 event: login_failure
        assert_eq!(audit_events.len(), 1, "Expected 1 audit event");
        
        let login_failure = &audit_events[0];
        assert_eq!(login_failure.event_type, "login_failure");
        // Actor is "unknown" for unauthenticated login attempts
        assert_eq!(login_failure.user_id, "unknown");
        // IP address is set to "unknown" when not available in request
        assert_eq!(login_failure.ip_address, Some("unknown".to_string()));
        
        // Verify failure reason and attempted username are in data (for audit forensics)
        let data: serde_json::Value = serde_json::from_str(&login_failure.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["failure_reason"], "invalid_password");
        assert_eq!(data["attempted_username"], "testuser");
    }

    #[tokio::test]
    async fn test_refresh_creates_jwt_issued_audit_trail() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // First, login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let result = api.refresh(&req, refresh_request).await;
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
    async fn test_refresh_with_invalid_token_creates_validation_failure_audit_trail() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Try to refresh with invalid token
        let refresh_request = Json(RefreshRequest {
            refresh_token: "invalid-token-12345".to_string(),
        });
        let result = api.refresh(&req, refresh_request).await;
        assert_refresh_unauthorized(result);
        
        // Query audit database to verify refresh_token_validation_failure event was created
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 1 event: refresh_token_validation_failure
        assert_eq!(audit_events.len(), 1, "Expected 1 audit event");
        
        let validation_failure = &audit_events[0];
        assert_eq!(validation_failure.event_type, "refresh_token_validation_failure");
        assert_eq!(validation_failure.user_id, "unknown");
        assert_eq!(validation_failure.ip_address, Some("unknown".to_string()));
        
        // Verify failure reason and token_hash are in data
        let data: serde_json::Value = serde_json::from_str(&validation_failure.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["failure_reason"], "not_found");
        assert!(data["token_hash"].is_string());
    }

    #[tokio::test]
    async fn test_refresh_with_expired_token_creates_validation_failure_audit_trail() {
        let (_db, audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Add a user
        let user_id = credential_store
            .add_user(&password_validator, "expireduser".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Create an expired refresh token
        let expired_token = token_service.generate_refresh_token();
        let token_hash = token_service.hash_refresh_token(&expired_token);
        let expires_at = chrono::Utc::now().timestamp() - 3600; // Expired 1 hour ago
        let jwt_id = "test-jwt-id-2".to_string();
        let ctx = crate::types::internal::context::RequestContext::new();
        
        credential_store
            .store_refresh_token_no_txn(&ctx, token_hash, user_id, expires_at, jwt_id)
            .await
            .expect("Failed to store expired token");
        
        // Try to refresh with expired token
        let refresh_request = Json(RefreshRequest {
            refresh_token: expired_token,
        });
        let result = api.refresh(&req, refresh_request).await;
        assert_refresh_unauthorized(result);
        
        // Query audit database to verify refresh_token_validation_failure event was created
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 2 events: refresh_token_issued (from store_refresh_token) and refresh_token_validation_failure
        assert_eq!(audit_events.len(), 2, "Expected 2 audit events");
        
        // Find the validation_failure event
        let validation_failure = audit_events
            .iter()
            .find(|e| e.event_type == "refresh_token_validation_failure")
            .expect("refresh_token_validation_failure event not found");
        assert_eq!(validation_failure.user_id, "unknown");
        
        // Verify failure reason is expired
        let data: serde_json::Value = serde_json::from_str(&validation_failure.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["failure_reason"], "expired");
    }

    #[tokio::test]
    async fn test_logout_creates_refresh_token_revoked_audit_trail() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // First, login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
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
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
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
            is_owner: false,
            is_system_admin: false,
            is_role_admin: false,
            app_roles: vec![],
            password_change_required: false,
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
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
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
            is_owner: false,
            is_system_admin: false,
            is_role_admin: false,
            app_roles: vec![],
            password_change_required: false,
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

    #[tokio::test]
    async fn test_create_request_context_sets_actor_id_from_jwt() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Login to get a valid JWT
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Create Bearer token with the JWT
        let bearer = Bearer { token: login_response.access_token.clone() };
        
        // Create request context with authentication using helpers
        let ctx = helpers::create_request_context(&req, Some(bearer), &auth_service.token_service()).await.into_context();
        
        // Verify context has API source
        assert_eq!(ctx.source, crate::types::internal::context::RequestSource::API);
        
        // Verify actor_id is set from JWT claims (sub field)
        assert!(ctx.authenticated);
        let claims = ctx.claims.unwrap();
        assert_eq!(ctx.actor_id, claims.sub);
        assert!(!ctx.actor_id.is_empty());
        assert_ne!(ctx.actor_id, "unknown"); // Should not be the default value
    }

    #[tokio::test]
    async fn test_create_request_context_without_auth_has_default_actor_id() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let _api = AuthApi::new(auth_service.clone());
        
        // Create a mock request for testing
        let req = poem::Request::builder().finish();
        
        // Create request context without authentication using helpers
        let ctx = helpers::create_request_context(&req, None, &auth_service.token_service()).await.into_context();
        
        // Verify context has API source
        assert_eq!(ctx.source, crate::types::internal::context::RequestSource::API);
        
        // Verify actor_id is the default "unknown" value
        assert!(!ctx.authenticated);
        assert_eq!(ctx.actor_id, "unknown");
    }

    #[tokio::test]
    async fn test_login_with_optional_jwt_captures_actor_id() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // First login to get a JWT
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let first_login = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Now login again WITH the JWT in the Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", first_login.access_token))
            .finish();
        
        let second_login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        
        // This should succeed and the context should have captured the JWT
        let second_login = api.login(&req_with_auth, second_login_request).await;
        
        // Verify login succeeded
        match second_login {
            LoginApiResponse::Ok(_) => {
                // Success - the optional JWT was captured and used for better audit logging
            }
            LoginApiResponse::Unauthorized(_) => {
                panic!("Login should succeed even with optional JWT");
            }
        }
    }

    #[tokio::test]
    async fn test_refresh_with_optional_jwt_captures_actor_id() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login to get tokens
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Refresh WITH the JWT in the Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        
        // This should succeed and the context should have captured the JWT
        let refresh_response = api.refresh(&req_with_auth, refresh_request).await;
        
        // Verify refresh succeeded
        match refresh_response {
            RefreshApiResponse::Ok(_) => {
                // Success - the optional JWT was captured and used for better audit logging
            }
            RefreshApiResponse::Unauthorized(_) => {
                panic!("Refresh should succeed even with optional JWT");
            }
        }
    }

    #[tokio::test]
    async fn test_login_without_jwt_still_works() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login without any JWT (normal case)
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        
        let login_response = api.login(&req, login_request).await;
        
        // Verify login succeeded
        match login_response {
            LoginApiResponse::Ok(_) => {
                // Success - login works without JWT as expected
            }
            LoginApiResponse::Unauthorized(_) => {
                panic!("Login should succeed without JWT");
            }
        }
    }

    // ========== Task 9.1: Login endpoint with optional auth audit tests ==========

    #[tokio::test]
    async fn test_login_with_auth_header_logs_actor_from_jwt() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // First login to get a JWT
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let first_login = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Count audit events from first login
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Now login again WITH the JWT in the Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", first_login.access_token))
            .finish();
        
        let second_login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        
        let second_login = unwrap_login_ok(api.login(&req_with_auth, second_login_request).await);
        
        // Decode the JWT to get the actor_id (sub claim)
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let first_jwt_claims = decode::<Claims>(
            &first_login.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        let second_jwt_claims = decode::<Claims>(
            &second_login.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Query audit database to get only the new events from second login
        let all_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Get only the events from the second login (skip the first 3)
        let audit_events: Vec<_> = all_events.iter().skip(events_before).collect();
        
        // Should have 3 new events: login_success, jwt_issued, refresh_token_issued
        assert_eq!(audit_events.len(), 3, "Expected 3 new audit events from second login");
        
        // Verify login_success event has actor_id from JWT
        let login_event = audit_events.iter()
            .find(|e| e.event_type == "login_success")
            .expect("login_success event not found");
        assert_eq!(login_event.user_id, first_jwt_claims.sub, "Actor should be from JWT");
        assert_eq!(login_event.jwt_id, first_jwt_claims.jti.clone(), "JWT ID should be from actor's JWT");
        
        // Verify target_user_id is in event details
        let data: serde_json::Value = serde_json::from_str(&login_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["target_user_id"], second_jwt_claims.sub, "Target user should be the logged-in user");
        
        // Verify jwt_issued event has actor_id from JWT
        let jwt_event = audit_events.iter()
            .find(|e| e.event_type == "jwt_issued")
            .expect("jwt_issued event not found");
        assert_eq!(jwt_event.user_id, first_jwt_claims.sub, "Actor should be from JWT");
        // jwt_id field contains the NEW JWT being issued (for easier querying)
        assert_eq!(jwt_event.jwt_id.as_ref().unwrap(), &second_jwt_claims.jti.clone().unwrap(), "JWT ID should be the new JWT");
        
        // Verify target_user_id and actor_jwt_id are in jwt_issued event details
        let jwt_data: serde_json::Value = serde_json::from_str(&jwt_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(jwt_data["target_user_id"], second_jwt_claims.sub, "Target user should be the JWT subject");
        assert_eq!(jwt_data["actor_jwt_id"], first_jwt_claims.jti.clone().unwrap(), "Actor JWT ID should be in data");
        
        // Verify refresh_token_issued event has actor_id from JWT
        let refresh_event = audit_events.iter()
            .find(|e| e.event_type == "refresh_token_issued")
            .expect("refresh_token_issued event not found");
        assert_eq!(refresh_event.user_id, first_jwt_claims.sub, "Actor should be from JWT");
        // jwt_id field contains the NEW JWT being issued (for easier querying)
        assert_eq!(refresh_event.jwt_id.as_ref().unwrap(), &second_jwt_claims.jti.unwrap(), "JWT ID should be the new JWT");
        
        // Verify target_user_id and actor_jwt_id are in refresh_token_issued event details
        let refresh_data: serde_json::Value = serde_json::from_str(&refresh_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(refresh_data["target_user_id"], second_jwt_claims.sub, "Target user should be the token owner");
        assert_eq!(refresh_data["actor_jwt_id"], first_jwt_claims.jti.unwrap(), "Actor JWT ID should be in data");
    }

    #[tokio::test]
    async fn test_login_without_auth_header_logs_unknown_actor() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login without any JWT (normal case)
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Decode the JWT to get the target_user_id (sub claim)
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let jwt_claims = decode::<Claims>(
            &login_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Query audit database to verify events have actor_id = "unknown"
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let audit_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Should have 3 events: login_success, jwt_issued, refresh_token_issued
        assert_eq!(audit_events.len(), 3, "Expected 3 audit events");
        
        // Verify login_success event has actor_id = "unknown"
        let login_event = audit_events.iter()
            .find(|e| e.event_type == "login_success")
            .expect("login_success event not found");
        assert_eq!(login_event.user_id, "unknown", "Actor should be unknown for unauthenticated login");
        
        // Verify target_user_id is in event details
        let data: serde_json::Value = serde_json::from_str(&login_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["target_user_id"], jwt_claims.sub, "Target user should be the logged-in user");
        // actor_jwt_id should not be present for unauthenticated requests
        assert!(data.get("actor_jwt_id").is_none(), "Actor JWT ID should not be present for unauthenticated login");
        
        // Verify jwt_issued event has actor_id = "unknown"
        let jwt_event = audit_events.iter()
            .find(|e| e.event_type == "jwt_issued")
            .expect("jwt_issued event not found");
        assert_eq!(jwt_event.user_id, "unknown", "Actor should be unknown for unauthenticated login");
        // jwt_id field contains the NEW JWT being issued (for easier querying)
        assert_eq!(jwt_event.jwt_id.as_ref().unwrap(), &jwt_claims.jti.clone().unwrap(), "JWT ID should be the new JWT");
        
        // Verify target_user_id is in jwt_issued event details
        let jwt_data: serde_json::Value = serde_json::from_str(&jwt_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(jwt_data["target_user_id"], jwt_claims.sub, "Target user should be the JWT subject");
        // actor_jwt_id should not be present for unauthenticated requests
        assert!(jwt_data.get("actor_jwt_id").is_none(), "Actor JWT ID should not be present for unauthenticated login");
        
        // Verify refresh_token_issued event has actor_id = "unknown"
        let refresh_event = audit_events.iter()
            .find(|e| e.event_type == "refresh_token_issued")
            .expect("refresh_token_issued event not found");
        assert_eq!(refresh_event.user_id, "unknown", "Actor should be unknown for unauthenticated login");
        // jwt_id field contains the NEW JWT being issued (for easier querying)
        assert_eq!(refresh_event.jwt_id.as_ref().unwrap(), &jwt_claims.jti.unwrap(), "JWT ID should be the new JWT");
        
        // Verify target_user_id is in refresh_token_issued event details
        let refresh_data: serde_json::Value = serde_json::from_str(&refresh_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(refresh_data["target_user_id"], jwt_claims.sub, "Target user should be the token owner");
        // actor_jwt_id should not be present for unauthenticated requests
        assert!(refresh_data.get("actor_jwt_id").is_none(), "Actor JWT ID should not be present for unauthenticated login");
    }

    #[tokio::test]
    async fn test_refresh_without_jwt_still_works() {
        let (_db, _audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login to get tokens
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Refresh without JWT (normal case)
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        
        let refresh_response = api.refresh(&req, refresh_request).await;
        
        // Verify refresh succeeded
        match refresh_response {
            RefreshApiResponse::Ok(_) => {
                // Success - refresh works without JWT as expected
            }
            RefreshApiResponse::Unauthorized(_) => {
                panic!("Refresh should succeed without JWT");
            }
        }
    }

    // ========== Task 9.2: Refresh endpoint with optional auth audit tests ==========

    #[tokio::test]
    async fn test_refresh_with_auth_header_logs_actor_from_jwt() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login to get tokens
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Count audit events from login
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Refresh WITH the JWT in the Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        
        let refresh_response = unwrap_refresh_ok(api.refresh(&req_with_auth, refresh_request).await);
        
        // Decode the JWTs to get actor and target user IDs
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let actor_claims = decode::<Claims>(
            &login_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        let new_jwt_claims = decode::<Claims>(
            &refresh_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Query audit database to get only the new events from refresh
        let all_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Get only the events from the refresh (skip the login events)
        let audit_events: Vec<_> = all_events.iter().skip(events_before).collect();
        
        // Should have 1 new event: jwt_issued
        assert_eq!(audit_events.len(), 1, "Expected 1 new audit event from refresh");
        
        // Verify jwt_issued event has actor_id from JWT
        let jwt_event = audit_events[0];
        assert_eq!(jwt_event.event_type, "jwt_issued");
        assert_eq!(jwt_event.user_id, actor_claims.sub, "Actor should be from JWT");
        // jwt_id field contains the NEW JWT being issued (for easier querying)
        assert_eq!(jwt_event.jwt_id.as_ref().unwrap(), &new_jwt_claims.jti.unwrap(), "JWT ID should be the new JWT");
        
        // Verify target_user_id and actor_jwt_id are in event details
        let data: serde_json::Value = serde_json::from_str(&jwt_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["target_user_id"], new_jwt_claims.sub, "Target user should be the JWT subject");
        assert_eq!(data["actor_jwt_id"], actor_claims.jti.clone().unwrap(), "Actor JWT ID should be in data");
    }

    #[tokio::test]
    async fn test_refresh_without_auth_header_logs_unknown_actor() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login to get tokens
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Count audit events from login
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Refresh WITHOUT the JWT in the Authorization header
        let req_without_auth = poem::Request::builder().finish();
        
        let refresh_request = Json(RefreshRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        
        let refresh_response = unwrap_refresh_ok(api.refresh(&req_without_auth, refresh_request).await);
        
        // Decode the new JWT to get the target user ID
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let new_jwt_claims = decode::<Claims>(
            &refresh_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Query audit database to get only the new events from refresh
        let all_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Get only the events from the refresh (skip the login events)
        let audit_events: Vec<_> = all_events.iter().skip(events_before).collect();
        
        // Should have 1 new event: jwt_issued
        assert_eq!(audit_events.len(), 1, "Expected 1 new audit event from refresh");
        
        // Verify jwt_issued event has actor_id = "unknown"
        let jwt_event = audit_events[0];
        assert_eq!(jwt_event.event_type, "jwt_issued");
        assert_eq!(jwt_event.user_id, "unknown", "Actor should be unknown for unauthenticated refresh");
        // jwt_id field contains the NEW JWT being issued (for easier querying)
        assert_eq!(jwt_event.jwt_id.as_ref().unwrap(), &new_jwt_claims.jti.unwrap(), "JWT ID should be the new JWT");
        
        // Verify target_user_id is in event details
        let data: serde_json::Value = serde_json::from_str(&jwt_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["target_user_id"], new_jwt_claims.sub, "Target user should be the JWT subject");
        // actor_jwt_id should not be present for unauthenticated requests
        assert!(data.get("actor_jwt_id").is_none(), "Actor JWT ID should not be present for unauthenticated refresh");
    }

    // ========== Task 9.3: Logout endpoint with optional auth audit tests ==========

    #[tokio::test]
    async fn test_logout_with_auth_header_logs_actor_from_jwt() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login to get tokens
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Decode the JWT to get actor_id and target_user_id
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let jwt_claims = decode::<Claims>(
            &login_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Count audit events from login
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Logout WITH the JWT in the Authorization header
        let req_with_auth = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", login_response.access_token))
            .finish();
        
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        
        unwrap_logout_ok(api.logout(&req_with_auth, logout_request).await);
        
        // Query audit database to get only the new events from logout
        let all_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Get only the events from the logout (skip the login events)
        let audit_events: Vec<_> = all_events.iter().skip(events_before).collect();
        
        // Should have 1 new event: refresh_token_revoked
        assert_eq!(audit_events.len(), 1, "Expected 1 new audit event from logout");
        
        // Verify refresh_token_revoked event has actor_id from JWT
        let revoke_event = audit_events[0];
        assert_eq!(revoke_event.event_type, "refresh_token_revoked");
        assert_eq!(revoke_event.user_id, jwt_claims.sub, "Actor should be from JWT");
        assert_eq!(revoke_event.jwt_id, jwt_claims.jti, "JWT ID should be from actor's JWT");
        
        // Verify target_user_id is in event details
        let data: serde_json::Value = serde_json::from_str(&revoke_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["target_user_id"], jwt_claims.sub, "Target user should be the token owner");
    }

    #[tokio::test]
    async fn test_logout_without_auth_header_logs_unknown_actor() {
        let (_db, audit_db, auth_service, _token_service, _credential_store) = setup_test_db().await;
        let api = AuthApi::new(auth_service);
        
        // Login to get tokens
        let req = poem::Request::builder().finish();
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "TestSecure-Pass-12345-UUID".to_string(),
        });
        let login_response = unwrap_login_ok(api.login(&req, login_request).await);
        
        // Decode the JWT to get target_user_id
        use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};
        use crate::types::internal::auth::Claims;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        
        let jwt_claims = decode::<Claims>(
            &login_response.access_token,
            &DecodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
            &validation,
        ).unwrap().claims;
        
        // Count audit events from login
        use crate::types::db::audit_event::Entity as AuditEvent;
        use sea_orm::EntityTrait;
        
        let events_before = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events")
            .len();
        
        // Logout WITHOUT the JWT in the Authorization header
        let req_without_auth = poem::Request::builder().finish();
        
        let logout_request = Json(LogoutRequest {
            refresh_token: login_response.refresh_token.clone(),
        });
        
        unwrap_logout_ok(api.logout(&req_without_auth, logout_request).await);
        
        // Query audit database to get only the new events from logout
        let all_events = AuditEvent::find()
            .all(&audit_db)
            .await
            .expect("Failed to query audit events");
        
        // Get only the events from the logout (skip the login events)
        let audit_events: Vec<_> = all_events.iter().skip(events_before).collect();
        
        // Should have 1 new event: refresh_token_revoked
        assert_eq!(audit_events.len(), 1, "Expected 1 new audit event from logout");
        
        // Verify refresh_token_revoked event has actor_id = "unknown"
        let revoke_event = audit_events[0];
        assert_eq!(revoke_event.event_type, "refresh_token_revoked");
        assert_eq!(revoke_event.user_id, "unknown", "Actor should be unknown for unauthenticated logout");
        assert_eq!(revoke_event.jwt_id, None, "JWT ID should be None for unauthenticated logout");
        
        // Verify target_user_id is in event details
        let data: serde_json::Value = serde_json::from_str(&revoke_event.data)
            .expect("Failed to parse audit data");
        assert_eq!(data["target_user_id"], jwt_claims.sub, "Target user should be the token owner");
    }

    // ========== Password Change Requirement Tests ==========

    #[tokio::test]
    async fn test_refresh_blocked_when_password_change_required() {
        let (db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a user with password_change_required=true
        let user_id = credential_store
            .add_user(&password_validator, "pwchange_user".to_string(), "SecureTest-Pass-123456789".to_string())
            .await
            .expect("Failed to add user");
        
        // Manually set password_change_required=true
        use crate::types::db::user::{Entity as User, ActiveModel as UserActiveModel, Column as UserColumn};
        use sea_orm::{EntityTrait, Set, QueryFilter, ColumnTrait};
        let user = User::find()
            .filter(UserColumn::Id.eq(&user_id))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("User not found");
        
        let mut user_active: UserActiveModel = user.into();
        user_active.password_change_required = Set(true);
        User::update(user_active)
            .exec(&db)
            .await
            .expect("Failed to update user");
        
        // Generate JWT with password_change_required=true
        let ctx = crate::types::internal::context::RequestContext::new();
        let (jwt, _jwt_id) = token_service.generate_jwt(
            &ctx,
            &uuid::Uuid::parse_str(&user_id).unwrap(),
            false,
            false,
            false,
            vec![],
            true, // password_change_required=true
        ).await.unwrap();
        
        // Generate and store a refresh token
        let refresh_token = token_service.generate_refresh_token();
        let token_hash = token_service.hash_refresh_token(&refresh_token);
        let expires_at = token_service.get_refresh_expiration();
        credential_store.store_refresh_token_no_txn(
            &ctx,
            token_hash,
            user_id.clone(),
            expires_at,
            "test-jwt-id".to_string(),
        ).await.expect("Failed to store refresh token");
        
        // Try to refresh with password_change_required=true
        // Provide the JWT in the Authorization header so the endpoint can check the flag
        let req = poem::Request::builder()
            .header("Authorization", format!("Bearer {}", jwt))
            .finish();
        let refresh_request = Json(RefreshRequest {
            refresh_token: refresh_token.clone(),
        });
        
        let result = api.refresh(&req, refresh_request).await;
        
        // Should be rejected with Unauthorized (403 mapped to 401 in this response type)
        match result {
            RefreshApiResponse::Unauthorized(json) => {
                assert!(json.error.contains("Password change required") || json.error.contains("password"));
            }
            RefreshApiResponse::Ok(_) => {
                panic!("Refresh should be blocked when password_change_required=true");
            }
        }
    }

    #[tokio::test]
    async fn test_whoami_allowed_when_password_change_required() {
        let (_db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a user with password_change_required=true
        let user_id = credential_store
            .add_user(&password_validator, "pwchange_user2".to_string(), "SecureTest-Pass-234567890".to_string())
            .await
            .expect("Failed to add user");
        
        // Generate JWT with password_change_required=true
        let ctx = crate::types::internal::context::RequestContext::new();
        let (jwt, _jwt_id) = token_service.generate_jwt(
            &ctx,
            &uuid::Uuid::parse_str(&user_id).unwrap(),
            false,
            false,
            false,
            vec![],
            true, // password_change_required=true
        ).await.unwrap();
        
        // Try to call whoami with password_change_required=true
        let req = poem::Request::builder().finish();
        let auth = BearerAuth(Bearer { token: jwt });
        
        let result = api.whoami(&req, auth).await;
        
        // Should be allowed
        match result {
            WhoAmIApiResponse::Ok(json) => {
                assert_eq!(json.user_id, user_id);
            }
            WhoAmIApiResponse::Unauthorized(_) => {
                panic!("Whoami should be allowed when password_change_required=true");
            }
        }
    }

    #[tokio::test]
    async fn test_change_password_allowed_when_password_change_required() {
        let (db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a user with password_change_required=true
        let user_id = credential_store
            .add_user(&password_validator, "pwchange_user3".to_string(), "SecureTest-Pass-345678901".to_string())
            .await
            .expect("Failed to add user");
        
        // Manually set password_change_required=true
        use crate::types::db::user::{Entity as User, ActiveModel as UserActiveModel, Column as UserColumn};
        use sea_orm::{EntityTrait, Set, QueryFilter, ColumnTrait};
        let user = User::find()
            .filter(UserColumn::Id.eq(&user_id))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("User not found");
        
        let mut user_active: UserActiveModel = user.into();
        user_active.password_change_required = Set(true);
        User::update(user_active)
            .exec(&db)
            .await
            .expect("Failed to update user");
        
        // Generate JWT with password_change_required=true
        let ctx = crate::types::internal::context::RequestContext::new();
        let (jwt, _jwt_id) = token_service.generate_jwt(
            &ctx,
            &uuid::Uuid::parse_str(&user_id).unwrap(),
            false,
            false,
            false,
            vec![],
            true, // password_change_required=true
        ).await.unwrap();
        
        // Try to change password with password_change_required=true
        let req = poem::Request::builder().finish();
        let auth = BearerAuth(Bearer { token: jwt });
        let change_request = Json(ChangePasswordRequest {
            old_password: "SecureTest-Pass-345678901".to_string(),
            new_password: "NewSecureTest-Pass-456789012".to_string(),
        });
        
        let result = api.change_password(&req, auth, change_request).await;
        
        // Should be allowed and succeed
        match result {
            ChangePasswordApiResponse::Ok(json) => {
                assert_eq!(json.message, "Password changed successfully");
                assert!(!json.access_token.is_empty());
                assert!(!json.refresh_token.is_empty());
            }
            ChangePasswordApiResponse::Unauthorized(_) => {
                panic!("Change password should be allowed when password_change_required=true");
            }
            ChangePasswordApiResponse::BadRequest(_) => {
                panic!("Change password should succeed with valid passwords");
            }
        }
    }

    #[tokio::test]
    async fn test_refresh_allowed_after_password_change() {
        let (db, _audit_db, auth_service, token_service, credential_store) = setup_test_db().await;
        let password_validator = crate::test::utils::setup_test_password_validator().await;
        let api = AuthApi::new(auth_service.clone());
        
        // Create a user with password_change_required=true
        let user_id = credential_store
            .add_user(&password_validator, "pwchange_user4".to_string(), "SecureTest-Pass-456789012".to_string())
            .await
            .expect("Failed to add user");
        
        // Manually set password_change_required=true
        use crate::types::db::user::{Entity as User, ActiveModel as UserActiveModel, Column as UserColumn};
        use sea_orm::{EntityTrait, Set, QueryFilter, ColumnTrait};
        let user = User::find()
            .filter(UserColumn::Id.eq(&user_id))
            .one(&db)
            .await
            .expect("Failed to query user")
            .expect("User not found");
        
        let mut user_active: UserActiveModel = user.into();
        user_active.password_change_required = Set(true);
        User::update(user_active)
            .exec(&db)
            .await
            .expect("Failed to update user");
        
        // Generate JWT with password_change_required=true
        let ctx = crate::types::internal::context::RequestContext::new();
        let (jwt, _jwt_id) = token_service.generate_jwt(
            &ctx,
            &uuid::Uuid::parse_str(&user_id).unwrap(),
            false,
            false,
            false,
            vec![],
            true, // password_change_required=true
        ).await.unwrap();
        
        // Change password (this should clear password_change_required)
        let req = poem::Request::builder().finish();
        let auth = BearerAuth(Bearer { token: jwt });
        let change_request = Json(ChangePasswordRequest {
            old_password: "SecureTest-Pass-456789012".to_string(),
            new_password: "NewSecureTest-Pass-567890123".to_string(),
        });
        
        let change_result = api.change_password(&req, auth, change_request).await;
        let new_tokens = match change_result {
            ChangePasswordApiResponse::Ok(json) => json,
            _ => panic!("Password change should succeed"),
        };
        
        // Now try to refresh with the new tokens (password_change_required should be false)
        let refresh_request = Json(RefreshRequest {
            refresh_token: new_tokens.refresh_token.clone(),
        });
        
        let refresh_result = api.refresh(&req, refresh_request).await;
        
        // Should be allowed now
        match refresh_result {
            RefreshApiResponse::Ok(json) => {
                assert!(!json.access_token.is_empty());
            }
            RefreshApiResponse::Unauthorized(_) => {
                panic!("Refresh should be allowed after password change");
            }
        }
    }
}


