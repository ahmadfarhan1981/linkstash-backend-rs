use poem_openapi::{payload::Json, OpenApi, Tags};
use poem::http::HeaderMap;
use crate::stores::CredentialStore;
use crate::services::TokenService;
use crate::types::dto::auth::{LoginRequest, TokenResponse, WhoAmIResponse, RefreshRequest, RefreshResponse};
use crate::errors::auth::AuthError;
use std::sync::Arc;

/// Authentication API endpoints
pub struct AuthApi {
    credential_store: Arc<CredentialStore>,
    token_manager: Arc<TokenService>,
}

impl AuthApi {
    /// Create a new AuthApi with the given CredentialStore and TokenService
    pub fn new(credential_store: Arc<CredentialStore>, token_manager: Arc<TokenService>) -> Self {
        Self { 
            credential_store,
            token_manager,
        }
    }
}

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
    async fn login(&self, body: Json<LoginRequest>) -> Result<Json<TokenResponse>, AuthError> {
        // Verify credentials using database
        let user_id_str = self.credential_store.verify_credentials(&body.username, &body.password).await?;
        
        // Parse user_id string to UUID
        let user_id = uuid::Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        // Generate real JWT using user_id from database
        let access_token = self.token_manager.generate_jwt(&user_id)?;
        
        // Generate refresh token
        let refresh_token = self.token_manager.generate_refresh_token();
        
        // Hash and store refresh token
        let token_hash = self.token_manager.hash_refresh_token(&refresh_token);
        let expires_at = self.token_manager.get_refresh_expiration();
        self.credential_store.store_refresh_token(token_hash, user_id_str, expires_at).await?;
        
        // Return real tokens
        Ok(Json(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 900, // 15 minutes in seconds
        }))
    }
    
    /// Verify JWT and return user information
    #[oai(path = "/whoami", method = "get", tag = "AuthTags::Authentication")]
    async fn whoami(&self, headers: &HeaderMap) -> Result<Json<WhoAmIResponse>, AuthError> {
        // Extract Authorization header
        let auth_header = headers
            .get("authorization")
            .ok_or_else(|| AuthError::missing_auth_header())?
            .to_str()
            .map_err(|_| AuthError::invalid_auth_header())?;
        
        // Parse Bearer token
        if !auth_header.starts_with("Bearer ") {
            return Err(AuthError::invalid_auth_header());
        }
        
        let token = &auth_header[7..]; // Skip "Bearer "
        
        // Validate JWT
        let claims = self.token_manager.validate_jwt(token)?;
        
        // Return user info
        Ok(Json(WhoAmIResponse {
            user_id: claims.sub,
            expires_at: claims.exp,
        }))
    }
    
    /// Refresh access token using a refresh token
    #[oai(path = "/refresh", method = "post", tag = "AuthTags::Authentication")]
    async fn refresh(&self, body: Json<RefreshRequest>) -> Result<Json<RefreshResponse>, AuthError> {
        // Hash the refresh token
        let token_hash = self.token_manager.hash_refresh_token(&body.refresh_token);
        
        // Validate refresh token and get user_id
        let user_id_str = self.credential_store.validate_refresh_token(&token_hash).await?;
        
        // Parse user_id string to UUID
        let user_id = uuid::Uuid::parse_str(&user_id_str)
            .map_err(|e| AuthError::internal_error(format!("Invalid user_id format: {}", e)))?;
        
        // Generate new JWT
        let access_token = self.token_manager.generate_jwt(&user_id)?;
        
        // Return new JWT (keep same refresh token)
        Ok(Json(RefreshResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 900, // 15 minutes in seconds
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poem_openapi::payload::Json;
    use sea_orm::{Database, DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter};
    use migration::{Migrator, MigratorTrait};

    async fn setup_test_db() -> (DatabaseConnection, Arc<CredentialStore>, Arc<TokenService>) {
        // Create in-memory SQLite database for testing
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        // Run migrations
        Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations");
        
        // Create credential store
        let credential_store = Arc::new(CredentialStore::new(db.clone()));
        
        // Create token manager with test secret
        let token_manager = Arc::new(TokenService::new("test-secret-key-minimum-32-characters-long".to_string()));
        
        // Add test user
        credential_store
            .add_user("testuser".to_string(), "testpass".to_string())
            .await
            .expect("Failed to create test user");
        
        (db, credential_store, token_manager)
    }

    #[tokio::test]
    async fn test_login_with_valid_credentials() {
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(request).await;
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        let request = Json(LoginRequest {
            username: "wronguser".to_string(),
            password: "wrongpass".to_string(),
        });

        let result = api.login(request).await;
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(request).await;
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        let request = Json(LoginRequest {
            username: "nonexistent".to_string(),
            password: "somepass".to_string(),
        });

        let result = api.login(request).await;
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(request).await;
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store.clone(), token_manager.clone());
        
        // Login to get a valid JWT
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(login_request).await.unwrap();
        
        // Create headers with the JWT
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", login_response.access_token).parse().unwrap(),
        );
        
        // Call whoami
        let result = api.whoami(&headers).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.user_id.is_empty());
        assert!(response.expires_at > 0);
    }

    #[tokio::test]
    async fn test_whoami_without_authorization_header_returns_401() {
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        // Create empty headers
        let headers = HeaderMap::new();
        
        // Call whoami without auth header
        let result = api.whoami(&headers).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::MissingAuthHeader(_)) => {
                // Expected error type
            }
            _ => panic!("Expected MissingAuthHeader error"),
        }
    }

    #[tokio::test]
    async fn test_whoami_with_invalid_jwt_returns_401() {
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        // Create headers with invalid JWT
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer invalid-jwt-token".parse().unwrap(),
        );
        
        // Call whoami with invalid JWT
        let result = api.whoami(&headers).await;
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        // Create an expired JWT manually
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
        use chrono::Utc;
        use crate::types::internal::auth::Claims;
        
        let now = Utc::now().timestamp();
        let expired_claims = Claims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200, // Issued 2 hours ago
        };
        
        let expired_token = encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret("test-secret-key-minimum-32-characters-long".as_bytes()),
        ).unwrap();
        
        // Create headers with expired JWT
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", expired_token).parse().unwrap(),
        );
        
        // Call whoami with expired JWT
        let result = api.whoami(&headers).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::ExpiredToken(_)) => {
                // Expected error type
            }
            _ => panic!("Expected ExpiredToken error"),
        }
    }

    #[tokio::test]
    async fn test_whoami_with_malformed_authorization_header_returns_401() {
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        // Create headers with malformed auth header (missing "Bearer ")
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "just-a-token-without-bearer".parse().unwrap(),
        );
        
        // Call whoami with malformed header
        let result = api.whoami(&headers).await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidAuthHeader(_)) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidAuthHeader error"),
        }
    }

    #[tokio::test]
    async fn test_login_refresh_token_is_not_placeholder() {
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Verify refresh token is not placeholder
        assert_ne!(response.refresh_token, "placeholder-rt");
        
        // Verify it's a base64-encoded string (should be 44 characters for 32 bytes)
        assert_eq!(response.refresh_token.len(), 44);
    }

    #[tokio::test]
    async fn test_login_stores_refresh_token_in_database() {
        let (db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager.clone());
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        
        // Hash the returned refresh token
        let token_hash = token_manager.hash_refresh_token(&response.refresh_token);
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(login_request).await.unwrap();
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager);
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store.clone(), token_manager.clone());
        
        // Add a user
        let user_id = credential_store
            .add_user("expireduser".to_string(), "password".to_string())
            .await
            .expect("Failed to add user");
        
        // Create an expired refresh token
        let expired_token = token_manager.generate_refresh_token();
        let token_hash = token_manager.hash_refresh_token(&expired_token);
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager.clone());
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(login_request).await.unwrap();
        
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
        let (_db, credential_store, token_manager) = setup_test_db().await;
        let api = AuthApi::new(credential_store, token_manager.clone());
        
        // Login to get tokens
        let login_request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });
        let login_response = api.login(login_request).await.unwrap();
        
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
}

