use poem_openapi::{payload::Json, OpenApi, Tags};
use super::{AuthError, LoginRequest, TokenResponse, CredentialStore};
use std::sync::Arc;

/// Authentication API endpoints
pub struct AuthApi {
    credential_store: Arc<CredentialStore>,
}

impl AuthApi {
    /// Create a new AuthApi with the given CredentialStore
    pub fn new(credential_store: Arc<CredentialStore>) -> Self {
        Self { credential_store }
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
        let _user_id = self.credential_store.verify_credentials(&body.username, &body.password).await?;
        
        // Return placeholder tokens (will be replaced with real tokens in Phase 3)
        Ok(Json(TokenResponse {
            access_token: "placeholder-jwt".to_string(),
            refresh_token: "placeholder-rt".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 900, // 15 minutes in seconds
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poem_openapi::payload::Json;
    use sea_orm::{Database, DatabaseConnection};
    use migration::{Migrator, MigratorTrait};

    async fn setup_test_db() -> (DatabaseConnection, Arc<CredentialStore>) {
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
        
        // Add test user
        credential_store
            .add_user("testuser".to_string(), "testpass".to_string())
            .await
            .expect("Failed to create test user");
        
        (db, credential_store)
    }

    #[tokio::test]
    async fn test_login_with_valid_credentials() {
        let (_db, credential_store) = setup_test_db().await;
        let api = AuthApi::new(credential_store);
        
        let request = Json(LoginRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let result = api.login(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.access_token, "placeholder-jwt");
        assert_eq!(response.refresh_token, "placeholder-rt");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 900);
    }

    #[tokio::test]
    async fn test_login_with_invalid_credentials() {
        let (_db, credential_store) = setup_test_db().await;
        let api = AuthApi::new(credential_store);
        
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
        let (_db, credential_store) = setup_test_db().await;
        let api = AuthApi::new(credential_store);
        
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
        let (_db, credential_store) = setup_test_db().await;
        let api = AuthApi::new(credential_store);
        
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
}
