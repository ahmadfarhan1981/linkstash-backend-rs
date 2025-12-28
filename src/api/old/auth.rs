use poem_openapi::auth::BearerAuthorization;
use poem_openapi::{payload::Json, OpenApi, Tags, SecurityScheme, auth::Bearer};
use poem::Request;
use crate::coordinators::AuthCoordinator;
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
    auth_coordinator: Arc<AuthCoordinator>
}

impl AuthApi {
    /// Create a new AuthApi with the given AuthCoordinator
    pub fn new(
        auth_coordinator: Arc<AuthCoordinator>,
    ) -> Self {
        Self { 
            auth_coordinator
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
    #[oai(path = "/login2", method = "post", tag = "AuthTags::Authentication")]
    async fn login2(&self, req: &Request, body: Json<LoginRequest>) -> LoginApiResponse {
        let auth = match  Bearer::from_request(req){
            Ok(bearer) => Some(bearer),
            Err(_) => None,
        };

        LoginApiResponse::Unauthorized(Json(ErrorResponse { error: "Unauthrorizd".to_string() }))

    }


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
        let ctx = helpers::create_request_context(req, auth, &self.auth_coordinator.token_provider()).await.into_context();
        
        match self.auth_coordinator
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
        let ctx = helpers::create_request_context(req, Some(auth.0), &self.auth_coordinator.token_provider()).await.into_context();
        
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
        let ctx = match helpers::create_request_context(req, auth, &self.auth_coordinator.token_provider()).await.into_result() {
            Ok(ctx) => ctx,
            Err(auth_error) => {
                return RefreshApiResponse::Unauthorized(Json(ErrorResponse {
                    error: auth_error.to_string(),
                }));
            }
        };
        
        match self.auth_coordinator
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
        let ctx = helpers::create_request_context(req, auth, &self.auth_coordinator.token_provider()).await.into_context();
        
        // Always return 200 to avoid leaking token validity information
        let _ = self.auth_coordinator.logout(&ctx, body.refresh_token.clone()).await;
        
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
        let ctx = helpers::create_request_context(req, Some(auth.0), &self.auth_coordinator.token_provider()).await.into_context();
        
        // Check if authenticated
        if !ctx.authenticated {
            return ChangePasswordApiResponse::Unauthorized(Json(ErrorResponse {
                error: "Unauthenticated".to_string(),
            }));
        }
        
        // Call auth coordinator to change password
        match self.auth_coordinator
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


