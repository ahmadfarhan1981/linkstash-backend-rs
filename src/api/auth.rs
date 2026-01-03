use crate::AppData;
use crate::coordinators::LoginCoordinator;
use crate::types::dto::auth::{ErrorResponse, LoginApiResponse, LoginRequest, TokenResponse};
use crate::types::internal::context::RequestContext;
use poem::Request;
use poem_openapi::auth::BearerAuthorization;
use poem_openapi::{OpenApi, SecurityScheme, Tags, auth::Bearer, payload::Json};
use std::sync::Arc;

/// Authentication API endpoints
pub struct AuthApi {
    auth_coordinator: LoginCoordinator,
}

impl AuthApi {
    /// Create a new AuthApi with the given AuthCoordinator
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            auth_coordinator: LoginCoordinator::new(app_data),
        }
    }
}

/// JWT Bearer token authentication
#[derive(SecurityScheme, Debug)]
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
    #[oai(path = "/login", method = "post", tag = "AuthTags::Authentication")]
    async fn login(&self, req: &Request, body: Json<LoginRequest>) -> LoginApiResponse {
        let auth = match Bearer::from_request(req) {
            Ok(bearer) => Some(bearer),
            Err(_) => None,
        };

        let ctx = RequestContext::new();
        
        // self.auth_coordinator.login(ctx, username, password);

        // self.auth_coordinator.login(ctx, username, password)
        LoginApiResponse::Ok(Json(TokenResponse {
            access_token: format!("{:?}", auth),
            refresh_token: "".to_string(),
            token_type: "".to_string(),
            expires_in: 0,
        }))
    }
    #[oai(path = "/test", method = "post", tag = "AuthTags::Authentication")]
    async fn test(
        &self,
        req: &Request,
        body: Json<LoginRequest>,
        auth: BearerAuth,
    ) -> LoginApiResponse {
        LoginApiResponse::Ok(Json(TokenResponse {
            access_token: format!("{:?}", auth),
            refresh_token: "".to_string(),
            token_type: "".to_string(),
            expires_in: 0,
        }))
    }
}
