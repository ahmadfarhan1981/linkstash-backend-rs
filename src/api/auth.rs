use poem_openapi::auth::BearerAuthorization;
use poem_openapi::{payload::Json, OpenApi, Tags, SecurityScheme, auth::Bearer};
use poem::Request;
use crate::coordinators::AuthCoordinator;
use crate::types::dto::auth::{
    LoginRequest, LoginApiResponse, ErrorResponse
};
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
}