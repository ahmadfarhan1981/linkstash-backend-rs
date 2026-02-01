use crate::AppData;
use crate::api::{Api, BearerAuth, TokenVerifier};
use crate::coordinators::LoginCoordinator;
use crate::types::dto::auth::{LoginApiResponse, LoginRequest, TokenResponse};
use crate::types::dto::common::ErrorResponse;

use poem::Request;
use poem_openapi::auth::BearerAuthorization;
use poem_openapi::{OpenApi, SecurityScheme, Tags, auth::Bearer, payload::Json};
use std::sync::Arc;
use uuid::Uuid;

/// Authentication API endpoints
pub struct AuthApi {
    auth_coordinator: LoginCoordinator,
    token_verifier: Arc<TokenVerifier>,
}

impl AuthApi {
    /// Create a new AuthApi with the given AuthCoordinator
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            auth_coordinator: LoginCoordinator::new(Arc::clone(&app_data)),
            token_verifier: Arc::new(TokenVerifier::new(Arc::clone(&app_data))),
        }
    }
}

/// API tags for authentication endpoints
#[derive(Tags)]
enum AuthTags {
    /// Authentication endpoints
    Authentication,
}
impl Api for AuthApi {
    fn token_verifier(&self) -> Arc<TokenVerifier> {
        todo!()
    }
}

#[OpenApi(prefix_path = "/auth")]
impl AuthApi {
    #[oai(path = "/login", method = "post", tag = "AuthTags::Authentication")]
    async fn login(&self, req: &Request, body: Json<LoginRequest>) -> LoginApiResponse {
        let meta = self.generate_request_context_meta(req);

        let response = self
            .auth_coordinator
            .login(meta, body.username.clone(), body.password.clone() )
            .await.unwrap_or(LoginApiResponse::Unauthorized(Json(ErrorResponse {
                    message: "Unauthorized".to_owned(),
                    error: "Error".to_owned(),
                    status_code: 301,
                })));
        response
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
