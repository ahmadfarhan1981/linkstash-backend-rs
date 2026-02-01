use crate::AppData;
use crate::api::{Api, BearerAuth, TokenVerifier};
use crate::coordinators::user_coordinator::UserCoordinator;

use crate::types::dto::auth::LoginRequest;
use crate::types::dto::user::{CreateUserApiResponse, CreatedUserResponse};
use poem::Request;
use poem_openapi::{OpenApi, Tags, payload::Json};
use std::sync::Arc;
use poem_openapi::auth::Bearer;
use crate::config::SecretManager;
use crate::errors::AuthError::InternalError;
use crate::errors::internal::jwt_validation::{JwtErrorInfo, JwtFailClass};

pub struct UserApi {
    user_coordinator: UserCoordinator,
    token_verifier: Arc<TokenVerifier>,
}

impl UserApi {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            user_coordinator: UserCoordinator::new(Arc::clone(&app_data)),
            token_verifier: Arc::new(TokenVerifier::new(Arc::clone(&app_data))),
        }
    }
}

#[derive(Tags)]
enum AuthTags {
    Authentication,
}
impl Api for UserApi {
    fn token_verifier(&self) -> Arc<TokenVerifier> {
        Arc::clone(&self.token_verifier)
    }
}

#[OpenApi(prefix_path = "/user")]
impl UserApi {
    #[oai(path = "/", method = "post", tag = "AuthTags::Authentication")]
    async fn user(
        &self,
        req: &Request,
        // auth: BearerAuth, TODO eneabled later
        body: Json<LoginRequest>,
    ) -> CreateUserApiResponse {
        let meta = self.generate_request_context_meta(req);
        let request_context= self.generate_request_context(meta);
        let res = self.user_coordinator.create_user(request_context, "username".to_owned(), "password".to_owned()).await;
        CreateUserApiResponse::Ok(Json(CreatedUserResponse {
            username: "200".to_owned(),
        }))
    }


}


