use crate::AppData;
use crate::api::{Api, BearerAuth};
use crate::coordinators::user_coordinator::UserCoordinator;

use crate::types::dto::auth::LoginRequest;
use crate::types::dto::user::{CreateUserApiResponse, CreatedUserResponse};
use poem::Request;
use poem_openapi::{OpenApi, Tags, payload::Json};
use std::sync::Arc;

pub struct UserApi {
    user_coordinator: UserCoordinator,
}

impl UserApi {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            user_coordinator: UserCoordinator::new(app_data),
        }
    }
}

#[derive(Tags)]
enum AuthTags {
    Authentication,
}
impl Api for UserApi {}

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

        CreateUserApiResponse::Ok(Json(CreatedUserResponse {
            username: "200".to_owned(),
        }))
    }
}
