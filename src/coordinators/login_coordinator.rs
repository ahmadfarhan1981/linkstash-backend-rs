use std::sync::Arc;

use poem_openapi::payload::Json;

use crate::{config::ApplicationError, errors::InternalError, providers::authentication_provider::AuthenticationProvider, types::{dto::auth::{LoginApiResponse, TokenResponse}, internal::context::RequestContext}};

pub struct LoginCoordinator{
    auth_provider: Arc<AuthenticationProvider>,
}

impl LoginCoordinator{
       pub async fn login(
        &self,
        ctx: &RequestContext,
        username: String,
        password: String,
    ) -> Result<LoginApiResponse, ApplicationError> {
        // self.auth_provider.

        Ok(LoginApiResponse::Ok(Json(TokenResponse{ access_token: "todo!()".to_string(), refresh_token: "todo!()".to_string(), token_type: "todo!()".to_string(), expires_in: 0 })))
    }
}