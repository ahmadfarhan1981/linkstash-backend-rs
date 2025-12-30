use std::sync::Arc;

use poem_openapi::payload::Json;

use crate::{AppData, config::ApplicationError, providers::authentication_provider::LoginRequest, types::{dto::auth::{LoginApiResponse, TokenResponse}, internal::context::RequestContext}};
use crate::providers::authentication_provider::AuthenticationProvider;

pub struct LoginCoordinator{
    authentication_provider : Arc<AuthenticationProvider>
}

impl LoginCoordinator{
     pub fn new(app_data: Arc<AppData>) -> Self {
        
    
        Self {
            authentication_provider: Arc::clone(&app_data.providers.authentication_provider),
        }
    }
    
    
       pub async fn login(
        &self,
        ctx: &RequestContext,
        username: String,
        password: String,
    ) -> Result<LoginApiResponse, ApplicationError> {
        // self.auth_provider. 
        // self.authentication_provider.verify_credential(ctx, conn, LoginRequest{})

        Ok(LoginApiResponse::Ok(Json(TokenResponse{ access_token: "todo!()".to_string(), refresh_token: "todo!()".to_string(), token_type: format!("{:?}", ctx), expires_in: 0 })))
    }
}