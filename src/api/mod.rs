// API layer - HTTP endpoints
pub mod admin;
pub mod auth;
pub mod health;
pub mod helpers;

use std::sync::Arc;

pub use admin::AdminApi;
pub use auth::AuthApi;
pub use health::HealthApi;
use migration::token;
use poem::Request;
use poem_openapi::auth::Bearer;


use crate::{providers::TokenProvider, types::{ApiResult, internal::context::RequestContext}};


pub trait Api {
    fn get_token_provider(&self) -> &Arc<TokenProvider>;

    fn get_context_for_authenticated_endpoint() {
        print!("Test");
    }

    async fn get_context_for_unauthenticated_endpoint(&self, req :&Request)-> ApiResult<RequestContext>{
        let token_provider = self.get_token_provider();
        let context = RequestContext::validate_request(req, token_provider).await;

        Err(crate::config::ApplicationError::UnknownSetting { name: "placeholder".to_owned() })
    }
}

