use std::sync::Arc;

use poem_openapi::payload::Json;
use sea_orm::ConnectionTrait;

use crate::audit::AuditLogger;
use crate::providers::TokenProvider;
use crate::providers::authentication_provider::AuthenticationProvider;
use crate::stores::user_store::UserStore;
use crate::{
    AppData,
    config::ApplicationError,
    providers::authentication_provider::LoginRequest,
    types::{
        dto::auth::{LoginApiResponse, TokenResponse},
        internal::context::RequestContext,
    },
};

pub struct LoginCoordinator {
    audit_logger: Arc<AuditLogger>,
    authentication_provider: Arc<AuthenticationProvider>,
    token_provider: Arc<TokenProvider>,
    user_store: Arc<UserStore>,

}

impl LoginCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            authentication_provider: Arc::clone(&app_data.providers.authentication_provider),
            audit_logger: Arc::clone(&app_data.audit_logger),
            token_provider: Arc::clone(&app_data.providers.token_provider),
            user_store: Arc::clone(&app_data.stores.user_store),
        }
    }

    pub async fn login(
        &self,
        ctx: &RequestContext,
        conn: &impl ConnectionTrait,
        username: String,
        password: String,
    ) -> Result<LoginApiResponse, ApplicationError> {
        // self.auth_provider.
        // self.authentication_provider.verify_credential(ctx, conn, LoginRequest{})
        
        match self.authentication_provider.verify_credential( conn, LoginRequest{ username, password }).await{
            Ok(user) => {
                match user {
                    crate::providers::authentication_provider::LoginResponse::Success { user } =>{
                        let user_for_jwt = self.user_store.get_user_roles_for_jwt(conn, &user.id).await?;
                        let jwt = self.token_provider.generate_jwt(&user_for_jwt).await?;
                        let rt = self.token_provider.generate_refresh_token();
                        self.user_store.save_refresh_token_for_user(conn , &user.id, &rt.token_hash, rt.created_at, rt.expires_at).await?;

                    },
                    crate::providers::authentication_provider::LoginResponse::Failure { reason } => todo!(),
                }
            },
            Err(_e) => {
            
            },
        }

        Ok(LoginApiResponse::Ok(Json(TokenResponse {
            access_token: "todo!()".to_string(),
            refresh_token: "todo!()".to_string(),
            token_type: format!("{:?}", ctx),
            expires_in: 0,
        })))
    }
}
