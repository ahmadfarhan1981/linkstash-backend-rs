use std::sync::Arc;

use poem_openapi::payload::Json;
use sea_orm::{ConnectionTrait, TransactionTrait};

use crate::audit::AuditLogger;
use crate::config::database::DatabaseConnections;
use crate::coordinators::{Coordinator, Exec, execute};
use crate::errors::AuthError;
use crate::providers::TokenProvider;
use crate::providers::authentication_provider::AuthenticationProvider;
use crate::providers::authentication_provider::VerifyCredentialResult::{Failure, Success};
use crate::stores::user_store::UserStore;
use crate::types::internal::context::RequestContextMeta;
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
    connections: DatabaseConnections,
}

impl Coordinator for LoginCoordinator{
    fn get_logger (&self)-> &Arc<AuditLogger> {
        &self.audit_logger
    }
}
impl LoginCoordinator {

    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            authentication_provider: Arc::clone(&app_data.providers.authentication_provider),
            audit_logger: Arc::clone(&app_data.audit_logger),
            token_provider: Arc::clone(&app_data.providers.token_provider),
            user_store: Arc::clone(&app_data.stores.user_store),
            connections: app_data.connections.clone(),
        }
    }

    pub async fn login(
        &self,
        context_meta: RequestContextMeta,
        username: String,
        password: String,
    ) -> Result<LoginApiResponse, ApplicationError> {
        let conn =self.connections.begin_auth_transaction().await?;
        
        let claims = self.token_provider.validate_jwt(context_meta.auth);
        let ctx = RequestContext::from(context_meta);
        let exec = self.exec(ctx);
        let verify_credential_result = exec.fut(self.authentication_provider.verify_credential(&conn, LoginRequest { username, password })).await?;
        

        match verify_credential_result {
            Success { user } => {        
                    let user_for_jwt = exec
                        .fut(self.user_store.get_user_roles_for_jwt(&conn, &user.id))
                        .await?;
                    let jwt = exec
                        .fut(self.token_provider.generate_jwt(&user_for_jwt))
                        .await?;
                    let rt = exec
                        .res(self.token_provider.generate_refresh_token())
                        .await?;
                    self.user_store
                        .save_refresh_token_for_user(
                            &conn,
                            &user.id,
                            &rt.token_hash,
                            rt.created_at,
                            rt.expires_at,
                        )
                        .await?;
                    Ok(LoginApiResponse::Ok(Json(TokenResponse {
                        access_token: jwt.jwt,
                        refresh_token: rt.token,
                        token_type: jwt.token_type,
                        expires_in: jwt.expires_in,
                    })))
                },
            Failure { reason } => Err(ApplicationError::UnknownServerError { message: "Placeholeder".to_owned() }),
        }

        
        
    }
    
}
