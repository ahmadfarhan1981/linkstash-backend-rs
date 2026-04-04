use std::sync::Arc;

use poem_openapi::payload::Json;

use crate::audit::AuditLogger;
use crate::config::database::DatabaseConnections;
use crate::coordinators::Coordinator;
use crate::providers::TokenProvider;
use crate::providers::authentication_provider::AuthenticationProvider;
use crate::providers::authentication_provider::VerifyCredentialResult::{Failure, Success};
use crate::stores::authentication_store::AuthenticationStore;
use crate::stores::user_store::UserStore;
use crate::types::dto::auth::{WhoAmIApiResponse, WhoAmIResponse};
use crate::types::dto::common::ErrorResponse;
use crate::types::internal::auth::Claims;
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
    connections: DatabaseConnections,
    authentication_provider: Arc<AuthenticationProvider>,
    token_provider: Arc<TokenProvider>,
    user_store: Arc<UserStore>,
    authentication_store: Arc<AuthenticationStore>,
}

impl Coordinator for LoginCoordinator {
    fn get_logger(&self) -> &Arc<AuditLogger> {
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
            authentication_store: Arc::clone(&app_data.stores.authentication_store),
        }
    }

    pub async fn login(
        &self,
        context_meta: RequestContextMeta,
        username: String,
        password: String,
    ) -> Result<LoginApiResponse, ApplicationError> {
        let conn = self.connections.begin_auth_transaction().await?;
        let ctx = RequestContext::from_context_meta(context_meta, &self.token_provider);
        let exec = self.exec(&ctx);
        let verify_credential_result = exec
            .fut(
                self.authentication_provider
                    .verify_credential(&conn, LoginRequest { username, password }),
            )
            .await?;
        match verify_credential_result {
            Success { user } => {
                let user_for_jwt = exec
                    .fut(
                        self.authentication_store
                            .get_user_roles_for_jwt(&conn, &user.id),
                    )
                    .await?;
                let jwt = exec
                    .fut(self.token_provider.generate_jwt(&user_for_jwt))
                    .await?;
                let rt = exec
                    .res(self.token_provider.generate_refresh_token())
                    .await?;
                exec.fut(self.authentication_store.save_refresh_token_for_user(
                    &conn,
                    &user.id,
                    &rt.token_hash,
                    rt.created_at,
                    rt.expires_at,
                ))
                .await?;
                Ok(LoginApiResponse::Ok(Json(TokenResponse {
                    access_token: jwt.jwt,
                    refresh_token: rt.token,
                    token_type: jwt.token_type,
                    expires_in: jwt.expires_in,
                })))
            }
            Failure { reason } => Err(ApplicationError::UnknownServerError {
                message: "Placeholeder".to_owned(),
            }),
        }
    }

    pub async fn whoami(
        &self,
        context_meta: RequestContextMeta,
    ) -> Result<WhoAmIApiResponse, ApplicationError> {
        let ctx = RequestContext::from_context_meta(context_meta, &self.token_provider);
        println!("{:?}", ctx);
        // Check if authenticated
        if !ctx.authenticated {
            return Ok(WhoAmIApiResponse::Unauthorized(Json(ErrorResponse {
                error: "Unauthenticated".to_string(),
                message: "Unauthenticated".to_owned(),
                status_code: 401,
            })));
        }

        let claims = ctx
            .claims
            .ok_or_else(|| ApplicationError::UnknownServerError {
                message: "No claims".to_owned(),
            })?;
        Ok(WhoAmIApiResponse::Ok(Json(WhoAmIResponse {
            user_id: claims.sub,
            expires_at: claims.exp,
        })))
    }
}
