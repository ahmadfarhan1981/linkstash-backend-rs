use std::sync::Arc;

use poem_openapi::payload::Json;
use sea_orm::ConnectionTrait;

use crate::audit::AuditLogger;
use crate::providers::authentication_provider::AuthenticationProvider;
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
}

impl LoginCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            authentication_provider: Arc::clone(&app_data.providers.authentication_provider),
            audit_logger: Arc::clone(&app_data.audit_logger)
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
                
            },
            Err(e) => {
                match e {
                    crate::errors::InternalError::Database(database_error) => todo!(),
                    crate::errors::InternalError::Parse { value_type, message } => todo!(),
                    crate::errors::InternalError::Crypto { operation, message } => todo!(),
                    crate::errors::InternalError::Credential(credential_error) => todo!(),
                    crate::errors::InternalError::SystemConfig(system_config_error) => todo!(),
                    crate::errors::InternalError::Audit(audit_error) => todo!(),
                    crate::errors::InternalError::JWTValidation(jwtvalidation_error) => todo!(),
                }
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
