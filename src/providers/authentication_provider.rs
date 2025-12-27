use std::sync::Arc;
use linkstash_backend::errors::InternalError;
use crate::stores::user_store::{UserForAuth, UserStore};
use crate::types::internal::context::RequestContext;
use crate::audit::audit_logger::AuditLogger;
use crate::config::database::DatabaseConnections;
use crate::providers::crypto_provider::CryptoProvider;
use crate::stores::CredentialStore;

pub struct LoginRequest{
    username: String,
    password: String,
}
pub enum  LoginResponse{
    Success{ user: UserForAuth},
    InvalidCredentials,
    /** For future **/
    Banned,
    RateLimited,
    PasswordChangeRequired,
}
pub struct RefreshRequest{}
pub struct RefreshResponse{}
pub struct LogoutRequest{}
pub struct LogoutResponse{}
pub struct AuthenticationProvider {
    store: Arc<UserStore>,
    connections : DatabaseConnections,
    crupto_provider: Arc<CryptoProvider>,

}
impl AuthenticationProvider {
    async fn verify_credential(&self, ctx: &RequestContext, creds: LoginRequest)->Result<LoginResponse, InternalError>{
        let txn = self.connections.begin_auth_transaction().await?;
        let user = self.store.get_user_from_username_for_auth(ctx, txn, &creds.username).await?;
        let result = self.crupto_provider.verify_password(user.password_hash, creds.password).await?;

            
        match result {
            true => Ok(LoginResponse::Success{ user }),
            false => Ok(LoginResponse::InvalidCredentials)
        }
    }
    async fn refresh(&self, ctx: &RequestContext, refresh_request: RefreshRequest)->Result<RefreshResponse, InternalError>{
        Ok(RefreshResponse{})
    }
    async fn logout(&self, ctx: &RequestContext, logout_request: LogoutRequest)->Result<LogoutResponse, InternalError>{
        Ok(LogoutResponse{})
    }

    
}