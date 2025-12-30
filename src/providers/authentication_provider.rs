use std::sync::Arc;
use clap::builder::Str;
use sea_orm::ConnectionTrait;

use crate::errors::InternalError;
use crate::stores::user_store::{UserForAuth, UserStore};
use crate::types::internal::context::RequestContext;
use crate::audit::audit_logger::AuditLogger;
use crate::config::database::DatabaseConnections;
use crate::providers::crypto_provider::CryptoProvider;


pub struct LoginRequest{
    pub username: String,
    pub password: String,
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
    crypto_provider: Arc<CryptoProvider>,

}

impl AuthenticationProvider {
    pub fn new(store: Arc<UserStore>, crypto_provider: Arc<CryptoProvider>) -> Self {
        Self{
            store,
            crypto_provider,
        }
    }
    pub async fn verify_credential(&self, 
                                    conn: &impl ConnectionTrait,
                                    creds: LoginRequest)->Result<LoginResponse, InternalError>{

        let user = self.store.get_user_from_username_for_auth(conn, &creds.username).await?;
        let user2 = user.clone();
        let result = self.crypto_provider.verify_password(&user.password_hash, &creds.password).await?;

        match result {
            true => Ok(LoginResponse::Success{ user: user2 }),
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