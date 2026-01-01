use std::sync::Arc;
use clap::builder::Str;
use sea_orm::ConnectionTrait;

use crate::errors::InternalError;
use crate::providers::{TokenProvider, token_provider};
use crate::stores::user_store::{UserForAuth, UserStore};
use crate::types::internal::context::RequestContext;
use crate::audit::audit_logger::AuditLogger;
use crate::config::database::DatabaseConnections;
use crate::providers::crypto_provider::CryptoProvider;
use crate::providers::token_provider::GeneratedRT;

pub struct LoginRequest{
    pub username: String,
    pub password: String,
}

pub struct AuthenticatedUser{
    pub username: String,
    pub jwt: String,
    pub rt: String,
}
pub enum  LoginResponse{
    Success{ user: UserForAuth},
    Failure{ reason: LoginFailureReason}
}

pub enum LoginFailureReason{
    InvalidCredentials,
    /** For future **/
    Banned,
    RateLimited,
}
pub struct RefreshRequest{}
pub struct RefreshResponse{}
pub struct LogoutRequest{}
pub struct LogoutResponse{}
pub struct AuthenticationProvider {
    store: Arc<UserStore>,
    crypto_provider: Arc<CryptoProvider>,
    token_provider: Arc<TokenProvider>

}

impl AuthenticationProvider {
    pub fn new(store: Arc<UserStore>, crypto_provider: Arc<CryptoProvider>, token_provider:Arc<TokenProvider>) -> Self {
        Self{
            store,
            crypto_provider,
            token_provider,
        }
    }
    pub async fn verify_credential(&self, 
                                    conn: &impl ConnectionTrait,
                                    creds: LoginRequest)->Result<LoginResponse, InternalError>{

        let user = self.store.get_user_from_username_for_auth(conn, &creds.username).await?;
        let authenticated = self.crypto_provider.verify_password(&user.password_hash, &creds.password).await?;
        


        match authenticated {
            true => Ok(LoginResponse::Success{ user }),
            false => Ok(LoginResponse::Failure { reason:LoginFailureReason::InvalidCredentials })
        }
    }

    // pub async fn generate_refresh_token_for_user(&self, conn: &impl ConnectionTrait, user_id:&str)-> Result<GeneratedRT,InternalError>{
    //     let rt = self.token_provider.generate_refresh_token();
    //     self.store.save_refresh_token_for_user(conn , user_id, &rt.token, rt.created_at, rt.expires_at).await?;
    //     Ok(rt)
    // }
    async fn refresh(&self, ctx: &RequestContext, refresh_request: RefreshRequest)->Result<RefreshResponse, InternalError>{
        Ok(RefreshResponse{})
    }
    async fn logout(&self, ctx: &RequestContext, logout_request: LogoutRequest)->Result<LogoutResponse, InternalError>{
        Ok(LogoutResponse{})
    }

    
}