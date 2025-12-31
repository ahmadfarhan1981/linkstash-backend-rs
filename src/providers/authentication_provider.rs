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
    Success{ user: AuthenticatedUser},
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
            true => {
                let user_for_jwt = self.store.get_user_roles_for_jwt(conn, &creds.username).await?;
                let jwt = self.token_provider.generate_jwt(&user_for_jwt).await?;
                let rt = self.token_provider.generate_refresh_token();
                self.store.save_refresh_token_for_user(conn , &user, &rt.token, rt.created_at, rt.expires_at).await?;
                Ok(LoginResponse::Success{ user:AuthenticatedUser{
                    username: creds.username.clone(),
                    jwt: jwt.jwt,
                    rt: rt.token.to_string() ,
                }  })

            },
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