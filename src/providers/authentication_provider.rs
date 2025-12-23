use linkstash_backend::errors::InternalError;
use crate::types::internal::context::RequestContext;
use crate::audit::audit_logger_provider::AuditLogger;

pub struct LoginRequest{}
pub struct LoginResponse{}
pub struct RefreshRequest{}
pub struct RefreshResponse{}
pub struct LogoutRequest{}
pub struct LogoutResponse{}
pub struct AuthenticationProvider {

}
impl AuthenticationProvider {
    async fn login(&self, ctx: &RequestContext, creds: LoginRequest)->Result<LoginResponse, InternalError>{
        Ok(LoginResponse{})
    }
    async fn refresh(&self, ctx: &RequestContext, refresh_request: RefreshRequest)->Result<RefreshResponse, InternalError>{
        Ok(RefreshResponse{})
    }
    async fn logout(&self, ctx: &RequestContext, logout_request: LogoutRequest)->Result<LogoutResponse, InternalError>{
        Ok(LogoutResponse{})
    }
}