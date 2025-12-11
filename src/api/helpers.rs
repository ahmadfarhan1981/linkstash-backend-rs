use poem::Request;
use poem_openapi::auth::Bearer;
use crate::types::internal::context::RequestContext;
use crate::providers::TokenProvider;
use crate::errors::AuthError;
use std::sync::Arc;

/// Result type for create_request_context that can carry context in error
pub enum ContextResult {
    /// Context created successfully, no password change required
    Ok(RequestContext),
    /// Password change required - context is included so allowed endpoints can extract it
    PasswordChangeRequired(RequestContext),
}

/// Extract IP address from request headers
/// 
/// Checks X-Forwarded-For, X-Real-IP, and falls back to remote address.
/// 
/// # Arguments
/// * `req` - The HTTP request
/// 
/// # Returns
/// * `Some(String)` - IP address if found
/// * `None` - No IP address could be determined
pub fn extract_ip_address(req: &Request) -> Option<String> {
    // Check X-Forwarded-For header (proxy/load balancer)
    if let Some(forwarded) = req.header("X-Forwarded-For") {
        if let Some(ip) = forwarded.split(',').next() {
            return Some(ip.trim().to_string());
        }
    }
    
    // Check X-Real-IP header (nginx)
    if let Some(real_ip) = req.header("X-Real-IP") {
        return Some(real_ip.to_string());
    }
    
    // Fall back to remote address
    req.remote_addr()
        .as_socket_addr()
        .map(|addr| addr.ip().to_string())
}

/// Create RequestContext from request and optional authentication
/// 
/// This helper function should be called at the beginning of every endpoint.
/// It creates a RequestContext with IP address and request_id, and if authentication
/// is provided, validates the JWT and populates the claims.
/// 
/// Returns ContextResult::PasswordChangeRequired if the user has password_change_required=true.
/// Most endpoints should convert this to an error using `?` operator via into_result().
/// Allowed endpoints (/auth/change-password, /auth/whoami) should extract the context.
/// 
/// # Arguments
/// * `req` - The HTTP request
/// * `auth` - Optional Bearer token (None for unauthenticated endpoints)
/// * `token_provider` - TokenProvider for JWT validation
/// 
/// # Returns
/// * `ContextResult::Ok(ctx)` - Context ready to use
/// * `ContextResult::PasswordChangeRequired(ctx)` - User must change password (context included)
pub async fn create_request_context(
    req: &Request,
    auth: Option<Bearer>,
    token_provider: &Arc<TokenProvider>,
) -> ContextResult {
    // Extract IP address
    let ip_address = extract_ip_address(req);
    
    // Create base context with IP and request_id (defaults to API source)
    let mut ctx = RequestContext::new()
        .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));
    
    // If auth is provided, validate JWT and populate claims
    if let Some(bearer) = auth {
        match token_provider.validate_jwt(&bearer.token).await {
            Ok(claims) => {
                // JWT is valid, set authenticated and claims
                // Set actor_id from JWT subject (user_id)
                ctx = ctx.with_auth(claims.clone()).with_actor_id(claims.sub.clone());
                
                // Check password change requirement AFTER successful JWT validation
                if claims.password_change_required {
                    tracing::debug!("Password change required for user {}", claims.sub);
                    return ContextResult::PasswordChangeRequired(ctx);
                }
            }
            Err(_) => {
                // JWT validation failed (expired, invalid, tampered)
                // TokenProvider.validate_jwt already logged the failure
                // Context remains with authenticated=false, claims=None
            }
        }
    }
    
    tracing::trace!("Request context created: {:?}", ctx);
    
    ContextResult::Ok(ctx)
}

impl ContextResult {
    /// Convert ContextResult to Result, mapping PasswordChangeRequired to an error
    /// 
    /// Most endpoints should use this to automatically reject users with password_change_required=true.
    /// 
    /// # Returns
    /// * `Ok(ctx)` - Context ready to use
    /// * `Err(AuthError::PasswordChangeRequired)` - User must change password first
    pub fn into_result(self) -> Result<RequestContext, AuthError> {
        match self {
            ContextResult::Ok(ctx) => Ok(ctx),
            ContextResult::PasswordChangeRequired(_) => Err(AuthError::password_change_required()),
        }
    }
    
    /// Extract the context regardless of whether password change is required
    /// 
    /// Only use this for endpoints that should remain accessible when password change is required
    /// (/auth/change-password, /auth/whoami).
    /// 
    /// # Returns
    /// The RequestContext
    pub fn into_context(self) -> RequestContext {
        match self {
            ContextResult::Ok(ctx) => ctx,
            ContextResult::PasswordChangeRequired(ctx) => ctx,
        }
    }
}


#[cfg(test)]
#[path = "helpers_test.rs"]
mod helpers_test;
