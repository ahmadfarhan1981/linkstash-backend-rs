use poem::Request;
use poem_openapi::auth::Bearer;
use crate::types::internal::context::RequestContext;
use crate::services::TokenService;
use std::sync::Arc;

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
/// Note: This fetches the current user to preserve other privilege flags
/// before calling set_privileges(). This extra read is intentional to:
/// 1. Prevent accidentally removing other roles
/// 2. Provide clear, single-purpose API endpoints
/// 3. Enable fine-grained authorization checks
/// 
/// The performance impact is negligible for admin operations.
/// 
/// # Arguments
/// * `req` - The HTTP request
/// * `auth` - Optional Bearer token (None for unauthenticated endpoints)
/// * `token_service` - TokenService for JWT validation
/// 
/// # Returns
/// RequestContext with authenticated=true if JWT is valid, false otherwise
pub async fn create_request_context(
    req: &Request,
    auth: Option<Bearer>,
    token_service: &Arc<TokenService>,
) -> RequestContext {
    // Extract IP address
    let ip_address = extract_ip_address(req);
    
    // Create base context with IP and request_id (defaults to API source)
    let mut ctx = RequestContext::new()
        .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));
    
    // If auth is provided, validate JWT and populate claims
    if let Some(bearer) = auth {
        match token_service.validate_jwt(&bearer.token).await {
            Ok(claims) => {
                // Set actor_id from JWT subject (user_id)
                ctx.actor_id = claims.sub.clone();
                // JWT is valid, set authenticated and claims
                ctx = ctx.with_auth(claims);
            }
            Err(_) => {
                // JWT validation failed (expired, invalid, tampered)
                // TokenService.validate_jwt already logged the failure
                // Context remains with authenticated=false, claims=None
            }
        }
    }
    
    tracing::trace!("Request context created: {:?}", ctx);
    
    ctx
}


#[cfg(test)]
#[path = "helpers_test.rs"]
mod helpers_test;
