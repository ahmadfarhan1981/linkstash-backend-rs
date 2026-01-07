use std::{net::IpAddr, sync::Arc};

use crate::{errors::InternalError, providers::TokenProvider, types::internal::{RequestContextMeta, auth::Claims}};
use poem::Request;
use poem_openapi::auth::{Bearer, BearerAuthorization};
use uuid::Uuid;

use super::{context_result::ContextResult, request_id::RequestId, request_source::RequestSource};

/// Request context that flows through all layers
///
/// Contains contextual information about the current request that is needed
/// for logging, auditing, and tracing across API, service, and store layers.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestContext {
    /// IP address of the client making the request
    pub ip_address: Option<IpAddr>,

    /// Unique identifier for this request (for tracing across layers)
    pub request_id: RequestId,

    /// Whether the request is authenticated (JWT validated successfully)
    pub authenticated: bool,

    /// Full JWT claims if authenticated
    pub claims: Option<Claims>,

    /// Source of the request (API, CLI, or System)
    pub source: RequestSource,

    /// Actor who initiated the operation
    pub actor_id: String,
}

impl RequestContext {
    /// Create a RequestContext for CLI operations
    ///
    /// # Arguments
    /// * `command_name` - Name of the CLI command being executed
    ///
    /// # Returns
    /// * RequestContext configured for CLI source
    pub fn for_cli(command_name: &str) -> Self {
        Self {
            ip_address: None,
            request_id: RequestId(Uuid::new_v4()),
            authenticated: false,
            claims: None,
            source: RequestSource::CLI,
            actor_id: format!("cli:{}", command_name),
        }
    }

    /// Create a RequestContext for system operations
    ///
    /// # Arguments
    /// * `operation_name` - Name of the system operation being executed
    ///
    /// # Returns
    /// * RequestContext configured for System source
    pub fn for_system(operation_name: &str) -> Self {
        Self {
            ip_address: None,
            request_id: RequestId(Uuid::new_v4()),
            authenticated: false,
            claims: None,
            source: RequestSource::System,
            actor_id: format!("system:{}", operation_name),
        }
    }

    fn extract_bearer(req: &Request) -> Option<Bearer> {
        match Bearer::from_request(req) {
            Ok(bearer) => Some(bearer),
            Err(_) => None,
        }
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
    fn extract_ip_address(req: &Request) -> Option<IpAddr> {
        // Check X-Forwarded-For header (proxy/load balancer)
        if let Some(forwarded) = req.header("X-Forwarded-For") {
            if let Some(ip) = forwarded.split(',').next() {
                return ip.trim().parse().ok();
            }
        }

        // Check X-Real-IP header (nginx)
        if let Some(real_ip) = req.header("X-Real-IP") {
            return real_ip.parse().ok();
        }

        // Fall back to remote address
        req.remote_addr().as_socket_addr().map(|addr| addr.ip())
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
    pub async fn validate_request(
        req: &Request,
        token_provider: &Arc<TokenProvider>,
    ) -> ContextResult {
        // TODO refactor with new structure in mind
        // Extract IP address
        let ip_address = Self::extract_ip_address(req);
        let auth = Self::extract_bearer(req);
        // Create base context with IP and request_id (defaults to API source)

        let mut ctx = RequestContext {
            ip_address,
            request_id: RequestId(Uuid::new_v4()),
            authenticated: false,
            claims: None,
            source: RequestSource::API,
            actor_id: "".to_owned(),
        };
        if let Some(ip) = ip_address {
            // ctx = ctx.clone().with_ip_address(ip);
            let mut ctx = ctx.clone();
            ctx.ip_address = Some(ip);
        }
        // .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));

        // If auth is provided, validate JWT and populate claims
        if let Some(bearer) = auth {
            match token_provider.validate_jwt(&bearer) {
                Ok(claims) => {
                    // JWT is valid, set authenticated and claims
                    // Set actor_id from JWT subject (user_id)
                    ctx = ctx
                        .with_auth(claims.clone())
                        .with_actor_id(claims.sub.clone());

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

    /// Set the ip_address
    pub fn with_ip_address(mut self, ip_address: IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Set authentication state with claims
    pub fn with_auth(mut self, claims: Claims) -> Self {
        self.authenticated = true;
        self.claims = Some(claims);
        self
    }

    /// Set the actor_id
    pub fn with_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.actor_id = actor_id.into();
        self
    }

    pub fn from_context_meta(
        context_meta: RequestContextMeta,
        token_provider: &Arc<TokenProvider>,
    ) -> Self {
        let claims = context_meta
            .auth
            .as_ref()
            .ok_or_else(|| {
                InternalError::Login(crate::errors::internal::login::LoginError::IncorrectPassword)
            })
            .and_then(|bearer| token_provider.validate_jwt(bearer));

        let actor_id = claims
            .as_ref()
            .ok()
            .map(|claims| claims.sub.clone())
            .unwrap_or("unknown".to_owned());

        Self {
            ip_address: context_meta.ip,
            request_id: context_meta.request_id,
            authenticated: claims.is_ok(),
            claims: claims.ok(),
            source: context_meta.source,
            actor_id,
        }
    }
}
