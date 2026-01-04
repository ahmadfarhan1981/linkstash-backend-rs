use std::sync::Arc;

use crate::{errors::AuthError, providers::TokenProvider, types::internal::auth::Claims};
use poem::Request;
use poem_openapi::auth::{Bearer, BearerAuthorization};
use uuid::Uuid;

/// Source of the request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSource {
    /// Request originated from API endpoint
    API,

    /// Request originated from CLI command
    CLI,

    /// Request originated from system (automated operations)
    System,
}

/// Request context that flows through all layers
///
/// Contains contextual information about the current request that is needed
/// for logging, auditing, and tracing across API, service, and store layers.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestContext {
    /// IP address of the client making the request
    pub ip_address: Option<String>,

    /// Unique identifier for this request (for tracing across layers)
    pub request_id: String,

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
    /// Create a new RequestContext with a generated request_id
    ///
    /// Defaults to API source with "unknown" actor_id.
    /// Use `for_cli()` or `for_system()` for non-API operations.
    pub fn new() -> Self {
        Self {
            ip_address: None,
            request_id: Uuid::new_v4().to_string(),
            authenticated: false,
            claims: None,
            source: RequestSource::API,
            actor_id: "unknown".to_string(),
        }
    }

    /// Create a RequestContext for CLI operations
    ///
    /// # Arguments
    /// * `command_name` - Name of the CLI command being executed
    ///
    /// # Returns
    /// * RequestContext configured for CLI source
    pub fn for_cli(command_name: &str) -> Self {
        Self {
            ip_address: Some("localhost".to_string()),
            request_id: Uuid::new_v4().to_string(),
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
            request_id: Uuid::new_v4().to_string(),
            authenticated: false,
            claims: None,
            source: RequestSource::System,
            actor_id: format!("system:{}", operation_name),
        }
    }

    /// Set the ip_address
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
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
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestContext {
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
    fn extract_ip_address(req: &Request) -> Option<String> {
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
    pub async fn validate_request(
        req: &Request,
        token_provider: &Arc<TokenProvider>,
    ) -> ContextResult {
        // TODO refactor with new structure in mind
        // Extract IP address
        let ip_address = Self::extract_ip_address(req);
        let auth = Self::extract_bearer(req);
        // Create base context with IP and request_id (defaults to API source)
        let mut ctx = RequestContext::new()
            .with_ip_address(ip_address.unwrap_or_else(|| "unknown".to_string()));

        // If auth is provided, validate JWT and populate claims
        if let Some(bearer) = auth {
            match token_provider.validate_jwt(&bearer.token).await {
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
}
/// Result type for create_request_context that can carry context in error
pub enum ContextResult {
    /// Context created successfully, no password change required
    Ok(RequestContext),
    /// Password change required - context is included so allowed endpoints can extract it
    PasswordChangeRequired(RequestContext),
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
