use uuid::Uuid;
use crate::types::internal::auth::Claims;

/// Request context that flows through all layers
/// 
/// Contains contextual information about the current request that is needed
/// for logging, auditing, and tracing across API, service, and store layers.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// IP address of the client making the request
    pub ip_address: Option<String>,
    
    /// Unique identifier for this request (for tracing across layers)
    pub request_id: String,
    
    /// Whether the request is authenticated (JWT validated successfully)
    pub authenticated: bool,
    
    /// Full JWT claims if authenticated
    pub claims: Option<Claims>,
}

impl RequestContext {
    /// Create a new RequestContext with a generated request_id
    pub fn new() -> Self {
        Self {
            ip_address: None,
            request_id: Uuid::new_v4().to_string(),
            authenticated: false,
            claims: None,
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
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}
