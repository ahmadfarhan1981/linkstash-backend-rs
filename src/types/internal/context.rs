use crate::types::internal::auth::Claims;
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
