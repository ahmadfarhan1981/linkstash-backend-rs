use poem_openapi::Object;

/// Response model for health check endpoint
#[derive(Object, Debug)]
pub struct HealthResponse {
    /// Status of the service
    pub status: String,

    /// Timestamp of the health check (ISO 8601 format)
    pub timestamp: String,
}

/// Standardized error response model
#[derive(Object, Debug)]
pub struct ErrorResponse {
    /// Error type or category
    pub error: String,

    /// Human-readable error message
    pub message: String,

    /// HTTP status code
    pub status_code: u16,
}
