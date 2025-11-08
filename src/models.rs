use poem_openapi::Object;

/// Request model for creating a new item
#[derive(Object, Debug)]
pub struct CreateItemRequest {
    /// Name of the item (1-100 characters)
    #[oai(validator(min_length = 1, max_length = 100))]
    pub name: String,
    
    /// Optional description of the item
    pub description: Option<String>,
}

/// Response model representing an item
#[derive(Object, Debug)]
pub struct Item {
    /// Unique identifier for the item
    pub id: String,
    
    /// Name of the item
    pub name: String,
    
    /// Optional description of the item
    pub description: Option<String>,
    
    /// Timestamp when the item was created (ISO 8601 format)
    pub created_at: String,
}

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
