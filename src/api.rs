use poem_openapi::{payload::Json, OpenApi};
use crate::models::{CreateItemRequest, Item, HealthResponse};
use chrono::Utc;
use uuid::Uuid;

/// API service containing all endpoint definitions
pub struct Api;

#[OpenApi]
impl Api {
    /// Health check endpoint
    /// 
    /// Returns the current status of the API service
    #[oai(path = "/health", method = "get", tag = "ApiTags::Health")]
    async fn health(&self) -> Json<HealthResponse> {
        Json(HealthResponse {
            status: "healthy".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        })
    }

    /// Create a new item
    /// 
    /// Accepts item details and returns the created item with generated ID and timestamp
    #[oai(path = "/items", method = "post", tag = "ApiTags::Items")]
    async fn create_item(
        &self,
        body: Json<CreateItemRequest>,
    ) -> Json<Item> {
        let item = Item {
            id: Uuid::new_v4().to_string(),
            name: body.name.clone(),
            description: body.description.clone(),
            created_at: Utc::now().to_rfc3339(),
        };
        
        Json(item)
    }
}

/// API tags for grouping endpoints in Swagger UI
#[derive(poem_openapi::Tags)]
enum ApiTags {
    /// Health check endpoints
    Health,
    /// Item management endpoints
    Items,
}
