use poem_openapi::{payload::Json, OpenApi, Tags};
use crate::types::dto::items::{CreateItemRequest, Item};
use chrono::Utc;
use uuid::Uuid;

/// Items API
pub struct ItemsApi;

/// API tags for item endpoints
#[derive(Tags)]
enum ApiTags {
    /// Item management endpoints
    Items,
}

#[OpenApi]
impl ItemsApi {
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
