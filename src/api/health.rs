use poem_openapi::{payload::Json, OpenApi, Tags};
use crate::types::dto::common::HealthResponse;
use chrono::Utc;

/// Health check API
pub struct HealthApi;

/// API tags for health endpoints
#[derive(Tags)]
enum ApiTags {
    /// Health check endpoints
    Health,
}

#[OpenApi]
impl HealthApi {
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
}
