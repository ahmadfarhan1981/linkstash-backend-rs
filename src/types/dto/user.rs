use poem_openapi::{ApiResponse, Object};
use poem_openapi::payload::Json;
use serde::{Deserialize, Serialize};
use crate::types::dto::common::ErrorResponse;

#[derive(ApiResponse)]
pub enum CreateUserApiResponse {
    /// Authentication successful, tokens provided
    #[oai(status = 200)]
    Ok(Json<CreatedUserResponse>),

    /// Invalid username or password
    #[oai(status = 401)]
    Unauthorized(Json<ErrorResponse>),
}

/// Response model containing authentication tokens
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreatedUserResponse {
   pub username: String,
}
