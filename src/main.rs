mod models;
mod api;

use poem::{listener::TcpListener, Route, Server};
use poem_openapi::OpenApiService;
use api::Api;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Create OpenAPI service with API implementation
    let api_service = OpenApiService::new(Api, "Swagger API Generation", "1.0.0")
        .server("http://localhost:3000/api");
    
    // Generate Swagger UI from OpenAPI service
    let ui = api_service.swagger_ui();
    
    // Compose routes: nest API service under /api and Swagger UI under /swagger
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/swagger", ui);
    
    // Configure TCP listener on 0.0.0.0:3000
    println!("Starting server on http://0.0.0.0:3000");
    println!("Swagger UI available at http://localhost:3000/swagger");
    println!("API endpoints available at http://localhost:3000/api");
    
    // Start Poem server with composed routes
    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
