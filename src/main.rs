mod api;
mod app_data;
mod config;
mod types;
mod errors;
mod stores;
mod services;
mod cli;

use std::sync::Arc;
use poem::{Route, Server, handler, listener::TcpListener, web::Html};
use poem_openapi::OpenApiService;
use api::{HealthApi, AuthApi, AdminApi};
use app_data::AppData;
use config::init_logging;
use clap::Parser;
use stores::CredentialStore;
use errors::auth::AuthError;

/// Seed test user for development
/// 
/// Only runs in debug builds. Creates a test user with username "testuser"
/// and password "testpass" for development and testing purposes.
#[cfg(debug_assertions)]
async fn seed_test_user(credential_store: &CredentialStore) {
    match credential_store.add_user("testuser".to_string(), "testpass".to_string()).await {
        Ok(user_id) => {
            tracing::info!("Test user created successfully with ID: {}", user_id);
        }
        Err(AuthError::DuplicateUsername(_)) => {
            tracing::debug!("Test user already exists, skipping creation");
        }
        Err(e) => {
            tracing::error!("Failed to create test user: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();
    
    // Initialize logging
    init_logging().expect("Failed to initialize logging");
    
    // Initialize AppData (databases, stores, stateless services)
    let app_data = Arc::new(
        AppData::init().await
            .expect("Failed to initialize application data")
    );
    
    // Check if CLI arguments are present
    let args: Vec<String> = std::env::args().collect();
    
    // If CLI arguments present (more than just the binary name), run CLI mode
    if args.len() > 1 {
        // Parse CLI arguments
        let cli = cli::Cli::parse();
        
        // Execute CLI command
        match cli::execute_command(cli, &app_data).await {
            Ok(()) => {
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
    
    // No CLI arguments - run server mode
    
    // Create auth service from AppData
    let auth_service = Arc::new(services::AuthService::new(app_data.clone()));
    
    // Create admin service from AppData
    let admin_service = Arc::new(services::AdminService::new(app_data.clone()));
    
    // Seed test user in debug mode
    #[cfg(debug_assertions)]
    seed_test_user(&app_data.credential_store).await;
    
    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);
    
    // Create AuthApi with AuthService (uses auth service's internal token service)
    let auth_api = AuthApi::new(auth_service.clone());
    
    // Create AdminApi with AdminService
    let admin_api = AdminApi::new(admin_service);
    
    // Create OpenAPI service with API implementation
    // Use localhost for the server URL since 0.0.0.0 is not accessible from browsers
    let server_url = format!("http://localhost:{}/api", port);
    let api_service = OpenApiService::new((HealthApi, auth_api, admin_api), "Linkstash RS auth backend", "1.0.0")
        .server(server_url);
    
    // Generate Swagger UI from OpenAPI service
    let swaggerui = api_service.swagger_ui();
    
    // Handler for root path serving static HTML
    #[handler]
    fn index() -> Html<&'static str> {
        Html(include_str!("../static/index.html"))
    }
    
    // Compose routes: nest API service under /api and Swagger UI under /swagger
    let app = Route::new()
        .at("/", poem::get(index))
        .nest("/api", api_service)
        .nest("/swagger", swaggerui);
    
    // Configure TCP listener    
    let listener =  TcpListener::bind(&bind_address);
    
    // Configure TCP listener
    tracing::info!("Starting server on http://{}", bind_address);
    tracing::info!("Swagger UI available at http://localhost:{}/swagger", port);

    // Start Poem server with composed routes
    Server::new(listener)
        .run(app)
        .await
}
