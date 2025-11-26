mod api;
mod config;
mod types;
mod errors;
mod stores;
mod services;
mod cli;


use poem::{Route, Server, handler, listener::TcpListener, web::Html};
use poem_openapi::OpenApiService;
use api::{HealthApi, AuthApi};
use config::{SecretManager, init_logging, init_database, init_audit_database};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();
    
    // Initialize logging
    init_logging().expect("Failed to initialize logging");
    
    // Initialize databases
    let db = init_database().await?;
    let audit_db = init_audit_database().await?;
    
    // Check if CLI arguments are present
    let args: Vec<String> = std::env::args().collect();
    
    // If CLI arguments present (more than just the binary name), run CLI mode
    if args.len() > 1 {
        // Initialize secrets for CLI mode
        let secret_manager = SecretManager::init()
            .expect("Failed to initialize secrets. Please ensure all required environment variables are set with valid values.");
        
        // Parse CLI arguments
        let cli = cli::Cli::parse();
        
        // Execute CLI command
        match cli::execute_command(cli, &db, &audit_db, &secret_manager).await {
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
    
    // Initialize secrets
    let secret_manager = std::sync::Arc::new(
        SecretManager::init()
            .expect("Failed to initialize secrets. Please ensure all required environment variables are set with valid values.")
    );
    
    // Initialize auth service (creates all internal dependencies)
    let auth_service = std::sync::Arc::new(
        services::AuthService::init(db, audit_db, secret_manager.clone())
            .await
            .expect("Failed to initialize auth service")
    );
    
    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);
    
    // Create AuthApi with AuthService (uses auth service's internal token service)
    let auth_api = AuthApi::new(auth_service.clone());
    
    // Create OpenAPI service with API implementation
    // Use localhost for the server URL since 0.0.0.0 is not accessible from browsers
    let server_url = format!("http://localhost:{}/api", port);
    let api_service = OpenApiService::new((HealthApi, auth_api), "Linkstash RS auth backend", "1.0.0")
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
