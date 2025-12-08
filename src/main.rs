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
use errors::InternalError;
use errors::internal::CredentialError;

/// Seed test user for development
/// 
/// Only runs in debug builds. Creates a test user with username "testuser"
/// and password "TestSecure-Pass-12345-UUID" for development and testing purposes.
#[cfg(debug_assertions)]
async fn seed_test_user(app_data: &AppData) {
    match app_data.credential_store.add_user(&app_data.password_validator, "testuser".to_string(), "TestSecure-Pass-12345-UUID".to_string()).await {
        Ok(user_id) => {
            tracing::info!("Test user created successfully with ID: {}", user_id);
        }
        Err(InternalError::Credential(CredentialError::DuplicateUsername(_))) => {
            tracing::debug!("Test user already exists, skipping creation");
        }
        Err(e) => {
            tracing::error!("Failed to create test user: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Check if CLI arguments are present
    let args: Vec<String> = std::env::args().collect();
    let is_cli_mode = args.len() > 1;
    
    // Parse CLI once if in CLI mode, otherwise use default env file
    let cli_parsed = if is_cli_mode {
        Some(cli::Cli::parse())
    } else {
        None
    };
    
    // Load environment variables from specified file
    let env_file = cli_parsed.as_ref()
        .map(|c| c.env_file.as_str())
        .unwrap_or(".env");
    dotenv::from_filename(env_file).ok();
    
    // Initialize logging
    init_logging().expect("Failed to initialize logging");
    
    // Initialize database connections and run migrations
    tracing::info!("Initializing database connections...");
    let db = config::init_database().await
        .expect("Failed to connect to auth database");
    let audit_db = config::init_audit_database().await
        .expect("Failed to connect to audit database");
    
    tracing::info!("Running database migrations...");
    config::migrate_auth_database(&db).await
        .expect("Failed to run auth database migrations");
    config::migrate_audit_database(&audit_db).await
        .expect("Failed to run audit database migrations");
    tracing::info!("Database migrations completed successfully");
    
    // If CLI mode, execute command and exit
    if let Some(cli) = cli_parsed {
        
        // Check if this is the migrate command - exit successfully since migrations are done
        if matches!(cli.command, cli::Commands::Migrate) {
            std::process::exit(0);
        }
        
        // For other CLI commands, initialize AppData with the migrated connections
        let app_data = Arc::new(
            AppData::init(db, audit_db).await
                .map_err(|e| format!("Failed to initialize application data: {}", e))
                .expect("Failed to initialize application data")
        );
        
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
    // Initialize AppData with the migrated connections
    let app_data = Arc::new(
        AppData::init(db, audit_db).await
            .map_err(|e| format!("Failed to initialize application data: {}", e))
            .expect("Failed to initialize application data")
    );
    
    // No CLI arguments - run server mode
    
    // Create auth service from AppData
    let auth_service = Arc::new(services::AuthService::new(app_data.clone()));
    
    // Create admin service from AppData
    let admin_service = Arc::new(services::AdminService::new(app_data.clone()));
    
    // Seed test user in debug mode
    #[cfg(debug_assertions)]
    seed_test_user(&app_data).await;
    
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
