mod api;
mod app_data;
mod config;
mod types;
mod errors;
mod stores;
mod coordinators;
mod providers;
mod cli;
mod audit;

use std::sync::Arc;
use config::BootstrapSettings;
use poem::{Route, Server, handler, listener::TcpListener, web::Html};
use poem_openapi::OpenApiService;
use api::{HealthApi, AuthApi, AdminApi};
use app_data::AppData;
use config::init_logging;
use clap::Parser;
use errors::InternalError;
use errors::internal::CredentialError;
use config::database::DatabaseConnections;

/// Seed test user for development
/// 
/// Only runs in debug builds. Creates a test user with username "testuser"
/// and password "TestSecure-Pass-12345-UUID" for development and testing purposes.
#[cfg(debug_assertions)]
async fn seed_test_user(app_data: &AppData) {
    // Create password validator from AppData stores
    let password_validator = std::sync::Arc::new(providers::PasswordValidatorProvider::new(
        app_data.common_password_store.clone(),
        app_data.hibp_cache_store.clone(),
    ));
    
    match app_data.credential_store.add_user(&password_validator, "testuser".to_string(), "TestSecure-Pass-12345-UUID".to_string()).await {
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
    
    let bootstrap_setting = BootstrapSettings::from_env().expect("Failed to load bootstrap settings");

    // Initialize logging
    init_logging().expect("Failed to initialize logging");

    tracing::info!("connecting to database...");
    let connections = DatabaseConnections::init(&bootstrap_setting).expect("Failed to connect to database");
    tracing::info!("Running database migrations...");
    connections.migrate().await.expect("Failed to run migrations");
    tracing::info!("Finished database migrations.");


    // If CLI mode, execute command and exit
    if let Some(cli) = cli_parsed {
        
        // Check if this is the migrate command - exit successfully since migrations are done
        if matches!(cli.command, cli::Commands::Migrate) {
            std::process::exit(0);
        }
        
        // For other CLI commands, initialize AppData with the migrated connections
        let app_data = Arc::new(
            AppData::init(connections).await
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
        AppData::init(connections).await
            .map_err(|e| format!("Failed to initialize application data: {}", e))
            .expect("Failed to initialize application data")
    );
    
    // No CLI arguments - run server mode
    
    // Create coordinators using AppData pattern
    let auth_coordinator = Arc::new(coordinators::AuthCoordinator::new(app_data.clone()));
    let admin_coordinator = Arc::new(coordinators::AdminCoordinator::new(app_data.clone()));
    
    // Seed test user in debug mode
    #[cfg(debug_assertions)]
    seed_test_user(&app_data).await;
    
    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);
    
    // Create AuthApi with AuthCoordinator
    let auth_api = AuthApi::new(auth_coordinator);
    
    // Create AdminApi with AdminCoordinator
    let admin_api = AdminApi::new(admin_coordinator);
    
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
