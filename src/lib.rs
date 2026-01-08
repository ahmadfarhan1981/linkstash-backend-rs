// Library exports for integration tests and external use

pub mod api;
pub mod app_data;
pub mod audit;
pub mod cli;
pub mod config;
pub mod coordinators;
pub mod errors;
pub mod providers;
pub mod stores;
pub mod types;
use std::sync::Arc;

pub use app_data::AppData;
use clap::Parser;
use poem::{Route, handler, web::Html};
use poem_openapi::OpenApiService;

use crate::{
    api::{AdminApi, AuthApi, HealthApi},
    config::{ApplicationError, BootstrapSettings, database::DatabaseConnections}, errors::InternalError,
};

// Test utilities (available for unit and integration tests)
// Note: Compiled in all builds but only used during testing
#[cfg(any(test, feature = "test-utils"))]
pub mod test;

/// Seed test user for development
///
/// Only runs in debug builds. Creates a test user with username "testuser"
/// and password "TestSecure-Pass-12345-UUID" for development and testing purposes.
#[cfg(debug_assertions)]
async fn seed_test_user(app_data: &AppData) {
    // Create password validator from AppData stores
    // let password_validator = std::sync::Arc::new(providers::PasswordValidatorProvider::new(
    //     app_data.common_password_store.clone(),
    //     app_data.hibp_cache_store.clone(),
    // ));

    // match app_data.credential_store.add_user(&password_validator, "testuser".to_string(), "TestSecure-Pass-12345-UUID".to_string()).await {
    //     Ok(user_id) => {
    //         tracing::info!("Test user created successfully with ID: {}", user_id);
    //     }
    //     Err(InternalError::Credential(CredentialError::DuplicateUsername(_))) => {
    //         tracing::debug!("Test user already exists, skipping creation");
    //     }
    //     Err(e) => {
    //         tracing::error!("Failed to create test user: {:?}", e);
    //     }
    // }
}

pub async fn init_appdata(bootstrap_settings: &BootstrapSettings) -> Result<AppData, InternalError> {
    tracing::info!("connecting to database...");
    let connections =
        DatabaseConnections::init(&bootstrap_settings).expect("Failed to connect to database");
    tracing::info!("Running database migrations...");
    connections
        .migrate()
        .await
        .expect("Failed to run migrations");
    tracing::info!("Finished database migrations.");

    AppData::init(connections).await
    
}

pub fn init_bootstrap_settings() -> Result<BootstrapSettings, ApplicationError> {
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
    let env_file = cli_parsed
        .as_ref()
        .map(|c| c.env_file.as_str())
        .unwrap_or(".env");
    dotenv::from_filename(env_file).ok();

    BootstrapSettings::from_env()
}

pub struct ReturnCode(pub i32);
pub enum CLIResult {
    Executed(ReturnCode),
    NotExecuted,
    
    
}
pub async fn run_cli_commands(app_data: &AppData)->CLIResult{
    let args: Vec<String> = std::env::args().collect();
    let cli  = cli::Cli::parse();
    println!("{:?}",cli.command);
    
    if let Some(command) = cli.command {        
        // Execute CLI command
        match cli::execute_command(command, app_data).await {
            Ok(()) => {
                CLIResult::Executed(ReturnCode(0))
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                CLIResult::Executed(ReturnCode(1))
            }
        }
    } else {
        CLIResult::NotExecuted
    }

}

pub async fn get_routes(app_data: Arc<AppData>) -> Result<Route, std::io::Error> {
    // No CLI arguments - run server mode

    // Create coordinators using AppData pattern
    // let auth_coordinator = Arc::new(coordinators::AuthCoordinator::new(app_data.clone()));
    // let admin_coordinator = Arc::new(coordinators::AdminCoordinator::new(app_data.clone()));
    let auth_coordinator = Arc::new(coordinators::LoginCoordinator::new(app_data.clone()));

    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);

    // Create AuthApi with AuthCoordinator
    let auth_api = AuthApi::new(Arc::clone(&app_data));

    // Create AdminApi with AdminCoordinator
    let admin_api = AdminApi::new();

    // Create OpenAPI service with API implementation
    // Use localhost for the server URL since 0.0.0.0 is not accessible from browsers
    let server_url = format!("http://localhost:{}/api", port);
    let api_service = OpenApiService::new(
        (HealthApi, auth_api, admin_api),
        "Linkstash RS auth backend",
        "1.0.0",
    )
    .server(server_url);

    // Generate Swagger UI from OpenAPI service
    let swaggerui = api_service.swagger_ui();

    // Handler for root path serving static HTML
    #[handler]
    fn index() -> Html<&'static str> {
        Html(include_str!("../static/index.html"))
    }

    // Compose routes: nest API service under /api and Swagger UI under /swagger
    let route = Route::new()
        .at("/", poem::get(index))
        .nest("/api", api_service)
        .nest("/swagger", swaggerui);
    Ok(route)
}
