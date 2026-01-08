use clap::Parser;
use linkstash_backend::AppData;
use linkstash_backend::config::BootstrapSettings;
use linkstash_backend::config::database::DatabaseConnections;
use linkstash_backend::config::init_logging;
use linkstash_backend::coordinators::LoginCoordinator;
use poem::{Server, listener::TcpListener};
use std::sync::Arc;

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

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let bootstrap_settings =
        linkstash_backend::init_bootstrap_settings().expect("Failed to load bootstrap settings");

    // Initialize logging
    init_logging().expect("Failed to initialize logging");

    

    // If CLI mode, execute command and exit
    // if let Some(cli) = cli_parsed {

    //     // Check if this is the migrate command - exit successfully since migrations are done
    //     if matches!(cli.command, cli::Commands::Migrate) {
    //         std::process::exit(0);
    //     }

    //     // For other CLI commands, initialize AppData with the migrated connections
    //     let app_data = Arc::new(
    //         AppData::init(connections).await
    //             .map_err(|e| format!("Failed to initialize application data: {}", e))
    //             .expect("Failed to initialize application data")
    //     );

    //     // Execute CLI command
    //     match cli::execute_command(cli, &app_data).await {
    //         Ok(()) => {
    //             std::process::exit(0);
    //         }
    //         Err(e) => {
    //             eprintln!("Error: {}", e);
    //             std::process::exit(1);
    //         }
    //     }
    // }

    // No CLI arguments - run server mode
    // TODO logging and error handling
    let app_data = Arc::new(
         linkstash_backend::init_appdata(&bootstrap_settings)
            .await
            .map_err(|e| format!("Failed to initialize application data: {}", e))
            .expect("Failed to initialize application data"),
    );


    // Create coordinators using AppData pattern
    // let auth_coordinator = Arc::new(coordinators::AuthCoordinator::new(app_data.clone()));
    // let admin_coordinator = Arc::new(coordinators::AdminCoordinator::new(app_data.clone()));
    //let auth_coordinator = Arc::new(LoginCoordinator::new(app_data.clone()));

    // Seed test user in debug mode
    #[cfg(debug_assertions)]
    seed_test_user(&app_data).await;

    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);

    let app = linkstash_backend::get_routes(app_data).await?;

    // Configure TCP listener
    let listener = TcpListener::bind(&bind_address);

    // Configure TCP listener
    tracing::info!("Starting server on http://{}", bind_address);
    tracing::info!("Swagger UI available at http://{}/swagger", bind_address);

    // Start Poem server with composed routes
    Server::new(listener).run(app).await
}
