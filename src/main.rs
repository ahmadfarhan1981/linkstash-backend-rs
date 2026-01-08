use clap::Parser;
use linkstash_backend::AppData;
use linkstash_backend::config::BootstrapSettings;
use linkstash_backend::config::database::DatabaseConnections;
use linkstash_backend::config::init_logging;
use linkstash_backend::coordinators::LoginCoordinator;
use poem::{Server, listener::TcpListener};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let bootstrap_settings =
        linkstash_backend::init_bootstrap_settings().expect("Failed to load bootstrap settings");

    // Initialize logging
    init_logging().expect("Failed to initialize logging");

    // No CLI arguments - run server mode
    // TODO logging and error handling
    let app_data = Arc::new(
        linkstash_backend::init_appdata(&bootstrap_settings)
            .await
            .expect("Failed to initialize application data"),
    );

    match linkstash_backend::run_cli_commands(&app_data).await {
        linkstash_backend::CLIResult::Executed(return_code) => std::process::exit(return_code.0),
        linkstash_backend::CLIResult::NotExecuted => {}
    }

    //configure routes
    let routes = linkstash_backend::get_routes(app_data).await?;

    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);
    // Configure TCP listener
    let listener = TcpListener::bind(&bind_address);
    tracing::info!("Starting server on http://{}", bind_address);
    tracing::info!("Swagger UI available at http://{}/swagger", bind_address);

    // Start Poem server with composed routes
    Server::new(listener).run(routes).await
}
