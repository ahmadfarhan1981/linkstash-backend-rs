mod api;
mod config;
mod types;
mod errors;
mod stores;
mod services;

use poem::{listener::TcpListener, Route, Server};
use poem_openapi::OpenApiService;
use api::{HealthApi, AuthApi};
use stores::CredentialStore;
use services::TokenService;
use config::{SecretManager, LoggingConfig, init_logging};
use errors::auth::AuthError;
use sea_orm::{Database, DatabaseConnection};
use migration::{Migrator, MigratorTrait};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();
    
    // Initialize application logging
    let logging_config = LoggingConfig::from_env();
    init_logging(&logging_config)
        .expect("Failed to initialize logging");
    
    tracing::info!("Application logging initialized with level: {}", logging_config.log_level);
    
    // Load database URL from environment or use default
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
    
    // Connect to database
    let db: DatabaseConnection = Database::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    tracing::info!("Connected to database: {}", database_url);
    
    // Run migrations
    Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations");
    
    tracing::info!("Database migrations completed");
    
    // Load audit database URL from environment or use default
    let audit_db_path = std::env::var("AUDIT_DB_PATH")
        .unwrap_or_else(|_| "audit.db".to_string());
    let audit_database_url = format!("sqlite://{}?mode=rwc", audit_db_path);
    
    // Connect to audit database with separate connection pool
    let audit_db: DatabaseConnection = Database::connect(&audit_database_url)
        .await
        .expect("Failed to connect to audit database");
    
    tracing::info!("Connected to audit database: {}", audit_database_url);
    
    // Run migrations on audit database
    Migrator::up(&audit_db, None)
        .await
        .expect("Failed to run audit database migrations");
    
    tracing::info!("Audit database migrations completed");
    
    // Initialize SecretManager
    let secret_manager = std::sync::Arc::new(
        SecretManager::init()
            .expect("Failed to initialize secrets. Please ensure all required environment variables are set with valid values.")
    );
    
    // Create TokenService with JWT secret and refresh token secret from SecretManager
    let token_manager = std::sync::Arc::new(TokenService::new(
        secret_manager.jwt_secret().to_string(),
        secret_manager.refresh_token_secret().to_string(),
    ));
    
    // Create CredentialStore with password_pepper from SecretManager
    let credential_store = std::sync::Arc::new(CredentialStore::new(
        db.clone(),
        secret_manager.password_pepper().to_string()
    ));
    
    // Create AuditStore with audit database connection
    let audit_store = std::sync::Arc::new(stores::AuditStore::new(audit_db.clone()));
    
    // Create AuthService (orchestrator for authentication flows)
    let auth_service = std::sync::Arc::new(services::AuthService::new(
        credential_store.clone(),
        token_manager.clone(),
        audit_store.clone(),
    ));
    
    // TODO: This is temporary - seed test user for development
    // Seed test user if not exists (username: "testuser", password: "testpass")
    match credential_store.add_user("testuser".to_string(), "testpass".to_string()).await {
        Ok(user_id) => {
            tracing::info!("Test user created successfully with ID: {}", user_id);
        }
        Err(AuthError::DuplicateUsername(_)) => {
            // If user already exists, that's fine - just log it
            tracing::debug!("Test user already exists, skipping creation");
        }
        Err(AuthError::InternalError(e)) => {
            tracing::error!("Failed to create test user: {:?}", e);
        }
        Err(e) => {
            tracing::error!("Failed to create test user: {:?}", e);
        }
    }
    
    // Create AuthApi with AuthService and TokenService
    let auth_api = AuthApi::new(auth_service.clone(), token_manager.clone());
    
    // Create OpenAPI service with API implementation
    let api_service = OpenApiService::new((HealthApi, auth_api), "Swagger API Generation", "1.0.0")
        .server("http://localhost:3000/api");
    
    // Generate Swagger UI from OpenAPI service
    let ui = api_service.swagger_ui();
    
    // Compose routes: nest API service under /api and Swagger UI under /swagger
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/swagger", ui);
    
    // Load server configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_address = format!("{}:{}", host, port);
    
    // Configure TCP listener
    tracing::info!("Starting server on http://{}", bind_address);
    tracing::info!("Swagger UI available at http://localhost:{}/swagger", port);
    tracing::info!("API endpoints available at http://localhost:{}/api", port);
    
    // Start Poem server with composed routes
    Server::new(TcpListener::bind(&bind_address))
        .run(app)
        .await
}
