mod api;
mod types;
mod errors;
mod stores;
mod services;

use poem::{listener::TcpListener, Route, Server};
use poem_openapi::OpenApiService;
use api::{HealthApi, AuthApi};
use stores::CredentialStore;
use services::TokenService;
use errors::auth::AuthError;
use sea_orm::{Database, DatabaseConnection};
use migration::{Migrator, MigratorTrait};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();
    
    // Load database URL from environment or use default
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://auth.db?mode=rwc".to_string());
    
    // Connect to database
    let db: DatabaseConnection = Database::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    println!("Connected to database: {}", database_url);
    
    // Run migrations
    Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations");
    
    println!("Database migrations completed");
    
    // Load JWT secret from environment
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET environment variable must be set");
    
    // Create TokenService
    let token_manager = std::sync::Arc::new(TokenService::new(jwt_secret));
    
    // TODO: This is temporary - seed test user for development
    // Seed test user if not exists (username: "testuser", password: "testpass")
    let credential_store = std::sync::Arc::new(CredentialStore::new(db.clone()));
    match credential_store.add_user("testuser".to_string(), "testpass".to_string()).await {
        Ok(user_id) => {
            println!("Test user created successfully with ID: {}", user_id);
        }
        Err(AuthError::DuplicateUsername(_)) => {
            // If user already exists, that's fine - just log it
            println!("Test user already exists, skipping creation");
        }
        Err(AuthError::InternalError(e)) => {
            println!("Failed to create test user: {:?}", e);
        }
        Err(e) => {
            println!("Failed to create test user: {:?}", e);
        }
    }
    
    // Create AuthApi with CredentialStore and TokenService
    let auth_api = AuthApi::new(credential_store.clone(), token_manager.clone());
    
    // Create OpenAPI service with API implementation
    let api_service = OpenApiService::new((HealthApi, auth_api), "Swagger API Generation", "1.0.0")
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
