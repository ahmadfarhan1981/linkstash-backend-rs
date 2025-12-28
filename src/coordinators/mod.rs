// Coordinators layer - Workflow orchestration
// 
// Coordinators handle pure workflow orchestration by composing provider operations
// for specific API endpoints. They determine the sequence of operations without
// containing business logic themselves.

// Coordinator modules
// pub mod auth_coordinator;
// pub mod admin_coordinator;
pub mod login_coordinator;
// Re-export coordinators for clean imports
// pub use auth_coordinator::AuthCoordinator;
// pub use admin_coordinator::AdminCoordinator;
pub use login_coordinator::LoginCoordinator;