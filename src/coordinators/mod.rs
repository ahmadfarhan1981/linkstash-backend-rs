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


// pub async fn execute<T>(
//     ctx: &RequestContext,
//     audit: &AuditLogger,
//     res: Result<ActionOutcome<T>, InternalError>,
// ) -> Result<T, ApplicationError> {
//     match res {
//         Ok(out) => {
//             audit.emit_all(ctx, &out.audit).await;
//             Ok(out.value)
//         }
//         Err(err) => {
//             audit.emit_all(ctx, &err.audit_intents()).await;
//             Err(err.into())
//         }
//     }
// }

// pub struct ActionOutcome<T> {
//     pub value: T,
//     pub audit: Vec<AuditIntent>,
// }