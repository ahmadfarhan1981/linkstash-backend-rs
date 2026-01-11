use std::sync::Arc;

use crate::{audit::AuditLogger, config::database::DatabaseConnections, coordinators::Coordinator, providers::TokenProvider, stores::user_store::UserStore};

/***
 * This coordinator handles user lifecycle related operations
 */
pub struct UserCoordinator {
    audit_logger: Arc<AuditLogger>,
    token_provider: Arc<TokenProvider>,
    user_store: Arc<UserStore>,
    connections: DatabaseConnections,
}

impl Coordinator for UserCoordinator {
    fn get_logger(&self) -> &Arc<AuditLogger> {
        &self.audit_logger
    }
}

impl UserCoordinator {
    
    
}