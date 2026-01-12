use std::sync::Arc;

use crate::config::ApplicationError;
use crate::providers::user_provider::UserProvider;
use crate::{
    AppData, audit::AuditLogger, config::database::DatabaseConnections, coordinators::Coordinator,
    providers::TokenProvider, stores::user_store::UserStore,
};
use crate::types::internal::{RequestContext, RequestContextMeta};
/***
 * This coordinator handles user lifecycle related operations
 */
pub struct UserCoordinator {
    audit_logger: Arc<AuditLogger>,
    token_provider: Arc<TokenProvider>,
    user_provider: Arc<UserProvider>,
    connections: DatabaseConnections,
}

impl Coordinator for UserCoordinator {
    fn get_logger(&self) -> &Arc<AuditLogger> {
        &self.audit_logger
    }
}

impl UserCoordinator {
    pub fn new(app_data: Arc<AppData>) -> Self {
        Self {
            audit_logger: Arc::clone(&app_data.audit_logger),
            token_provider: Arc::clone(&app_data.providers.token_provider),
            user_provider: Arc::clone(&app_data.providers.user_provider),
            connections: app_data.connections.clone(),
        }
    }
    pub async fn create_user( &self,
                              context_meta: RequestContextMeta,
                              username: String,
                              password: String,) -> Result<(), ApplicationError> {

        let ctx = &RequestContext::from_context_meta(context_meta, token_provider)
        let exec = self.exec(ctx)
        let conn = self.connections.begin_auth_transaction().await?;
        //checks if user exists
        let user_exists = self.user_provider.user_exists(&conn, &username).await?;
        //hash password
        // future: validate pass
        //creata
        // set pass
        // set auth 
        Ok(())
    }
}
