use crate::audit::AuditLogger;
use crate::config::database::DatabaseConnections;
use crate::config::ApplicationError;
use crate::coordinators::Coordinator;
use crate::stores::authentication_store::AuthenticationStore;
use crate::stores::authorization_store::AuthorizationStore;
use crate::stores::user_store::{UserId, UserStore, UserToCreate};
use crate::types::dto::auth::LoginApiResponse;
use crate::types::internal::RequestContextMeta;
use std::sync::Arc;
use uuid::Uuid;

pub struct OwnerCoordinator {
    audit_logger: Arc<AuditLogger>,
    user_store: Arc<UserStore>,
    connections: DatabaseConnections,
    authentication_store: Arc<AuthenticationStore>,
    authorization_store: Arc<AuthorizationStore>,

}

impl Coordinator for OwnerCoordinator {
    fn get_logger(&self) -> &Arc<AuditLogger> {
        &self.audit_logger
    }
}

impl OwnerCoordinator {
    pub async fn create_owner(
        &self,
        context_meta: RequestContextMeta,
        username: String,
        password: String,
    ) -> Result<LoginApiResponse, ApplicationError> {
        let new_uuid = Uuid::new_v4().to_string();
        let owner_to_create = UserToCreate {
            id: UserId::new(),
            username,
        };
        self.user_store.create_user()
        // self.authorization_store.set_permissions()
        // self.authorization_store.change_password()
    }
}