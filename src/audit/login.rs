use serde_json::json;
use crate::errors::InternalError;
use crate::types::internal::audit::{AuditEvent, EventType};
use crate::types::internal::context::RequestContext;
use super::AuditLogger;
impl AuditLogger{
    /// Log a successful login event
    ///
    /// # Arguments
    /// * `ctx` - Request context containing actor information
    /// * `target_user_id` - ID of the user who logged in (target of the action)
    pub async fn log_login_success(
        &self,
        ctx: &RequestContext,
        target_user_id: String,
    ) -> Result<(), InternalError> {
        let mut event = AuditEvent::new(EventType::LoginSuccess);
        event.user_id = Some(ctx.actor_id.clone());
        event.ip_address = ctx.ip_address.clone();
        event.jwt_id = ctx.claims.as_ref().and_then(|c| c.jti.clone());
        event.data.insert("target_user_id".to_string(), json!(target_user_id));
        event.data.insert("request_id".to_string(), json!(ctx.request_id.clone()));

        self.audit_store.write_event(event).await
    }
}