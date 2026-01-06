use super::AuditLogger;
use crate::errors::InternalError;
use crate::types::internal::audit::{AuditEvent, EventType};
use crate::types::internal::context::RequestContext;
use serde_json::json;

impl AuditLogger {
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
        event.user_id = ctx.actor_id.clone();
        event.ip_address = ctx
            .ip_address
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        event.jwt_id = ctx
            .claims
            .as_ref()
            .map(|c| c.jti.clone())
            .unwrap_or_else(|| "none".to_string());
        event
            .data
            .insert("target_user_id".to_string(), json!(target_user_id));
        event
            .data
            .insert("request_id".to_string(), json!(ctx.request_id.clone()));

        self.audit_store.write_event(event).await
    }
}
