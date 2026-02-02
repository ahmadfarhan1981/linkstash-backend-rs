use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::errors::InternalError;
use crate::errors::internal::AuditError;
use crate::types::db::audit_event;
use crate::types::internal::audit::AuditEvent;

pub struct AuditStore;

impl AuditStore {
    pub fn new() -> Self {
        Self
    }

    pub async fn write_event(&self, conn: &impl ConnectionTrait, event: AuditEvent) -> Result<(), InternalError> {
        let data_json = serde_json::to_string(&event.data).map_err(|e| {
            AuditError::LogWriteFailed(format!("Failed to serialize audit data: {}", e))
        })?;

        let audit_event = audit_event::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            timestamp: Set(event.timestamp),
            event_type: Set(event.event_type.to_string()),
            user_id: Set(event.user_id),
            ip_address: Set(event.ip_address),
            jwt_id: Set(event.jwt_id),
            data: Set(data_json),
        };

        audit_event
            .insert(db)
            .await
            .map_err(|e| InternalError::database("write_audit_event", e))?;

        Ok(())
    }
}
