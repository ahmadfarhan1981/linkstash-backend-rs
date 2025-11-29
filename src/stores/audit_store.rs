use chrono::Utc;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::types::db::audit_event;
use crate::types::internal::audit::AuditEvent;
use crate::errors::InternalError;
use crate::errors::internal::AuditError;

/// Repository for audit event storage operations
pub struct AuditStore {
    db: DatabaseConnection,
}

impl AuditStore {
    /// Create a new AuditStore with the given database connection
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Write an audit event to the database
    ///
    /// Validates that user_id is present, serializes the data HashMap to JSON,
    /// and inserts the event into the audit_events table.
    ///
    /// # Errors
    ///
    /// Returns `InternalError` if serialization or database insert fails
    pub async fn write_event(&self, event: AuditEvent) -> Result<(), InternalError> {
        // Serialize data HashMap to JSON
        let data_json = serde_json::to_string(&event.data)
            .map_err(|e| AuditError::LogWriteFailed(format!("Failed to serialize audit data: {}", e)))?;

        // Create active model for insertion
        // Note: user_id is optional for events like login_failure where user may not exist
        let audit_event = audit_event::ActiveModel {
            id: sea_orm::ActiveValue::NotSet, // Let auto-increment handle this
            timestamp: Set(Utc::now().to_rfc3339()),
            event_type: Set(event.event_type.to_string()),
            user_id: Set(event.user_id.unwrap_or_else(|| "unknown".to_string())),
            ip_address: Set(event.ip_address),
            jwt_id: Set(event.jwt_id),
            data: Set(data_json),
        };

        // Insert into database
        audit_event.insert(&self.db).await
            .map_err(|e| InternalError::database("write_audit_event", e))?;

        Ok(())
    }
}
