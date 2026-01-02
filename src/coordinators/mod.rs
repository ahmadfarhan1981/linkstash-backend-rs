// Coordinators layer - Workflow orchestration
//
// Coordinators handle pure workflow orchestration by composing provider operations
// for specific API endpoints. They determine the sequence of operations without
// containing business logic themselves.

// Coordinator modules
// pub mod auth_coordinator;
// pub mod admin_coordinator;
pub mod login_coordinator;
use std::{collections::HashMap, sync::Arc};

// Re-export coordinators for clean imports
// pub use auth_coordinator::AuthCoordinator;
// pub use admin_coordinator::AdminCoordinator;
pub use login_coordinator::LoginCoordinator;

use crate::{
    audit::AuditLogger,
    config::ApplicationError,
    errors::InternalError,
    types::internal::{
        audit::{AuditEvent, EventType},
        context::RequestContext,
    },
};

pub async fn execute<T>(
    ctx: &RequestContext,
    audit: &Arc<AuditLogger>,
    res: Result<ActionOutcome<T>, InternalError>,
) -> Result<T, ApplicationError> {
    match res {
        Ok(out) => {
            // audit.emit_all(ctx, &out.audit).await;
            Ok(out.value)
        }
        Err(err) => {
            // audit.emit_all(ctx, &err.audit_intents()).await;
            // log errors
            Err(err.into())
        }
    }
}

pub struct ActionOutcome<T> {
    pub value: T,
    pub audit: Vec<AuditIntent>,
}

pub struct AuditIntent {
    pub event_type: EventType,
    pub data: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}



// use std::{future::Future, sync::Arc};

#[derive(Clone)]
pub struct Exec {
    ctx: RequestContext,
    audit: Arc<AuditLogger>,
}

impl Exec {
    pub fn new(ctx: &RequestContext, audit: Arc<AuditLogger>) -> Self {
        Self {
            ctx: ctx.clone(),
            audit,
        }
    }

    /// Call your existing execute() with an already-awaited result.
    pub async fn res<T>(
        &self,
        res: Result<ActionOutcome<T>, InternalError>,
    ) -> Result<T, ApplicationError> {
        execute(&self.ctx, &self.audit, res).await
    }

    /// Call your existing execute() with a future that resolves to the result.
    pub async fn fut<F, T>(&self, fut: F) -> Result<T, ApplicationError>
    where
        F: Future<Output = Result<ActionOutcome<T>, InternalError>>,
    {
        execute(&self.ctx, &self.audit, fut.await).await
    }
}
