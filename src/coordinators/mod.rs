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

use std::{future::Future, sync::Arc};

use crate::{
    audit::AuditLogger,
    config::ApplicationError,
    errors::InternalError,
    types::internal::{
        action_outcome::ActionOutcome,
        audit_intent::AuditIntent,
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

pub trait Coordinator{
    fn get_logger (&self)-> &Arc<AuditLogger>;

    fn exec(&self, ctx: &RequestContext) -> Exec {
        Exec {
            ctx: ctx.clone(),
            audit: Arc::clone(self.get_logger()),
        }
    }
}