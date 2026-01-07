use crate::errors::AuthError;

use super::request_context::RequestContext;

/// Result type for create_request_context that can carry context in error
pub enum ContextResult {
    /// Context created successfully, no password change required
    Ok(RequestContext),
    /// Password change required - context is included so allowed endpoints can extract it
    PasswordChangeRequired(RequestContext),
}

impl ContextResult {
    /// Convert ContextResult to Result, mapping PasswordChangeRequired to an error
    ///
    /// Most endpoints should use this to automatically reject users with password_change_required=true.
    ///
    /// # Returns
    /// * `Ok(ctx)` - Context ready to use
    /// * `Err(AuthError::PasswordChangeRequired)` - User must change password first
    pub fn into_result(self) -> Result<RequestContext, AuthError> {
        match self {
            ContextResult::Ok(ctx) => Ok(ctx),
            ContextResult::PasswordChangeRequired(_) => Err(AuthError::password_change_required()),
        }
    }

    /// Extract the context regardless of whether password change is required
    ///
    /// Only use this for endpoints that should remain accessible when password change is required
    /// (/auth/change-password, /auth/whoami).
    ///
    /// # Returns
    /// The RequestContext
    pub fn into_context(self) -> RequestContext {
        match self {
            ContextResult::Ok(ctx) => ctx,
            ContextResult::PasswordChangeRequired(ctx) => ctx,
        }
    }
}