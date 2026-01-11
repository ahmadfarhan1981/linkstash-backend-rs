#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    
    #[error("Encode JWT failure in {component} during {operation}: {message}")]
    EncodeJWT{
        operation: &'static str,
        component: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        message: String,
    },

    #[error("crypto failure in {component} during {operation}: {message}")]
    Other {
        operation: &'static str,
        component: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        message: String,
    },
}

impl CryptoError {
    pub fn other_from_error<E>(
        component: &'static str,
        operation: &'static str,
        err: E,
    ) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let message = err.to_string();
        Self::Other {
            component,
            operation,
            source: Some(Box::new(err)),
            message,
        }
    }

    pub fn other_from_string(
        component: &'static str,
        operation: &'static str,
        error_message: String,
    ) -> Self
    {
        
        Self::Other {
            component,
            operation,
            source: None,
            message: error_message,
        }
    }
}
