#[derive(Debug, thiserror::Error)]
pub enum CryptoError {

    #[error("crypto failure during {operation}")]
    Other {
        operation: &'static str,
        component: &'static str,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl CryptoError {
    pub fn other<E>(
        component: &'static str,
        operation: &'static str,
        err: E,
    ) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other {
            component,
            operation,
            source: Box::new(err),
        }
    }
}
