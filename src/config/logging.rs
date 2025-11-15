use std::env;
use std::path::PathBuf;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Configuration for application logging
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub log_level: String,
    pub app_log_file: Option<PathBuf>,
    pub app_log_retention_days: u32,
}

impl LoggingConfig {
    /// Load logging configuration from environment variables
    pub fn from_env() -> Self {
        let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
        
        let app_log_file = env::var("APP_LOG_FILE")
            .ok()
            .map(PathBuf::from);
        
        let app_log_retention_days = env::var("APP_LOG_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        
        Self {
            log_level,
            app_log_file,
            app_log_retention_days,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("Failed to initialize logging: {0}")]
    InitializationError(String),
    
    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),
    
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),
}

/// Initialize the tracing subscriber with console and optional file output
/// Reads configuration from environment variables automatically
pub fn init_logging() -> Result<(), LoggingError> {
    let config = LoggingConfig::from_env();
    
    // Create the environment filter for log level
    let env_filter = EnvFilter::try_new(&config.log_level)
        .map_err(|e| LoggingError::InvalidLogLevel(format!("{}: {}", config.log_level, e)))?;
    
    // Create console layer with human-readable formatting
    let console_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(true)
        .with_line_number(true)
        .with_filter(env_filter.clone());
    
    // Build the subscriber with console layer
    let subscriber = tracing_subscriber::registry()
        .with(console_layer);
    
    // Add file layer if configured
    if let Some(log_file_path) = &config.app_log_file {
        // Create parent directory if it doesn't exist
        if let Some(parent) = log_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // Create file appender with daily rotation
        let file_appender = tracing_appender::rolling::daily(
            log_file_path.parent().unwrap_or_else(|| std::path::Path::new(".")),
            log_file_path.file_name()
                .ok_or_else(|| LoggingError::InitializationError("Invalid log file path".to_string()))?,
        );
        
        let file_layer = fmt::layer()
            .with_writer(file_appender)
            .with_target(true)
            .with_ansi(false)
            .with_file(true)
            .with_line_number(true)
            .with_filter(env_filter);
        
        subscriber
            .with(file_layer)
            .try_init()
            .map_err(|e| LoggingError::InitializationError(e.to_string()))?;
    } else {
        subscriber
            .try_init()
            .map_err(|e| LoggingError::InitializationError(e.to_string()))?;
    }
    
    Ok(())
}
