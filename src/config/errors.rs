use std::fmt;

#[derive(Debug)]
pub enum BootstrapError {
    MissingDatabaseUrl,
    InvalidDatabaseUrl(String),
    MissingRequiredSetting { setting_name: String },
    InvalidFormat { setting_name: String, expected: String, actual: String },
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDatabaseUrl => {
                write!(f, "Required environment variable DATABASE_URL is missing")
            }
            Self::InvalidDatabaseUrl(url) => {
                write!(f, "Invalid database URL format: {}", url)
            }
            Self::MissingRequiredSetting { setting_name } => {
                write!(f, "Required bootstrap setting '{}' is missing", setting_name)
            }
            Self::InvalidFormat { setting_name, expected, actual } => {
                write!(
                    f,
                    "Bootstrap setting '{}' has invalid format. Expected: {}, got: {}",
                    setting_name, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for BootstrapError {}

#[derive(Debug)]
pub enum ApplicationError {
    DatabaseConnection(String),
    InvalidSetting { setting_name: String, reason: String },
    ParseError { setting_name: String, error: String },
    UnknownSetting { name: String },
    ReadOnlyFromEnvironment { setting_name: String },
    NoWritableSource { setting_name: String },
    FileUpdatesNotSupported,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseConnection(msg) => {
                write!(f, "Database connection error: {}", msg)
            }
            Self::InvalidSetting { setting_name, reason } => {
                write!(f, "Invalid setting '{}': {}", setting_name, reason)
            }
            Self::ParseError { setting_name, error } => {
                write!(f, "Failed to parse setting '{}': {}", setting_name, error)
            }
            Self::UnknownSetting { name } => {
                write!(f, "Unknown setting: {}", name)
            }
            Self::ReadOnlyFromEnvironment { setting_name } => {
                write!(
                    f,
                    "Setting '{}' is overridden by environment variable and cannot be updated at runtime",
                    setting_name
                )
            }
            Self::NoWritableSource { setting_name } => {
                write!(
                    f,
                    "Setting '{}' has no writable persistent source configured",
                    setting_name
                )
            }
            Self::FileUpdatesNotSupported => {
                write!(f, "Runtime updates to file-based configuration are not supported")
            }
        }
    }
}

impl std::error::Error for ApplicationError {}

#[derive(Debug)]
pub enum SettingsError {
    Bootstrap(BootstrapError),
    Application(ApplicationError),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bootstrap(err) => write!(f, "Bootstrap error: {}", err),
            Self::Application(err) => write!(f, "Application settings error: {}", err),
        }
    }
}

impl std::error::Error for SettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bootstrap(err) => Some(err),
            Self::Application(err) => Some(err),
        }
    }
}

impl From<BootstrapError> for SettingsError {
    fn from(err: BootstrapError) -> Self {
        Self::Bootstrap(err)
    }
}

impl From<ApplicationError> for SettingsError {
    fn from(err: ApplicationError) -> Self {
        Self::Application(err)
    }
}