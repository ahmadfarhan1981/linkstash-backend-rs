use std::fmt;



#[derive(Debug)]
pub enum ApplicationError {
    DatabaseConnection(String),
    InvalidSetting { setting_name: String, reason: String },
    ParseError { setting_name: String, error: String },
    UnknownSetting { name: String },
    ReadOnlyFromEnvironment { setting_name: String },
    NoWritableSource { setting_name: String },
    FileUpdatesNotSupported,
    UnknownServerError{message: String},
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
            },
            Self::UnknownServerError { message }=>{
                write!(f, "Unknow server error: {} ", message)

            }

        }
    }
}

impl std::error::Error for ApplicationError {}

#[derive(Debug)]
pub enum SettingsError {
    Application(ApplicationError),
    Secret(crate::config::secret_manager::SecretError),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application(err) => write!(f, "Settings error: {}", err),
            Self::Secret(err) => write!(f, "Secret error: {}", err),
        }
    }
}

impl std::error::Error for SettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Application(err) => Some(err),
            Self::Secret(err) => Some(err),
        }
    }
}

impl From<ApplicationError> for SettingsError {
    fn from(err: ApplicationError) -> Self {
        Self::Application(err)
    }
}

impl From<crate::config::secret_manager::SecretError> for SettingsError {
    fn from(err: crate::config::secret_manager::SecretError) -> Self {
        Self::Secret(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_error_display() {
        let error = ApplicationError::InvalidSetting {
            setting_name: "test_setting".to_string(),
            reason: "test reason".to_string(),
        };
        assert_eq!(format!("{}", error), "Invalid setting 'test_setting': test reason");
    }

    #[test]
    fn test_settings_error_display() {
        let app_error = ApplicationError::UnknownSetting {
            name: "unknown_setting".to_string(),
        };
        let settings_error = SettingsError::Application(app_error);
        assert_eq!(format!("{}", settings_error), "Settings error: Unknown setting: unknown_setting");
    }

    #[test]
    fn test_settings_error_from_application_error() {
        let app_error = ApplicationError::DatabaseConnection("test error".to_string());
        let settings_error: SettingsError = app_error.into();
        
        match settings_error {
            SettingsError::Application(ApplicationError::DatabaseConnection(msg)) => {
                assert_eq!(msg, "test error");
            }
            _ => panic!("Expected Application error"),
        }
    }
}