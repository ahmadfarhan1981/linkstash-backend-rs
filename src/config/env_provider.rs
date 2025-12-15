use std::collections::HashMap;

/// Trait for providing environment variable access
/// 
/// This abstraction allows for dependency injection of environment variable
/// sources, enabling clean testing without race conditions from parallel
/// test execution modifying shared global environment state.
pub trait EnvironmentProvider {
    fn get_var(&self, key: &str) -> Option<String>;
}

/// Production environment provider that reads from system environment
pub struct SystemEnvironment;

impl EnvironmentProvider for SystemEnvironment {
    fn get_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Test environment provider with configurable variables
/// 
/// Allows tests to provide specific environment variable values
/// without modifying the global environment state.
#[cfg(test)]
pub struct MockEnvironment {
    vars: std::collections::HashMap<String, String>,
}

#[cfg(test)]
impl MockEnvironment {
    pub fn new(vars: HashMap<String, String>) -> Self {
        Self { vars }
    }
    
    pub fn empty() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }
    
    pub fn with_var(mut self, key: &str, value: &str) -> Self {
        self.vars.insert(key.to_string(), value.to_string());
        self
    }
    
    pub fn with_vars(mut self, vars: &[(&str, &str)]) -> Self {
        for (key, value) in vars {
            self.vars.insert(key.to_string(), value.to_string());
        }
        self
    }
}

#[cfg(test)]
impl EnvironmentProvider for MockEnvironment {
    fn get_var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_environment_provider() {
        let provider = SystemEnvironment;
        
        unsafe {
            std::env::set_var("TEST_VAR_12345", "test_value");
        }
        
        assert_eq!(provider.get_var("TEST_VAR_12345"), Some("test_value".to_string()));
        assert_eq!(provider.get_var("NON_EXISTENT_VAR_98765"), None);
        
        unsafe {
            std::env::remove_var("TEST_VAR_12345");
        }
    }

    #[test]
    fn test_mock_environment_provider() {
        let provider = MockEnvironment::empty()
            .with_var("TEST_KEY", "test_value")
            .with_var("ANOTHER_KEY", "another_value");
        
        assert_eq!(provider.get_var("TEST_KEY"), Some("test_value".to_string()));
        assert_eq!(provider.get_var("ANOTHER_KEY"), Some("another_value".to_string()));
        assert_eq!(provider.get_var("NON_EXISTENT"), None);
    }

    #[test]
    fn test_mock_environment_with_vars() {
        let provider = MockEnvironment::empty()
            .with_vars(&[
                ("KEY1", "value1"),
                ("KEY2", "value2"),
                ("KEY3", "value3"),
            ]);
        
        assert_eq!(provider.get_var("KEY1"), Some("value1".to_string()));
        assert_eq!(provider.get_var("KEY2"), Some("value2".to_string()));
        assert_eq!(provider.get_var("KEY3"), Some("value3".to_string()));
        assert_eq!(provider.get_var("KEY4"), None);
    }

    #[test]
    fn test_mock_environment_empty() {
        let provider = MockEnvironment::empty();
        
        assert_eq!(provider.get_var("ANY_KEY"), None);
    }
}