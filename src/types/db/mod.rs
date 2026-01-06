// Database entities - SeaORM models
pub mod audit_event;
pub mod common_password;
pub mod hibp_cache;
pub mod refresh_token;
pub mod system_config;
pub mod system_settings;
pub mod user;


pub struct AccessToken(String);

impl  AccessToken {
 pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<T> From<T> for AccessToken
where
    T: AsRef<str>,
{
    fn from(value: T) -> Self {
        Self(value.as_ref().to_owned())
    }
}


impl std::fmt::Display for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[access_token]")
    }
}