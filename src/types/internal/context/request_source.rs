/// Source of the request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSource {
    /// Request originated from API endpoint
    API,

    /// Request originated from CLI command
    CLI,

    /// Request originated from system (automated operations)
    System,
}