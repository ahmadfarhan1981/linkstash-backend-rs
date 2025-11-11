/// Defines the source type for a secret
#[derive(Debug, Clone)]
pub enum SecretType {
    /// Load from environment variable
    EnvVar { name: String },
    // Future variants:
    // AwsSecretsManager { secret_id: String, region: String },
    // AzureKeyVault { vault_url: String, secret_name: String },
    // File { path: PathBuf },
}

/// Configuration for a single secret
pub struct SecretConfig {
    /// Secret type (where to load from)
    pub secret_type: SecretType,
    /// Whether this secret is required
    pub required: bool,
    /// Minimum length (None = no minimum)
    pub min_length: Option<usize>,
}

impl SecretConfig {
    pub fn new(secret_type: SecretType) -> Self {
        Self {
            secret_type,
            required: true,
            min_length: None,
        }
    }

    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    pub fn min_length(mut self, length: usize) -> Self {
        self.min_length = Some(length);
        self
    }
}
