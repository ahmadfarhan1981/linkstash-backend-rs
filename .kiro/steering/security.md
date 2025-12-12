---
inclusion: always
---

# Security Protocols

## Secrets Management

### Secret Manager Protocol

- **ALL secrets MUST be managed through the secret manager module**
- Never hardcode secrets in source code
- Never pass secrets as plain strings between functions
- Use the secret manager for loading, storing, and accessing all sensitive data

### Struct Security

- **Any struct containing secret fields MUST implement `Debug` and `Display` traits**
- Custom implementations MUST redact secret values (e.g., `"[REDACTED]"` or `"***"`)
- This prevents accidental exposure in logs, error messages, or debug output
- Example:
  ```rust
  impl fmt::Debug for MySecretStruct {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
          f.debug_struct("MySecretStruct")
              .field("secret", &"[REDACTED]")
              .finish()
      }
  }
  ```

### Environment Variables

- **ALWAYS update `.env.example` when adding ANY environment variable**
- `.env.example` should contain:
  - All environment variable names (secrets and non-secrets)
  - Example/placeholder values (never real secrets)
  - Comments explaining purpose and format requirements
- Keep `.env.example` in version control
- Never commit `.env` file with actual secrets