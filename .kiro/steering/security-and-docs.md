---
inclusion: always
---

# Security & Documentation Protocols

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

## Documentation Protocol

### When to Document

Document functionality when:
- Developers need to extend or modify existing code
- System administrators need to configure or run the system
- The implementation involves non-obvious patterns or decisions

### What NOT to Document

- **API endpoints** - Swagger UI provides sufficient documentation
- **End-user functionality** - Client applications handle UX documentation
- **Self-explanatory code** - Let the code speak for itself

### Documentation Location

- **`docs/` directory** - All developer and admin documentation
- Use descriptive filenames: `adding-secrets.md`, `extending-auth.md`, etc.
- Keep docs focused and concise

### Documentation Audience

1. **Developers** - Extending or modifying the system
   - Architecture decisions
   - Extension points
   - Code patterns and conventions
   
2. **Administrators** - Running and configuring the system
   - Deployment procedures
   - Configuration options
   - Troubleshooting guides

3. **End Users** - NOT our responsibility
   - Swagger UI covers API usage
   - Client applications handle user experience

### Documentation Format

- Use Markdown
- Include code examples where helpful
- Keep it practical and actionable
- Update docs when changing related functionality
