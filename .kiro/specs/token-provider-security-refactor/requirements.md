# Requirements Document

## Introduction

The TokenProvider currently violates our security model by storing JWT and refresh token secrets as plain strings in struct fields, rather than accessing them through the SecretManager. This creates multiple copies of sensitive secrets in memory and violates the principle that ALL secrets MUST be managed through the secret manager module.

## Glossary

- **TokenProvider**: Provider responsible for JWT generation, validation, and refresh token operations
- **SecretManager**: Centralized manager for application secrets that loads and validates secrets from environment variables
- **AppData**: Centralized application data structure containing shared resources including SecretManager
- **Secret**: Sensitive cryptographic material (JWT secret, refresh token secret) that must be protected

## Requirements

### Requirement 1

**User Story:** As a security-conscious developer, I want all secrets to be accessed through the SecretManager, so that secrets are centrally managed and not duplicated in memory.

#### Acceptance Criteria

1. WHEN TokenProvider is created THEN the system SHALL NOT store JWT secret as a plain string in struct fields
2. WHEN TokenProvider is created THEN the system SHALL NOT store refresh token secret as a plain string in struct fields
3. WHEN TokenProvider needs JWT secret THEN the system SHALL access it through SecretManager reference
4. WHEN TokenProvider needs refresh token secret THEN the system SHALL access it through SecretManager reference
5. WHEN TokenProvider is created THEN the system SHALL store a reference to SecretManager instead of copying secrets

### Requirement 2

**User Story:** As a developer following the AppData pattern, I want TokenProvider to follow the same constructor pattern as other providers, so that the architecture remains consistent.

#### Acceptance Criteria

1. WHEN TokenProvider is instantiated THEN the system SHALL take Arc<SecretManager> as a parameter instead of plain string secrets
2. WHEN TokenProvider is instantiated THEN the system SHALL maintain the same public interface for all existing methods
3. WHEN TokenProvider accesses secrets THEN the system SHALL call SecretManager methods at point of use
4. WHEN TokenProvider is created by coordinators THEN the system SHALL extract SecretManager from AppData
5. WHEN TokenProvider implements Debug trait THEN the system SHALL NOT expose secret values

### Requirement 3

**User Story:** As a developer maintaining backward compatibility, I want all existing TokenProvider functionality to work unchanged, so that no API contracts are broken.

#### Acceptance Criteria

1. WHEN generate_jwt is called THEN the system SHALL produce identical JWT tokens as before the refactor
2. WHEN validate_jwt is called THEN the system SHALL validate tokens identically as before the refactor
3. WHEN generate_refresh_token is called THEN the system SHALL produce cryptographically secure tokens as before
4. WHEN hash_refresh_token is called THEN the system SHALL produce identical hashes as before the refactor
5. WHEN get_refresh_expiration is called THEN the system SHALL return identical expiration timestamps as before

### Requirement 4

**User Story:** As a security auditor, I want to ensure secrets are never exposed in debug output or logs, so that sensitive information cannot leak through development tools.

#### Acceptance Criteria

1. WHEN TokenProvider Debug trait is used THEN the system SHALL NOT expose SecretManager secrets
2. WHEN TokenProvider Display trait is used THEN the system SHALL NOT expose SecretManager secrets
3. WHEN TokenProvider is logged or printed THEN the system SHALL show redacted placeholders for secret fields
4. WHEN SecretManager is accessed THEN the system SHALL maintain existing secret protection mechanisms
5. WHEN errors occur during secret access THEN the system SHALL NOT expose secret values in error messages