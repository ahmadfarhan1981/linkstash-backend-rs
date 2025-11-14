# Requirements Document

## Introduction

This document specifies the requirements for a user registration system that prevents spam through proof-of-work (PoW) challenges while providing trusted bypass mechanisms for backend services and administrative users. The system supports anonymous registration (username/password only) with configurable anti-spam measures and rate limiting.

## Glossary

- **Registration System**: The component responsible for creating new user accounts in the identity provider
- **PoW (Proof of Work)**: A computational challenge that clients must solve to prove they expended CPU resources, used to prevent automated spam
- **Challenge**: A server-generated random identifier used as input for PoW computation
- **Nonce**: A number that, when combined with the challenge and hashed, produces a valid PoW solution
- **Difficulty**: The number of leading zeros required in the hash output (e.g., 4 means "0000...")
- **API Key**: A secret token used by trusted backend services to bypass PoW requirements
- **User Admin**: A user with administrative privileges who can create accounts without PoW
- **Rate Limit**: A restriction on the number of registration attempts allowed within a time window
- **Global Rate Limit**: Rate limit applied across all public registration attempts
- **Scoped Rate Limit**: Rate limit applied per API key or per user admin
- **Per-IP Rate Limit**: Rate limit applied to a single IP address
- **Per-Subnet Rate Limit**: Rate limit applied to an IP subnet (e.g., /24 CIDR block)
- **Graduated Difficulty**: Dynamic adjustment of PoW difficulty based on rate limit pressure
- **Hard Limit**: A rate limit threshold that results in request rejection
- **Soft Limit**: A rate limit threshold that results in increased PoW difficulty rather than rejection
- **Invite Code**: A human-readable code that allows registration without PoW when the invite system is enabled
- **Invite Quota**: The number of invite codes a user is allowed to generate
- **Invite Tree**: The hierarchical relationship tracking who invited whom
- **Invite System**: The feature that allows users to generate invite codes for new user registration

## Requirements

### Requirement 1: Public User Registration

**User Story:** As a new user, I want to register an account with just a username and password, so that I can use the application without providing personal information

#### Acceptance Criteria

1. WHEN a client requests a PoW challenge, THE Registration System SHALL generate a unique challenge identifier with a difficulty level and expiration time
2. WHEN a client submits a registration request with valid PoW solution, THE Registration System SHALL verify the solution matches the challenge requirements
3. WHEN a client submits a registration request with username and password and valid PoW, THE Registration System SHALL create a new user account with hashed password
4. WHEN a client submits a registration request with an expired challenge, THE Registration System SHALL reject the request with an appropriate error
5. WHEN a client submits a registration request with an already-used challenge, THE Registration System SHALL reject the request with an appropriate error

### Requirement 2: PoW Challenge Generation

**User Story:** As the system, I want to generate PoW challenges that are computationally expensive to solve but cheap to verify, so that I can prevent automated spam without impacting legitimate users

#### Acceptance Criteria

1. WHEN a PoW challenge is requested, THE Registration System SHALL generate a random challenge identifier using a cryptographically secure random generator
2. WHEN a PoW challenge is generated, THE Registration System SHALL include the hash algorithm specification (SHA-256), difficulty level, and input format in the response
3. WHEN a PoW challenge is generated, THE Registration System SHALL set an expiration time between 5 and 10 minutes from creation
4. WHEN a PoW challenge is generated, THE Registration System SHALL store the challenge with its creation time and used status
5. THE Registration System SHALL use SHA-256 as the hash algorithm for PoW verification

### Requirement 3: PoW Solution Verification

**User Story:** As the system, I want to verify PoW solutions efficiently, so that I can confirm clients performed the required work without doing the work myself

#### Acceptance Criteria

1. WHEN verifying a PoW solution, THE Registration System SHALL compute SHA-256 hash of the concatenated challenge identifier and nonce
2. WHEN verifying a PoW solution, THE Registration System SHALL check that the hash output starts with the required number of leading zeros in hexadecimal format
3. WHEN a valid PoW solution is verified, THE Registration System SHALL mark the challenge as used to prevent reuse
4. WHEN an invalid PoW solution is submitted, THE Registration System SHALL reject the registration request with an appropriate error
5. THE Registration System SHALL complete PoW verification in less than 10 milliseconds

### Requirement 4: Trusted Backend Registration with Request Signing

**User Story:** As a backend service, I want to register users without solving PoW challenges using cryptographic request signing, so that I can securely create accounts even over untrusted networks

#### Acceptance Criteria

1. WHEN a registration request includes a valid API key identifier and request signature, THE Registration System SHALL bypass PoW verification
2. WHEN a registration request includes an invalid signature, THE Registration System SHALL reject the request with an authentication error
3. WHEN a registration request with valid signature is received, THE Registration System SHALL create the user account with the provided credentials
4. THE Registration System SHALL support multiple API keys, each with its own secret for signature generation
5. THE Registration System SHALL log all API key usage with key identifier for audit purposes

### Requirement 4.1: Request Signature Generation

**User Story:** As a backend service, I want to sign my registration requests cryptographically, so that API secrets are never transmitted over the network

#### Acceptance Criteria

1. WHEN signing a request, THE Backend Service SHALL compute HMAC-SHA256 of the concatenated request body and timestamp using the API secret
2. WHEN signing a request, THE Backend Service SHALL include the API key identifier, signature, and timestamp in request headers
3. THE Backend Service SHALL use ISO 8601 format for timestamps in signature computation
4. THE Backend Service SHALL include the complete request body in signature computation
5. THE Backend Service SHALL never transmit the API secret, only the computed signature

### Requirement 4.2: Request Signature Verification

**User Story:** As the system, I want to verify request signatures, so that I can authenticate trusted backends without transmitting secrets

#### Acceptance Criteria

1. WHEN verifying a signed request, THE Registration System SHALL retrieve the API secret associated with the provided key identifier
2. WHEN verifying a signed request, THE Registration System SHALL compute HMAC-SHA256 of the request body and timestamp using the stored API secret
3. WHEN the computed signature matches the provided signature, THE Registration System SHALL authenticate the request as valid
4. WHEN the computed signature does not match, THE Registration System SHALL reject the request with an authentication error
5. THE Registration System SHALL use constant-time comparison for signature verification to prevent timing attacks

### Requirement 4.3: Timestamp Validation

**User Story:** As the system, I want to validate request timestamps, so that I can prevent replay attacks using captured signatures

#### Acceptance Criteria

1. WHEN verifying a signed request, THE Registration System SHALL check that the timestamp is within an acceptable time window (configurable, default 5 minutes)
2. WHEN the timestamp is outside the acceptable window, THE Registration System SHALL reject the request with a timestamp error
3. WHEN the timestamp is in the future, THE Registration System SHALL reject the request with a timestamp error
4. THE Registration System SHALL allow clock skew tolerance of up to 30 seconds
5. THE Registration System SHALL make the timestamp window configurable through environment variables

### Requirement 5: User Admin Registration

**User Story:** As a user administrator, I want to create user accounts without solving PoW challenges, so that I can efficiently onboard users as part of my administrative duties

#### Acceptance Criteria

1. WHEN a registration request includes a valid JWT with user_admin role in claims, THE Registration System SHALL bypass PoW verification
2. WHEN a registration request includes a JWT without user_admin role, THE Registration System SHALL require PoW verification
3. WHEN a registration request with valid user_admin JWT is received, THE Registration System SHALL create the user account with the provided credentials
4. THE Registration System SHALL apply per-user rate limits to user admin registrations
5. THE Registration System SHALL log all user admin registrations with the admin user identifier for audit purposes

### Requirement 6: Per-IP Rate Limiting

**User Story:** As the system, I want to limit registrations from a single IP address, so that a single attacker cannot consume the global registration quota

#### Acceptance Criteria

1. THE Registration System SHALL enforce a configurable per-IP hard limit for public registration attempts
2. WHEN the per-IP hard limit is exceeded, THE Registration System SHALL reject the registration request with a rate limit error
3. THE Registration System SHALL track per-IP rate limit by counting registration attempts from each IP address within a sliding time window
4. THE Registration System SHALL apply per-IP rate limits only to public registrations, not to API key or user admin registrations
5. THE Registration System SHALL make the per-IP rate limit configurable through environment variables with a default of 5 registrations per hour

### Requirement 7: Per-Subnet Rate Limiting with Graduated Difficulty

**User Story:** As a legitimate user behind a shared IP (NAT/corporate network), I want to still register even when my subnet is under pressure, so that I am not blocked by other users' activity

#### Acceptance Criteria

1. THE Registration System SHALL track registration attempts per IP subnet using configurable CIDR notation (default /24)
2. WHEN subnet registration count exceeds the soft limit threshold, THE Registration System SHALL increase PoW difficulty for subsequent challenges from that subnet
3. WHEN subnet registration count exceeds the hard limit threshold, THE Registration System SHALL reject registration requests from that subnet with a rate limit error
4. THE Registration System SHALL calculate graduated difficulty by adding pressure levels to the base difficulty (e.g., base 4 + pressure 2 = difficulty 6)
5. THE Registration System SHALL make subnet rate limit thresholds and pressure levels configurable through environment variables

### Requirement 8: Global Rate Limiting with Graduated Difficulty

**User Story:** As the system, I want to slow down registrations during high load without completely blocking legitimate users, so that the service degrades gracefully under attack

#### Acceptance Criteria

1. THE Registration System SHALL track total public registration attempts within a sliding time window
2. WHEN global registration count exceeds soft limit thresholds, THE Registration System SHALL increase PoW difficulty for all subsequent public registration challenges
3. WHEN global registration count exceeds the hard limit threshold, THE Registration System SHALL reject public registration requests with a rate limit error
4. THE Registration System SHALL support multiple graduated difficulty levels based on configurable global count thresholds
5. THE Registration System SHALL apply global rate limits and difficulty adjustments only to public registrations, not to API key or user admin registrations

### Requirement 9: Scoped Rate Limiting for Trusted Paths

**User Story:** As the system, I want to limit registrations per API key and per user admin, so that compromised credentials cannot be used for unlimited spam

#### Acceptance Criteria

1. THE Registration System SHALL enforce a configurable per-API-key hard limit for trusted backend registrations
2. THE Registration System SHALL enforce a configurable per-user hard limit for user admin registrations
3. WHEN a per-API-key rate limit is exceeded, THE Registration System SHALL reject the registration request with a rate limit error
4. WHEN a per-user admin rate limit is exceeded, THE Registration System SHALL reject the registration request with a rate limit error
5. THE Registration System SHALL make scoped rate limits configurable through environment variables

### Requirement 10: Dynamic PoW Difficulty Calculation

**User Story:** As the system, I want to calculate PoW difficulty based on current rate limit pressure, so that difficulty automatically adjusts to current threat levels

#### Acceptance Criteria

1. WHEN generating a PoW challenge, THE Registration System SHALL calculate the difficulty by combining base difficulty with subnet pressure and global pressure levels
2. THE Registration System SHALL determine subnet pressure level based on current subnet registration count relative to configured thresholds
3. THE Registration System SHALL determine global pressure level based on current global registration count relative to configured thresholds
4. THE Registration System SHALL include the calculated difficulty level in the PoW challenge response
5. THE Registration System SHALL ensure that calculated difficulty never exceeds a configurable maximum difficulty level (default 8 leading zeros)

### Requirement 11: Username Uniqueness

**User Story:** As the system, I want to ensure usernames are unique, so that each user can be distinctly identified

#### Acceptance Criteria

1. WHEN a registration request is received, THE Registration System SHALL check if the username already exists
2. WHEN a username already exists, THE Registration System SHALL reject the registration request with a conflict error
3. THE Registration System SHALL perform case-insensitive username uniqueness checks
4. THE Registration System SHALL enforce username format requirements (alphanumeric, minimum length, maximum length)
5. THE Registration System SHALL validate username format before checking uniqueness

### Requirement 12: Password Security

**User Story:** As the system, I want to securely store user passwords, so that user credentials are protected even if the database is compromised

#### Acceptance Criteria

1. WHEN a user account is created, THE Registration System SHALL hash the password using Argon2id algorithm
2. THE Registration System SHALL never store plaintext passwords in the database
3. THE Registration System SHALL never log or expose passwords in error messages or responses
4. THE Registration System SHALL enforce minimum password length requirements (configurable, default 8 characters)
5. THE Registration System SHALL validate password requirements before creating the account

### Requirement 13: Rate Limit and Difficulty Configuration

**User Story:** As a system administrator, I want to configure rate limits and PoW difficulty settings, so that I can tune the system based on observed traffic patterns and threat levels

#### Acceptance Criteria

1. THE Registration System SHALL load all rate limit thresholds from environment variables with documented defaults
2. THE Registration System SHALL load base PoW difficulty and graduated difficulty pressure levels from environment variables
3. THE Registration System SHALL load subnet CIDR notation for subnet-based rate limiting from environment variables (default /24)
4. THE Registration System SHALL validate all configuration values at startup and reject invalid configurations with clear error messages
5. THE Registration System SHALL support configuration changes without code modifications

### Requirement 14: Transport Security for API Keys

**User Story:** As a system administrator, I want to ensure API keys are transmitted securely, so that they cannot be intercepted by attackers

#### Acceptance Criteria

1. THE Registration System SHALL document that API key authentication requires HTTPS/TLS in production environments
2. THE Registration System SHALL log a warning at startup when running in HTTP mode with API key authentication enabled
3. THE Registration System SHALL support HTTP mode for local development with explicit acknowledgment of security implications
4. THE Registration System SHALL include transport security requirements in API documentation
5. THE Registration System SHALL recommend request signing as an optional enhancement for high-security deployments

### Requirement 15: Invite Code Generation

**User Story:** As a user with invite quota, I want to generate invite codes, so that I can invite friends to register without requiring them to solve PoW challenges

#### Acceptance Criteria

1. WHEN a user with available invite quota requests code generation, THE Registration System SHALL generate a unique invite code consisting of 4 randomly selected words from a predefined word list
2. WHEN generating an invite code, THE Registration System SHALL use a cryptographically secure random generator for word selection
3. WHEN an invite code is generated, THE Registration System SHALL decrement the user's invite quota by one
4. WHEN an invite code is generated, THE Registration System SHALL store the code with metadata including creator user ID, creation timestamp, and used status
5. WHEN a user with zero invite quota requests code generation, THE Registration System SHALL reject the request with a quota exceeded error

### Requirement 16: Invite Code Format

**User Story:** As a user, I want invite codes to be easy to communicate verbally, so that I can share them at social gatherings without writing them down

#### Acceptance Criteria

1. THE Registration System SHALL format invite codes as four words separated by hyphens (e.g., "horse-battery-stapler-cloud")
2. THE Registration System SHALL use only lowercase letters in invite codes
3. THE Registration System SHALL use a word list of at least 2048 common English words for code generation
4. THE Registration System SHALL ensure the word list contains only easily pronounceable words without offensive content
5. THE Registration System SHALL ensure invite codes provide at least 44 bits of entropy (2048^4 combinations)

### Requirement 17: Registration with Invite Code

**User Story:** As a new user with an invite code, I want to register without solving PoW challenges, so that I can quickly join the application

#### Acceptance Criteria

1. WHEN the invite system is enabled and a registration request includes a valid unused invite code, THE Registration System SHALL bypass PoW verification
2. WHEN the invite system is enabled and a valid invite code is used, THE Registration System SHALL mark the code as used and record the new user ID and usage timestamp
3. WHEN the invite system is enabled and an invalid or already-used invite code is provided, THE Registration System SHALL reject the registration request with an appropriate error
4. WHEN the invite system is disabled and an invite code is provided, THE Registration System SHALL ignore the invite code and require PoW verification
5. WHEN the invite system is disabled and an invite code is provided, THE Registration System SHALL not consume or validate the invite code

### Requirement 18: Invite System Enable/Disable

**User Story:** As a system administrator, I want to enable or disable the invite system globally, so that I can control whether invite codes allow registration bypass

#### Acceptance Criteria

1. THE Registration System SHALL maintain a global invite system enabled/disabled state
2. WHEN an admin or trusted backend requests to enable the invite system, THE Registration System SHALL set the state to enabled
3. WHEN an admin or trusted backend requests to disable the invite system, THE Registration System SHALL set the state to disabled
4. THE Registration System SHALL allow invite code generation and status queries regardless of the invite system state
5. THE Registration System SHALL include the current invite system state in all invite-related API responses

### Requirement 19: Invite Quota Management

**User Story:** As a system administrator, I want to grant invite quotas to users, so that I can control who can invite new users and in what quantity

#### Acceptance Criteria

1. WHEN an admin or trusted backend grants invites to a user, THE Registration System SHALL add the specified number of invites to the user's current quota
2. THE Registration System SHALL support granting invites to multiple users simultaneously for batch operations
3. THE Registration System SHALL validate that the grant amount is a positive integer
4. THE Registration System SHALL log all invite quota grants with admin/backend identifier, target user, and amount for audit purposes
5. THE Registration System SHALL allow users to have unlimited accumulated invite quota (no maximum cap)

### Requirement 20: Invite Status and History

**User Story:** As a user, I want to view my invite quota and generated codes, so that I can track my invitations and see which codes have been used

#### Acceptance Criteria

1. WHEN a user requests their invite status, THE Registration System SHALL return their current invite quota, the invite system enabled state, and a list of all codes they generated
2. WHEN returning generated codes, THE Registration System SHALL include the code, creation timestamp, used status, and the user ID who used it (if used)
3. THE Registration System SHALL allow users to query only their own invite codes and status
4. THE Registration System SHALL allow admins to query any user's invite status and codes
5. THE Registration System SHALL return invite status information regardless of whether the invite system is enabled or disabled

### Requirement 21: Invite Tree Tracking

**User Story:** As a user, I want to see who I invited, so that I can track the growth of my invite network

#### Acceptance Criteria

1. WHEN an invite code is used for registration, THE Registration System SHALL record the relationship between the inviter and the new user
2. WHEN a user requests their invite tree, THE Registration System SHALL return a list of all users they directly invited with registration timestamps
3. THE Registration System SHALL store invite relationships permanently for audit and analytics purposes
4. THE Registration System SHALL allow users to query only their own direct invitees
5. THE Registration System SHALL allow admins to query the full invite tree for any user including all descendants

### Requirement 22: Invite Code Security

**User Story:** As a user, I want to retrieve my generated invite codes at any time, so that I can share them when needed without having to remember or write them down

#### Acceptance Criteria

1. WHEN an invite code is generated, THE Registration System SHALL store the plaintext code in the database
2. WHEN a user requests their invite status, THE Registration System SHALL return all their generated codes in plaintext
3. WHEN verifying an invite code during registration, THE Registration System SHALL perform case-insensitive comparison of the provided code against stored codes
4. THE Registration System SHALL rate limit invite code verification attempts to prevent brute force attacks
5. THE Registration System SHALL track the creator user ID for all invite codes to enable accountability and abuse prevention
