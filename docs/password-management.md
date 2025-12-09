# Password Management

## Overview

The password management system provides comprehensive password security through validation, change functionality, and enforcement mechanisms. It ensures strong password policies are consistently applied across all user creation and password change flows.

## Password Policy

All passwords in the system must meet the following requirements:

### Length Requirements

- **Minimum**: 15 characters
- **Maximum**: 128 characters

The minimum length of 15 characters supports strong passphrases while the maximum prevents potential DoS attacks through excessive hashing operations.

### Validation Checks

Passwords are validated against multiple security criteria in the following order:

1. **Length Check**: Ensures password is between 15-128 characters
2. **Username Substring Check**: Prevents passwords containing the username (case-insensitive)
3. **Common Password Check**: Rejects passwords from a configurable common password list
4. **Compromised Password Check**: Validates against HaveIBeenPwned database using k-anonymity

### Validation Error Messages

- `"Password must be at least 15 characters"` - Password too short
- `"Password must not exceed 128 characters"` - Password too long
- `"Password must not contain your username"` - Username found in password
- `"Password is too common"` - Password found in common password list
- `"Password has been compromised in a data breach"` - Password found in HIBP database

## Password Change Flow

### API Endpoint

**POST** `/api/auth/change-password`

Changes the authenticated user's password and issues new tokens.

#### Request

```json
{
  "old_password": "current-password",
  "new_password": "new-secure-password"
}
```

**Headers:**
```
Authorization: Bearer <jwt-token>
```

#### Response (Success - 200 OK)

```json
{
  "message": "Password changed successfully",
  "access_token": "eyJhbGc...",
  "refresh_token": "base64-encoded-token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Response (Error - 400 Bad Request)

```json
{
  "error": "Current password is incorrect"
}
```

or

```json
{
  "error": "Password validation failed: Password is too common"
}
```

### Password Change Process

When a password is changed, the system performs the following operations:

1. **Verify Old Password**: Confirms the current password is correct
2. **Validate New Password**: Runs all validation checks (length, username, common, compromised)
3. **Hash New Password**: Uses Argon2id to securely hash the new password
4. **Update Database**: Stores the new password hash
5. **Clear Password Change Flag**: Sets `password_change_required` to `false`
6. **Revoke All Tokens**: Invalidates all existing refresh tokens for the user
7. **Issue New Tokens**: Generates new JWT and refresh token pair

This ensures that after a password change:
- Old refresh tokens cannot be used
- The user receives fresh tokens immediately
- All other sessions are logged out

### Example Usage

```bash
# Change password
curl -X POST http://localhost:3000/api/auth/change-password \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "current-password",
    "new_password": "new-secure-passphrase-with-15-chars"
  }'
```

## Password Change Requirement for Bootstrap Accounts

### Overview

Bootstrap accounts (owner and admin users created during system initialization) are created with `password_change_required=true`. This forces users to change their password before accessing protected endpoints.

### Bootstrap Behavior

When creating bootstrap accounts:

1. **Auto-Generated Passwords**: System generates a secure 20-character password using mixed charset (uppercase, lowercase, digits, special characters)
2. **Manual Passwords**: If provided, passwords are validated against all policy requirements
3. **Password Change Flag**: All bootstrap accounts have `password_change_required=true`
4. **Warning Display**: Bootstrap command displays: "Password change required on first login"

### Enforcement Mechanism

The `password_change_required` flag is included in JWT claims. When a user with this flag set attempts to access protected endpoints:

- **Blocked Endpoints**: Most endpoints return `403 Forbidden` with message: "Password change required. Please change your password at /auth/change-password"
- **Allowed Endpoints**: Only `/auth/change-password` and `/auth/whoami` remain accessible

This fail-secure design ensures new endpoints are automatically protected by default.

### Workflow Example

```bash
# 1. Bootstrap creates account with password_change_required=true
cargo run -- bootstrap --non-interactive

# 2. Login with bootstrap credentials
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "owner", "password": "generated-password"}'

# Response includes JWT with password_change_required=true

# 3. Attempt to access protected endpoint (FAILS)
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "..."}'

# Response: 403 Forbidden
# {"error": "Password change required. Please change your password at /auth/change-password"}

# 4. Check status (ALLOWED)
curl -X GET http://localhost:3000/api/auth/whoami \
  -H "Authorization: Bearer eyJhbGc..."

# Response: 200 OK with user info including password_change_required flag

# 5. Change password (ALLOWED)
curl -X POST http://localhost:3000/api/auth/change-password \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "generated-password",
    "new_password": "my-new-secure-passphrase"
  }'

# Response: 200 OK with new tokens (password_change_required=false)

# 6. Now all endpoints are accessible
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "new-refresh-token"}'

# Response: 200 OK
```

## Common Password List Management

### Overview

The system maintains a local database table of common passwords that should be rejected. Administrators can download and update this list from external sources.

### CLI Command

**Command**: `download-passwords`

Downloads a password list from a URL and loads it into the database.

#### Usage

```bash
cargo run -- download-passwords --url <URL>
```

#### Example

```bash
# Download from a common password list
cargo run -- download-passwords --url https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt

# Output:
# Downloading common password list from: https://...
# ✓ Successfully loaded 10000 passwords into database
```

#### Behavior

1. **Fetch**: Downloads content from the specified URL
2. **Parse**: Reads passwords line-by-line from the response
3. **Load**: Clears existing passwords and inserts new ones in batches (1000 per batch)
4. **Transactional**: All operations occur in a single database transaction
5. **Case-Insensitive**: Passwords are stored in lowercase for case-insensitive matching

#### Recommended Sources

- [SecLists Common Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)
- [OWASP Top 10000 Passwords](https://github.com/OWASP/passfault/blob/master/wordlists/wordlists/)
- Custom organizational password blacklists

### Database Storage

Common passwords are stored in the `common_passwords` table:

```sql
CREATE TABLE common_passwords (
    password TEXT PRIMARY KEY  -- Lowercase password
);
```

The primary key provides indexed lookups for fast validation.

## HaveIBeenPwned Integration

### Overview

The system checks passwords against the HaveIBeenPwned (HIBP) database to detect passwords compromised in data breaches. This uses the k-anonymity model to protect user privacy.

### k-Anonymity Model

The HIBP integration uses k-anonymity to ensure the actual password is never sent to the HIBP API:

1. **Hash Password**: Compute SHA-1 hash of the password
2. **Split Hash**: Extract first 5 characters as prefix, remainder as suffix
3. **Query API**: Send only the 5-character prefix to HIBP
4. **Receive Suffixes**: HIBP returns all hash suffixes matching the prefix
5. **Local Check**: Search locally for the full hash suffix in the response

**Example:**

```
Password: "password123"
SHA-1 Hash: "482C811DA5D5B4BC6D497FFA98491E38"
Prefix (sent to API): "482C8"
Suffix (checked locally): "11DA5D5B4BC6D497FFA98491E38"
```

This ensures HIBP never knows which specific password was checked.

### Caching

To minimize API calls and improve performance, HIBP responses are cached locally:

#### Cache Table

```sql
CREATE TABLE hibp_cache (
    hash_prefix TEXT PRIMARY KEY,  -- 5-character SHA-1 prefix
    response_data TEXT,             -- Full API response (hash suffixes)
    fetched_at INTEGER              -- Unix timestamp
);
```

#### Cache Behavior

- **Cache Hit**: If a fresh cache entry exists for the prefix, use cached data
- **Cache Miss**: If no entry exists or entry is stale, fetch from API and cache
- **Staleness**: Cache entries are considered stale after 30 days (2,592,000 seconds)
- **Upsert**: New API responses update existing cache entries

#### Cache Staleness Configuration

The cache staleness duration is hardcoded to 30 days. This balances:
- **Performance**: Reduces API calls for frequently checked prefixes
- **Freshness**: Ensures new breaches are detected within a reasonable timeframe
- **API Limits**: Respects HIBP rate limits

### Graceful Degradation

If the HIBP API is unavailable or returns an error:

1. **Log Warning**: System logs the error for monitoring
2. **Allow Password**: Validation continues without the compromised check
3. **No User Impact**: Users are not blocked by temporary API issues

This ensures system availability is not dependent on external services.

### API Details

- **Endpoint**: `https://api.pwnedpasswords.com/range/{prefix}`
- **Method**: GET
- **User-Agent**: `Linkstash-Auth`
- **Rate Limit**: HIBP allows reasonable usage without authentication
- **Response Format**: Plain text, one hash suffix per line with count

**Example Response:**

```
11DA5D5B4BC6D497FFA98491E38:3
1E4C9B93F3F0682250B6CF8331B7EE68FD8:2
...
```

## Security Considerations

### Password Storage

- All passwords are hashed using **Argon2id** before storage
- Password hashes include a **pepper** value from environment configuration
- Plaintext passwords are never logged or stored

### Token Invalidation

When a password is changed:
- All refresh tokens are deleted from the database
- Old JWTs become invalid at next validation (short 15-minute expiration)
- User must re-authenticate with new password

### Audit Logging

All password operations are logged to the audit database:

- **Password Changes**: Success/failure, timestamp, user ID, IP address
- **Validation Failures**: Reason for rejection (never the actual password)
- **HIBP Checks**: API failures and warnings

Audit logs never contain:
- Plaintext passwords
- Password hashes
- Valid JWT tokens
- Refresh tokens

### Username Check

The username substring check is case-insensitive and prevents obvious weak passwords like:
- `alice-password123` (username: alice)
- `BOB12345` (username: bob)

For UUID-based usernames (like the owner account), this check is effectively skipped as UUIDs are unlikely to appear in passwords.

## Environment Configuration

Password management uses the following environment variables:

```bash
# Password Security (REQUIRED)
PASSWORD_PEPPER=pepper-min-16-chars-change-in-prod

# Database Configuration
DATABASE_URL=sqlite://auth.db?mode=rwc
AUDIT_DB_PATH=audit.db
```

**Note**: HIBP cache staleness is currently hardcoded to 30 days and not configurable via environment variables.

## Database Migrations

The password management feature requires the following migrations:

1. **m20250127_000001_create_common_passwords.rs** - Creates `common_passwords` table
2. **m20250127_000002_create_hibp_cache.rs** - Creates `hibp_cache` table
3. **m20250127_000003_add_password_change_required.rs** - Adds `password_change_required` column to `users` table

Migrations run automatically on server startup.

## Testing

### Manual Testing Checklist

1. **Length Validation**
   - Try password with < 15 characters (should fail)
   - Try password with 15-128 characters (should pass)
   - Try password with > 128 characters (should fail)

2. **Username Check**
   - Try password containing username (should fail)
   - Try password with username in different case (should fail)
   - Try password without username (should pass)

3. **Common Password Check**
   - Download common password list
   - Try password from the list (should fail)
   - Try unique password (should pass)

4. **HIBP Check**
   - Try known compromised password like "password123" (should fail)
   - Try unique random password (should pass)

5. **Password Change Flow**
   - Change password with correct old password (should succeed)
   - Try with incorrect old password (should fail)
   - Verify old refresh tokens are invalidated
   - Verify new tokens work

6. **Password Change Requirement**
   - Bootstrap new account
   - Login and verify JWT has `password_change_required=true`
   - Try accessing protected endpoint (should get 403)
   - Access `/auth/whoami` (should work)
   - Change password (should work)
   - Verify new JWT has `password_change_required=false`
   - Verify protected endpoints now work

### Swagger UI Testing

The password change endpoint is available in Swagger UI at `/swagger`:

1. Navigate to `/swagger`
2. Find `POST /auth/change-password` under Authentication tag
3. Click "Try it out"
4. Enter old and new passwords
5. Add Authorization header with Bearer token
6. Execute and verify response

## Troubleshooting

### Common Issues

**Issue**: Password validation fails with "Password is too common"
- **Solution**: Choose a more unique password or update the common password list

**Issue**: Password validation fails with "Password has been compromised in a data breach"
- **Solution**: Choose a different password that hasn't been exposed in breaches

**Issue**: HIBP check takes a long time
- **Solution**: First check for a prefix is slow (API call), subsequent checks are fast (cached)

**Issue**: Bootstrap account can't access any endpoints
- **Solution**: This is expected behavior. Change password first at `/auth/change-password`

**Issue**: Common password list is empty
- **Solution**: Run `cargo run -- download-passwords --url <URL>` to populate the list

### Logs

Check application logs for password validation issues:

```bash
# View logs
tail -f logs/app.log

# Look for HIBP warnings
grep "HIBP check failed" logs/app.log
```

Check audit logs for password change events:

```sql
-- Query audit database
sqlite3 audit.db

-- View password change events
SELECT * FROM audit_events 
WHERE event_type IN ('password_changed', 'password_change_failed')
ORDER BY timestamp DESC 
LIMIT 10;
```

## Future Enhancements

Potential improvements to the password management system:

1. **Password History**: Prevent reuse of last N passwords
2. **Password Expiration**: Force periodic password changes after X days
3. **Password Strength Meter**: Provide real-time feedback in UI
4. **Admin-Initiated Password Reset**: Allow admins to force password changes for users
5. **Configurable Password Policy**: Make min/max length configurable via environment variables
6. **Configurable HIBP Staleness**: Allow cache staleness to be configured via environment or system config

## Related Documentation

- [Security & Documentation Protocols](./security-and-docs.md) - Secret management and documentation standards
- [Request Context Pattern](./request-context.md) - How authentication context flows through the system
- [Extending Audit Logs](./extending-audit-logs.md) - Adding new audit events for password operations
