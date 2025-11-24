# Bootstrap and Owner Management

## Overview

This guide explains how to bootstrap the Linkstash authentication system and manage the Owner account. The bootstrap process creates the initial administrative accounts needed to operate the system, while owner management provides emergency access controls.

## Table of Contents

1. [Understanding the Admin Role System](#understanding-the-admin-role-system)
2. [Bootstrap Process](#bootstrap-process)
3. [Owner Account Management](#owner-account-management)
4. [Credential Management](#credential-management)
5. [Security Best Practices](#security-best-practices)
6. [Troubleshooting](#troubleshooting)

---

## Understanding the Admin Role System

The system uses a three-tier administrative role structure:

### Owner
- **Purpose:** Emergency admin management only
- **Capabilities:** Can assign/remove System Admin and Role Admin roles
- **Status:** INACTIVE by default (must be explicitly activated)
- **Quantity:** Only one per system
- **Use Case:** Initial setup and emergency situations

### System Admin
- **Purpose:** Day-to-day system operations
- **Capabilities:** User management, system configuration, token revocation, can assign/remove Role Admin roles
- **Status:** ACTIVE by default
- **Quantity:** Multiple allowed (recommended: 2-5)
- **Use Case:** Regular administrative tasks

### Role Admin
- **Purpose:** Reserved for future application role management
- **Capabilities:** Flag exists in schema but functionality not yet implemented
- **Status:** ACTIVE by default
- **Quantity:** Multiple allowed
- **Use Case:** Future app_roles management (separate spec)

### Design Rationale

The Owner account is kept inactive by default to minimize attack surface. It should only be activated when needed for emergency operations (like recovering from a compromised System Admin account) and deactivated immediately after use.

---

## Bootstrap Process

Bootstrap is a one-time operation that creates the initial administrative accounts. It must be run before the system can be used.

### Prerequisites

1. Database migrations have been run: `sea-orm-cli migrate up`
2. Environment variables are configured (`.env` file exists with `JWT_SECRET`)
3. Server is NOT running (bootstrap requires exclusive database access)

### Running Bootstrap

```bash
cargo run -- bootstrap
```

### Bootstrap Flow

The bootstrap command will guide you through the following steps:

#### 1. Owner Account Creation

```
Creating Owner account...
Generated username: a1b2c3d4-e5f6-7890-abcd-ef1234567890

Choose password option:
1. Auto-generate secure password
2. Enter password manually

Enter choice (1 or 2):
```

**Recommendation:** Use auto-generated passwords for all bootstrap accounts. They meet all security requirements and eliminate human error.

If you choose manual entry, the password will be accepted without validation (password strength enforcement will be added in a future update).

#### 2. Owner Credentials Display

```
✅ Owner account created successfully!

Username: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Password: Xy9#mK2$pL5@nQ8!wR3%

⚠️  WARNING: Owner account is INACTIVE (system flag owner_active=false)
⚠️  The owner account cannot be used until activated via CLI:
⚠️  cargo run -- owner activate
⚠️  
⚠️  Keep owner credentials secure and only activate when needed for
⚠️  emergency admin management. Deactivate immediately after use.

Choose credential export option:
1. Display only (shown above)
2. Copy username to clipboard
3. Copy password to clipboard
4. Export to KeePassX XML
5. Export to Bitwarden JSON
6. Skip export

Enter choice (1-6):
```

**Important:** The password is displayed only once. Choose an export option to save it securely.

#### 3. System Admin Accounts

```
How many System Admin accounts to create? (0-10): 2

Creating System Admin account 1 of 2...
Generated username: b2c3d4e5-f6a7-8901-bcde-f12345678901

Choose password option:
1. Auto-generate secure password
2. Enter password manually

Enter choice (1 or 2): 1

✅ System Admin account created successfully!

Username: b2c3d4e5-f6a7-8901-bcde-f12345678901
Password: Qw7&tY4#uI9@oP2$aS6%

Choose credential export option:
1. Display only (shown above)
2. Copy username to clipboard
3. Copy password to clipboard
4. Export to KeePassX XML
5. Export to Bitwarden JSON
6. Skip export

Enter choice (1-6): 4

✅ Credentials exported to: system_admin_b2c3d4e5.xml
```

This process repeats for each System Admin account.

#### 4. Role Admin Accounts

```
How many Role Admin accounts to create? (0-10): 1

Creating Role Admin account 1 of 1...
[... similar flow to System Admin ...]
```

#### 5. Bootstrap Complete

```
✅ Bootstrap completed successfully!

Summary:
- Owner account created (INACTIVE)
- 2 System Admin accounts created (ACTIVE)
- 1 Role Admin account created (ACTIVE)

Next steps:
1. Distribute credentials to administrators securely
2. System Admins can log in immediately
3. Activate Owner account only when needed: cargo run -- owner activate
```

### What Happens During Bootstrap

1. **Validation:** Checks that no owner account exists (prevents duplicate bootstrap)
2. **Owner Creation:** Creates owner account with UUID username, is_owner=true, status=INACTIVE
3. **System Config:** Verifies system_config table has owner_active=false (set by migration)
4. **Admin Creation:** Creates System Admin and Role Admin accounts with UUID usernames, appropriate flags, status=ACTIVE
5. **Audit Logging:** Logs all account creations to audit database
6. **Credential Export:** Saves credentials to password manager formats if requested

### Bootstrap Rejection

If you attempt to run bootstrap when an owner already exists:

```
❌ Error: System already bootstrapped
An owner account already exists. Bootstrap can only be run once.

To manage existing admin accounts, use:
- cargo run -- owner activate    (activate owner account)
- cargo run -- owner deactivate  (deactivate owner account)
- cargo run -- owner info        (view owner information)
```

---

## Owner Account Management

The Owner account is managed exclusively through CLI commands that require server access. This adds a physical security layer.

### Viewing Owner Information

Check the owner account status without making changes:

```bash
cargo run -- owner info
```

**Output:**
```
Owner Account Information:
Username: a1b2c3d4-e5f6-7890-abcd-ef1234567890
User ID: 1
Status: INACTIVE (owner_active=false)

The owner account cannot log in until activated.
To activate: cargo run -- owner activate
```

### Activating the Owner Account

Enable the owner account for emergency use:

```bash
cargo run -- owner activate
```

**Output:**
```
⚠️  WARNING: You are about to activate the Owner account.
⚠️  This should only be done for emergency admin management.
⚠️  Deactivate the account immediately after use.

Are you sure you want to activate the Owner account? (yes/no): yes

✅ Owner account activated successfully!

The owner can now log in using their credentials.
Remember to deactivate after use: cargo run -- owner deactivate
```

**What Happens:**
1. Confirmation prompt (requires typing "yes")
2. System config `owner_active` flag set to true
3. Event logged to audit database with timestamp and CLI operation type
4. Owner can now log in via API

### Deactivating the Owner Account

Disable the owner account after emergency use:

```bash
cargo run -- owner deactivate
```

**Output:**
```
⚠️  WARNING: You are about to deactivate the Owner account.
⚠️  The owner will not be able to log in after deactivation.
⚠️  All active owner sessions will be invalidated.

Are you sure you want to deactivate the Owner account? (yes/no): yes

✅ Owner account deactivated successfully!

The owner account is now inactive and cannot log in.
To reactivate: cargo run -- owner activate
```

**What Happens:**
1. Confirmation prompt (requires typing "yes")
2. System config `owner_active` flag set to false
3. All owner refresh tokens deleted from database
4. Event logged to audit database
5. Owner cannot log in (login endpoint checks owner_active flag)

**Note:** The owner can also deactivate their own account via the API endpoint `/admin/owner/deactivate` while logged in. This is useful for self-service deactivation after completing emergency tasks.

### Owner Login Flow

When the owner attempts to log in:

1. Login endpoint receives username and password
2. Validates credentials against database
3. **Checks system config `owner_active` flag**
4. If `owner_active=false`: Returns 403 Forbidden with message "Owner account is inactive"
5. If `owner_active=true`: Issues JWT and refresh token normally

---

## Credential Management

Bootstrap accounts use UUID usernames and require secure credential handling.

### Username Format

All bootstrap accounts use UUID v4 usernames:
```
a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Rationale:** UUIDs are:
- Unpredictable (cannot be guessed or enumerated)
- Unique (no collisions)
- Not personally identifiable (no user information leaked)

### Password Requirements

Currently, bootstrap accepts any password without validation. Password strength enforcement will be added in a future update via the password-management spec.

**Current Behavior:**
- Manual passwords: Accepted without validation
- Auto-generated passwords: 20 characters with uppercase, lowercase, digits, and symbols

**Future Behavior:**
- Minimum 15 characters
- Maximum 64 characters
- Checked against common/compromised password lists

### Export Formats

Bootstrap supports multiple credential export formats for secure distribution:

#### 1. Display Only
Credentials shown in terminal only. Use this if you're entering them directly into a password manager.

#### 2. Clipboard Copy
Copies username or password to system clipboard. Useful for quick entry into password managers.

**Platform Support:**
- Windows: Uses clipboard API
- macOS: Uses pbcopy
- Linux: Uses xclip or xsel

#### 3. KeePassX XML
Exports credentials in KeePassX XML format compatible with:
- KeePass
- KeePassX
- KeePassXC

**File Format:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<database>
  <entry>
    <title>Linkstash Owner</title>
    <username>a1b2c3d4-e5f6-7890-abcd-ef1234567890</username>
    <password>Xy9#mK2$pL5@nQ8!wR3%</password>
    <url>https://your-linkstash-instance.com</url>
  </entry>
</database>
```

**Filename:** `owner_a1b2c3d4.xml` (role_type + first 8 chars of username)

#### 4. Bitwarden JSON
Exports credentials in Bitwarden JSON format compatible with:
- Bitwarden
- Vaultwarden (self-hosted)

**File Format:**
```json
{
  "encrypted": false,
  "items": [
    {
      "type": 1,
      "name": "Linkstash Owner",
      "login": {
        "username": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "password": "Xy9#mK2$pL5@nQ8!wR3%",
        "uris": [
          {
            "uri": "https://your-linkstash-instance.com"
          }
        ]
      }
    }
  ]
}
```

**Filename:** `owner_a1b2c3d4.json`

#### 5. Skip Export
No export performed. Credentials are only displayed in terminal.

**Warning:** If you skip export, you must manually save the credentials. They will not be displayed again.

### Importing Credentials

#### KeePassX/KeePassXC
1. Open KeePassXC
2. File → Import → KeePassX XML
3. Select the exported `.xml` file
4. Credentials appear in your database

#### Bitwarden
1. Open Bitwarden web vault
2. Tools → Import Data
3. Select format: "Bitwarden (json)"
4. Choose the exported `.json` file
5. Import

#### Vaultwarden
Same process as Bitwarden (uses same import format).

### Credential Distribution

For team deployments:

1. **Individual Export:** Each account gets its own export file during bootstrap
2. **Secure Transfer:** Use encrypted channels (Signal, encrypted email, secure file share)
3. **Verification:** Confirm receipt before deleting export files
4. **Cleanup:** Delete export files after distribution
5. **Password Change:** Users should change passwords on first login (will be enforced in future update)

---

## Security Best Practices

### Owner Account Security

#### Keep Owner Inactive
- Only activate for emergency operations
- Deactivate immediately after use
- Monitor audit logs for owner activation events

#### Secure Owner Credentials
- Store in password manager (not plaintext file)
- Limit access to owner credentials (only senior administrators)
- Use separate password manager entry from personal accounts
- Consider physical security (hardware security key, secure enclave)

#### Emergency Use Only
Owner should be used for:
- Recovering from compromised System Admin accounts
- Initial system setup
- Disaster recovery scenarios

Owner should NOT be used for:
- Day-to-day administration (use System Admin)
- Regular user management (use System Admin)
- Application role management (use Role Admin when implemented)

### System Admin Security

#### Multiple Admins
- Create 2-5 System Admin accounts during bootstrap
- Ensures availability if one account is compromised or unavailable
- Enables separation of duties

#### Active Monitoring
- Review audit logs regularly for admin actions
- Monitor for unusual patterns (off-hours access, bulk operations)
- Set up alerts for sensitive operations

#### Credential Rotation
- Change passwords periodically (will be enforced in future update)
- Rotate after personnel changes
- Use strong, unique passwords

### Audit Logging

All bootstrap and owner management operations are logged to the audit database:

**Bootstrap Events:**
- Owner account creation
- System Admin account creation
- Role Admin account creation

**Owner Management Events:**
- Owner activation (CLI)
- Owner deactivation (CLI or API)
- Owner information queries (CLI)

**Audit Log Fields:**
- Timestamp
- Event type
- Actor (who performed the action)
- Target (who was affected)
- IP address (for API operations)
- Operation method (CLI vs API)

### Self-Modification Prevention

The system prevents users from modifying their own admin roles:

```
❌ Error: Cannot modify your own admin roles
```

This prevents privilege escalation through compromised sessions. Even if an attacker gains access to an admin account, they cannot grant themselves additional privileges.

---

## Troubleshooting

### Bootstrap Issues

#### "System already bootstrapped"

**Problem:** An owner account already exists.

**Solution:** Bootstrap can only be run once. Use owner management commands instead:
```bash
cargo run -- owner info
cargo run -- owner activate
```

If you need to start over (development only):
1. Delete the database files: `auth.db`, `audit.db`
2. Run migrations: `sea-orm-cli migrate up`
3. Run bootstrap again

#### "Database error: table user not found"

**Problem:** Migrations haven't been run.

**Solution:**
```bash
sea-orm-cli migrate up
cargo run -- bootstrap
```

#### "Failed to load secrets"

**Problem:** Environment variables not configured.

**Solution:** Ensure `.env` file exists with required secrets:
```bash
JWT_SECRET=your-secret-key-min-32-chars-long-change-this
```

See `.env.example` for all required variables.

### Owner Management Issues

#### "Owner account not found"

**Problem:** Bootstrap hasn't been run or database is corrupted.

**Solution:**
1. Check if bootstrap was run: `cargo run -- owner info`
2. If not, run bootstrap: `cargo run -- bootstrap`
3. If database is corrupted, restore from backup or re-bootstrap (development only)

#### "Owner account is inactive" (during login)

**Problem:** Owner account hasn't been activated.

**Solution:**
```bash
cargo run -- owner activate
```

Then attempt login again.

#### Owner activation doesn't persist

**Problem:** Multiple instances accessing the same database or database connection issues.

**Solution:**
1. Ensure server is not running during CLI operations
2. Check database file permissions
3. Verify only one process is accessing the database

### Credential Export Issues

#### "Failed to copy to clipboard"

**Problem:** Clipboard utilities not installed (Linux).

**Solution:**
- Install xclip: `sudo apt-get install xclip`
- Or install xsel: `sudo apt-get install xsel`
- Or use file export instead

#### "Permission denied" when writing export file

**Problem:** No write permissions in current directory.

**Solution:**
- Run from a directory where you have write permissions
- Or specify output directory (future enhancement)

#### Export file not found after creation

**Problem:** File created in unexpected location.

**Solution:** Export files are created in the current working directory. Check where you ran the command:
```bash
pwd  # Show current directory
ls -la *.xml *.json  # List export files
```

### Login Issues

#### "Invalid credentials" with correct password

**Problem:** Owner account is inactive.

**Solution:** Activate the owner account:
```bash
cargo run -- owner activate
```

#### "User not found" with UUID username

**Problem:** Username copied incorrectly (extra spaces, missing characters).

**Solution:**
- Copy username from password manager (don't type manually)
- Verify full UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Check for trailing spaces or newlines

#### JWT validation fails after owner deactivation

**Problem:** Old JWTs still in use after deactivation.

**Solution:** This is expected behavior. Deactivation:
1. Deletes all refresh tokens (prevents new access tokens)
2. Existing access tokens expire naturally (15 minutes)

Wait 15 minutes or restart the client application to clear cached tokens.

---

## Command Reference

### Bootstrap Commands

```bash
# Run initial system bootstrap
cargo run -- bootstrap
```

### Owner Management Commands

```bash
# View owner account information
cargo run -- owner info

# Activate owner account (enable login)
cargo run -- owner activate

# Deactivate owner account (disable login)
cargo run -- owner deactivate
```

### Database Commands

```bash
# Run database migrations
sea-orm-cli migrate up

# Rollback last migration
sea-orm-cli migrate down

# Check migration status
sea-orm-cli migrate status
```

### Server Commands

```bash
# Start server (after bootstrap)
cargo run

# Start server with specific environment
JWT_SECRET=xxx cargo run

# Build release binary
cargo build --release
./target/release/linkstash
```

---

## Next Steps

After completing bootstrap:

1. **Distribute Credentials:** Securely share credentials with administrators
2. **Test Login:** Verify System Admins can log in
3. **Start Server:** Run `cargo run` to start the API server
4. **Configure Monitoring:** Set up audit log monitoring
5. **Document Procedures:** Create runbooks for your team
6. **Backup Database:** Establish backup procedures for `auth.db` and `audit.db`

For API usage after bootstrap, see the Swagger UI at `http://localhost:3000/swagger`.

