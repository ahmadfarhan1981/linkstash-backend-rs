// Credential export functionality for bootstrap accounts
// Supports multiple export formats including password managers

use arboard::Clipboard;
use std::fs;

/// Export format options for credentials
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    /// Display credentials in terminal only
    DisplayOnly,
    /// Copy username to clipboard
    CopyUsername,
    /// Copy password to clipboard
    CopyPassword,
    /// Export to KeePassX XML format
    KeePassXML,
    /// Export to Bitwarden JSON format
    BitwardenJSON,
    /// Skip credential export
    Skip,
}

/// Export credentials in the specified format
/// 
/// # Arguments
/// * `username` - Account username
/// * `password` - Account password (plaintext)
/// * `role_type` - Role type for file naming (e.g., "owner", "system_admin")
/// * `format` - Export format to use
/// 
/// # Returns
/// * `Ok(())` - Export completed successfully
/// * `Err(...)` - Export failed
pub fn export_credentials(
    username: &str,
    password: &str,
    role_type: &str,
    format: ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        ExportFormat::DisplayOnly => {
            // Credentials already displayed by caller, nothing to do
            Ok(())
        }
        ExportFormat::CopyUsername => {
            copy_to_clipboard(username)?;
            println!("✓ Username copied to clipboard");
            Ok(())
        }
        ExportFormat::CopyPassword => {
            copy_to_clipboard(password)?;
            println!("✓ Password copied to clipboard");
            Ok(())
        }
        ExportFormat::KeePassXML => {
            export_keepass_xml(username, password, role_type)?;
            Ok(())
        }
        ExportFormat::BitwardenJSON => {
            export_bitwarden_json(username, password, role_type)?;
            Ok(())
        }
        ExportFormat::Skip => {
            // User chose to skip export
            Ok(())
        }
    }
}

/// Copy text to system clipboard
fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text)?;
    Ok(())
}

/// Export credentials to KeePassX XML format
/// 
/// Creates a file named {role_type}_{username}.xml with KeePassX-compatible XML
fn export_keepass_xml(
    username: &str,
    password: &str,
    role_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = format!("{}_{}.xml", role_type, username);
    
    // KeePassX XML format (compatible with KeePass, KeePassX, KeePassXC)
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE KEEPASSX_DATABASE>
<database>
  <group>
    <title>Linkstash Admin Accounts</title>
    <entry>
      <title>Linkstash {} Account</title>
      <username>{}</username>
      <password>{}</password>
      <url>http://localhost:3000</url>
      <comment>Bootstrap account created on {}</comment>
    </entry>
  </group>
</database>"#,
        role_type.replace('_', " ").to_uppercase(),
        escape_xml(username),
        escape_xml(password),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    
    fs::write(&filename, xml)?;
    println!("✓ Credentials exported to {}", filename);
    Ok(())
}

/// Export credentials to Bitwarden JSON format
/// 
/// Creates a file named {role_type}_{username}.json with Bitwarden-compatible JSON
fn export_bitwarden_json(
    username: &str,
    password: &str,
    role_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = format!("{}_{}.json", role_type, username);
    
    // Bitwarden JSON export format (compatible with Bitwarden, Vaultwarden)
    let json = serde_json::json!({
        "encrypted": false,
        "folders": [],
        "items": [
            {
                "id": uuid::Uuid::new_v4().to_string(),
                "organizationId": null,
                "folderId": null,
                "type": 1,
                "name": format!("Linkstash {} Account", role_type.replace('_', " ").to_uppercase()),
                "notes": format!("Bootstrap account created on {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")),
                "favorite": false,
                "login": {
                    "username": username,
                    "password": password,
                    "totp": null,
                    "uris": [
                        {
                            "match": null,
                            "uri": "http://localhost:3000"
                        }
                    ]
                },
                "collectionIds": []
            }
        ]
    });
    
    fs::write(&filename, serde_json::to_string_pretty(&json)?)?;
    println!("✓ Credentials exported to {}", filename);
    Ok(())
}

/// Escape special XML characters
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
