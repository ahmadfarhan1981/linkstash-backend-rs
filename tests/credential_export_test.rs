// Integration tests for credential export functionality

use linkstash_backend::cli::credential_export::{export_credentials, ExportFormat};
use std::fs;
use std::path::Path;

#[test]
fn test_export_display_only() {
    let result = export_credentials("test_user", "test_pass", "owner", ExportFormat::DisplayOnly);
    assert!(result.is_ok());
}

#[test]
fn test_export_skip() {
    let result = export_credentials("test_user", "test_pass", "owner", ExportFormat::Skip);
    assert!(result.is_ok());
}

#[test]
fn test_export_keepass_xml() {
    let username = "test_user_keepass";
    let password = "test_pass_123";
    let role_type = "owner";
    let filename = format!("{}_{}.xml", role_type, username);
    
    // Clean up any existing file
    let _ = fs::remove_file(&filename);
    
    // Export credentials
    let result = export_credentials(username, password, role_type, ExportFormat::KeePassXML);
    assert!(result.is_ok());
    
    // Verify file was created
    assert!(Path::new(&filename).exists());
    
    // Verify file content
    let content = fs::read_to_string(&filename).unwrap();
    assert!(content.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(content.contains("<username>test_user_keepass</username>"));
    assert!(content.contains("<password>test_pass_123</password>"));
    assert!(content.contains("Linkstash OWNER Account"));
    
    // Clean up
    fs::remove_file(&filename).unwrap();
}

#[test]
fn test_export_bitwarden_json() {
    let username = "test_user_bitwarden";
    let password = "test_pass_456";
    let role_type = "system_admin";
    let filename = format!("{}_{}.json", role_type, username);
    
    // Clean up any existing file
    let _ = fs::remove_file(&filename);
    
    // Export credentials
    let result = export_credentials(username, password, role_type, ExportFormat::BitwardenJSON);
    assert!(result.is_ok());
    
    // Verify file was created
    assert!(Path::new(&filename).exists());
    
    // Verify file content
    let content = fs::read_to_string(&filename).unwrap();
    assert!(content.contains("\"encrypted\": false"));
    assert!(content.contains("\"username\": \"test_user_bitwarden\""));
    assert!(content.contains("\"password\": \"test_pass_456\""));
    assert!(content.contains("Linkstash SYSTEM ADMIN Account"));
    
    // Clean up
    fs::remove_file(&filename).unwrap();
}

#[test]
fn test_xml_escaping() {
    // Use a valid filename but test XML escaping in the content
    let username = "test_user_xml";
    let password = "pass<word>&\"'";
    let role_type = "owner";
    let filename = format!("{}_{}.xml", role_type, username);
    
    // Clean up any existing file
    let _ = fs::remove_file(&filename);
    
    // Export credentials with special characters in password
    let result = export_credentials(username, password, role_type, ExportFormat::KeePassXML);
    assert!(result.is_ok());
    
    // Verify file was created
    assert!(Path::new(&filename).exists());
    
    // Verify XML escaping in password field
    let content = fs::read_to_string(&filename).unwrap();
    assert!(content.contains("&lt;"));
    assert!(content.contains("&gt;"));
    assert!(content.contains("&amp;"));
    assert!(content.contains("&quot;"));
    assert!(content.contains("&apos;"));
    
    // Clean up
    fs::remove_file(&filename).unwrap();
}
