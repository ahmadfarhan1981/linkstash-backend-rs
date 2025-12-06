use crate::app_data::AppData;
use crate::services::audit_logger;
use crate::types::internal::context::RequestContext;

/// Download and load common password list from URL
/// 
/// Passwords are converted to lowercase for case-insensitive matching.
/// The list should contain one password per line.
/// 
/// # Returns
/// * `Ok(())` - Passwords downloaded and loaded successfully
/// * `Err(...)` - Download or database operation failed
pub async fn download_and_load_passwords(
    url: &str,
    app_data: &AppData,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = RequestContext::for_cli("download-passwords");
    
    println!("Downloading common password list from: {}", url);
    
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP request failed with status: {}", response.status()).into());
    }
    
    let content = response.text().await?;
    let passwords: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    
    println!("Downloaded {} passwords", passwords.len());
    
    let count = app_data.common_password_store.load_passwords(passwords).await?;
    
    println!("✓ Successfully loaded {} passwords into database", count);
    
    audit_logger::log_common_password_list_downloaded(
        &app_data.audit_store,
        &ctx,
        url,
        count,
    )
    .await?;
    
    Ok(())
}
