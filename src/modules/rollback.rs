use std::fs;
use std::path::Path;

pub fn backup_policy(current_path: &str) -> Result<String, String> {
    if !Path::new(current_path).exists() {
        return Ok("No existing policy to backup".to_string());
    }
    
    let backup_path = format!("{}.bak", current_path);
    match fs::copy(current_path, &backup_path) {
        Ok(_) => Ok(format!("Policy backed up to {}", backup_path)),
        Err(e) => Err(format!("Failed to backup policy: {}", e))
    }
}

pub fn rollback_policy(current_path: &str) -> Result<String, String> {
    let backup_path = format!("{}.bak", current_path);
    
    if !Path::new(&backup_path).exists() {
        return Err("No backup policy found to rollback to.".to_string());
    }

    match fs::copy(&backup_path, current_path) {
        Ok(_) => Ok("Successfully rolled back policy to previous known-good state.".to_string()),
        Err(e) => Err(format!("Failed to restore policy: {}", e))
    }
}
