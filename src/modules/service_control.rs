use std::process::Command;

pub fn manage_service(service_name: &str, action: &str) -> Result<String, String> {
    let act = match action.to_lowercase().as_str() {
        "start" => "start",
        "stop" => "stop",
        "restart" => "restart",
        _ => return Err(format!("Unsupported service action: {}", action)),
    };

    #[cfg(unix)]
    let mut cmd = {
        let mut c = crate::hidden_command!("systemctl");
        c.arg(act).arg(service_name);
        c
    };

    #[cfg(windows)]
    let mut cmd = {
        let mut c = crate::hidden_command!("net");
        c.arg(act).arg(service_name);
        c
    };

    let output = cmd.output().map_err(|e| format!("Failed to execute service command: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(format!("Successfully performed '{}' on service '{}'.\n{}", action, service_name, stdout))
    } else {
        Err(format!("Failed to perform '{}' on service '{}'.\nStdout: {}\nStderr: {}", 
            action, service_name, stdout, stderr))
    }
}
