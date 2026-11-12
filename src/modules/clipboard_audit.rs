use serde_json::json;
use arboard::Clipboard;

pub fn audit_clipboard() -> serde_json::Value {
    let mut contents = "No active display or clipboard access failed".to_string();
    let mut dlp_violation = false;
    let mut action_taken = "None";
    let mut findings_list = Vec::new();

    if let Ok(mut clipboard) = Clipboard::new() {
        if let Ok(text) = clipboard.get_text() {
            if text.is_empty() {
                contents = "[Clipboard is empty]".to_string();
            } else {
                contents = text.clone();

                // Active DataGuard Clipboard Inspection
                let findings = crate::engines::dlp_engine::inspect_content(&text);
                if !findings.is_empty() {
                    dlp_violation = true;
                    findings_list = findings;

                    // Active DLP Enforcement: Erase sensitive clipboard payload to prevent paste exfiltration
                    let _ = clipboard.set_text("[RESTRICTED CONTENT - BLOCKED BY MONITORIX DATAGUARD]");
                    action_taken = "BlockedAndScrubbed";
                    crate::log_msg("[DataGuard Clipboard] Sensitive content intercepted on clipboard. Scrubbed payload.");
                }
            }
        } else {
            contents = "[Clipboard contains non-text data or is inaccessible]".to_string();
        }
    }

    // Limit clipboard size to avoid massive payloads
    let truncated: String = contents.chars().take(500).collect();

    json!({
        "EventType": if dlp_violation { "ClipboardDlpViolation" } else { "ClipboardAuditReport" },
        "IsViolation": dlp_violation,
        "ActionTaken": action_taken,
        "Findings": findings_list,
        "ClipboardContents": if dlp_violation { "[REDACTED BY DATAGUARD]" } else { &truncated },
        "Timestamp": chrono::Utc::now().to_rfc3339()
    })
}
