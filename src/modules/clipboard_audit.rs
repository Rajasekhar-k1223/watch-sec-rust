use serde_json::json;
use arboard::Clipboard;

pub fn audit_clipboard() -> serde_json::Value {
    let mut contents = "No active display or clipboard access failed".to_string();

    if let Ok(mut clipboard) = Clipboard::new() {
        if let Ok(text) = clipboard.get_text() {
            if text.is_empty() {
                contents = "[Clipboard is empty]".to_string();
            } else {
                contents = text;
            }
        } else {
            contents = "[Clipboard contains non-text data or is inaccessible]".to_string();
        }
    }

    // Limit clipboard size to avoid massive payloads
    let truncated: String = contents.chars().take(500).collect();

    json!({
        "EventType": "ClipboardAuditReport",
        "ClipboardContents": truncated
    })
}
