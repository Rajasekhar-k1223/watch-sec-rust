/// mail_monitor.rs — Email Intelligence Module
/// Captures sent emails from Outlook (Windows via PowerShell COM) and
/// Thunderbird (Linux/macOS via mbox parsing). Matches the Python agent's
/// behaviour of POSTing structured mail events to POST /api/mail/.
///
/// Deduplication is handled in-memory using a HashSet of Message-IDs so
/// the same email is never reported twice within a single agent session.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Mutex;

// ── In-memory dedup set (Message-ID or Outlook EntryID) ──────────────────────
static SEEN_IDS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn with_seen<F: FnOnce(&mut HashSet<String>) -> bool>(f: F) -> bool {
    if let Ok(mut guard) = SEEN_IDS.lock() {
        let set = guard.get_or_insert_with(HashSet::new);
        f(set)
    } else {
        false
    }
}

/// Returns true if `id` is new (not yet seen), and marks it as seen.
fn mark_seen(id: &str) -> bool {
    if id.is_empty() {
        return true; // If no ID, always report (safest fallback)
    }
    with_seen(|set| {
        if set.contains(id) {
            false
        } else {
            set.insert(id.to_string());
            true
        }
    })
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Capture recent mail events from whatever client is available on this OS.
/// Returns a Vec of JSON objects ready to be POST-ed to /api/mail/
/// Each item matches the MailLogDto schema on the backend.
pub fn capture_mail_events() -> Vec<Value> {
    let mut events: Vec<Value> = Vec::new();

    #[cfg(target_os = "windows")]
    events.extend(capture_outlook_windows());

    #[cfg(not(target_os = "windows"))]
    events.extend(capture_thunderbird_unix());

    events
}

// ── Windows — Outlook COM via PowerShell ─────────────────────────────────────

#[cfg(target_os = "windows")]
fn capture_outlook_windows() -> Vec<Value> {
    crate::modules::com_helper::outlook_com::extract_emails()
}

// ── Linux / macOS — Thunderbird mbox parser ──────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn capture_thunderbird_unix() -> Vec<Value> {
    let mut events = Vec::new();

    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return events;
    }

    // Thunderbird profile locations
    let candidate_bases = vec![
        // Linux
        format!("{}/.thunderbird", home),
        // macOS
        format!("{}/Library/Thunderbird/Profiles", home),
    ];

    for base in &candidate_bases {
        let base_path = std::path::Path::new(base);
        if !base_path.exists() {
            continue;
        }

        // Iterate profile directories
        let Ok(entries) = std::fs::read_dir(base_path) else {
            continue;
        };
        for entry in entries.flatten() {
            let profile_dir = entry.path();
            if !profile_dir.is_dir() {
                continue;
            }

            // Common Sent folder paths
            let candidates = vec![
                profile_dir.join("Mail").join("Local Folders").join("Sent"),
                profile_dir.join("ImapMail").join("Sent"),
                profile_dir.join("Mail").join("Local Folders").join("Sent Messages"),
            ];

            for sent_path in candidates {
                if sent_path.exists() {
                    let parsed = parse_mbox_file(&sent_path);
                    events.extend(parsed);
                }
            }
        }
    }

    crate::log_msg(&format!(
        "[MailMonitor] Captured {} new Thunderbird mail events.",
        events.len()
    ));
    events
}

#[cfg(not(target_os = "windows"))]
fn parse_mbox_file(path: &std::path::Path) -> Vec<Value> {
    let mut events = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return events,
    };

    // RFC-2822 mbox: messages separated by "From " lines
    let mut in_headers = false;
    let mut in_body    = false;
    let mut sender     = String::new();
    let mut recipient  = String::new();
    let mut subject    = String::new();
    let mut msg_id     = String::new();
    let mut body_lines: Vec<&str> = Vec::new();

    let flush = |sender: &str, recipient: &str, subject: &str, msg_id: &str,
                  body_lines: &[&str], events: &mut Vec<Value>| {
        if sender.is_empty() && subject.is_empty() {
            return;
        }
        if !mark_seen(msg_id) {
            return;
        }
        let body_preview: String = body_lines
            .iter()
            .flat_map(|l| l.chars())
            .take(500)
            .collect();
        events.push(json!({
            "Sender":          sender,
            "Recipient":       recipient,
            "Subject":         subject,
            "BodyPreview":     body_preview,
            "HasAttachments":  false,
            "AttachmentNames": "",
            "Attachments":     [],
        }));
    };

    for line in content.lines() {
        if line.starts_with("From ") && !in_body {
            // Message boundary — flush previous
            if in_headers || in_body {
                flush(&sender, &recipient, &subject, &msg_id, &body_lines, &mut events);
            }
            // Reset state
            in_headers = true;
            in_body    = false;
            sender.clear();
            recipient.clear();
            subject.clear();
            msg_id.clear();
            body_lines.clear();
            continue;
        }

        if in_headers && line.is_empty() {
            // Blank line signals end of headers → start of body
            in_headers = false;
            in_body    = true;
            continue;
        }

        if in_headers {
            // Parse header fields (case-insensitive prefix match)
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("from:") {
                sender = line[5..].trim().to_string();
            } else if lower.starts_with("to:") {
                recipient = line[3..].trim().to_string();
            } else if lower.starts_with("subject:") {
                subject = line[8..].trim().to_string();
            } else if lower.starts_with("message-id:") {
                msg_id = line[11..].trim().to_string();
            }
        } else if in_body && body_lines.len() < 15 {
            body_lines.push(line);
        }
    }

    // Flush last message
    if in_headers || in_body {
        flush(&sender, &recipient, &subject, &msg_id, &body_lines, &mut events);
    }

    events
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Best-effort MIME type guess from filename extension.
#[allow(dead_code)]
fn guess_content_type(filename: &str) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pdf")                                    { return "application/pdf"; }
    if lower.ends_with(".xlsx") || lower.ends_with(".xls")       { return "application/vnd.ms-excel"; }
    if lower.ends_with(".docx") || lower.ends_with(".doc")       { return "application/msword"; }
    if lower.ends_with(".zip")                                    { return "application/zip"; }
    if lower.ends_with(".png")                                    { return "image/png"; }
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg")       { return "image/jpeg"; }
    if lower.ends_with(".txt")                                    { return "text/plain"; }
    if lower.ends_with(".csv")                                    { return "text/csv"; }
    if lower.ends_with(".exe") || lower.ends_with(".dll")        { return "application/x-msdownload"; }
    "application/octet-stream"
}
