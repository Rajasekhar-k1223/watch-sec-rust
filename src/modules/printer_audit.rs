use serde_json::json;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{BufRead, BufReader};

pub fn is_printer_allowed(printer_name: &str) -> bool {
    let lower = printer_name.to_lowercase();
    // Block virtual print-to-PDF / XPS by default for sensitive documents
    if lower.contains("pdf") || lower.contains("xps") || lower.contains("onenote") || lower.contains("fax") {
        return false;
    }
    true
}

#[cfg(unix)]
pub fn audit_cups_print_jobs() -> Option<serde_json::Value> {
    let cups_log_path = "/var/log/cups/page_log";
    let mut jobs = Vec::new();
    let mut blocked_count = 0;

    if let Ok(file) = fs::File::open(cups_log_path) {
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        for line in reader.lines().flatten() {
            lines.push(line);
        }

        for l in lines.iter().rev().take(5) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 6 {
                let printer = parts.get(0).copied().unwrap_or("Unknown");
                let user = parts.get(1).copied().unwrap_or("Unknown");
                let job_id = parts.get(2).copied().unwrap_or("0");
                let allowed = is_printer_allowed(printer);

                if !allowed {
                    blocked_count += 1;
                    // Cancel print job on unauthorized/virtual printer
                    let _ = crate::hidden_command!("cancel").arg(job_id).output();
                    crate::log_msg(&format!("[DataGuard Print] Blocked print job #{} on virtual printer {}", job_id, printer));
                }

                jobs.push(json!({
                    "Printer": printer,
                    "User": user,
                    "JobId": job_id,
                    "Time": parts.get(3).copied().unwrap_or("Unknown"),
                    "Pages": parts.get(4).copied().unwrap_or("1"),
                    "IsAllowed": allowed,
                    "ActionTaken": if allowed { "Printed" } else { "CancelledByDataGuard" }
                }));
            }
        }
    }

    if jobs.is_empty() {
        return None;
    }

    Some(json!({
        "Type": "PrinterAudit",
        "RecentJobs": jobs,
        "BlockedJobs": blocked_count,
        "Timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

#[cfg(windows)]
pub fn audit_cups_print_jobs() -> Option<serde_json::Value> {
    // Windows Print Spooler WMI & Spool directory audit
    use wmi::{COMLibrary, WMIConnection};
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Win32_PrintJob {
        pub document: Option<String>,
        pub name: Option<String>,
        pub owner: Option<String>,
        pub job_id: Option<u32>,
        pub total_pages: Option<u32>,
    }

    if let Ok(com_con) = COMLibrary::new() {
        if let Ok(wmi_con) = WMIConnection::with_namespace_path("ROOT\\CIMV2", com_con.into()) {
            if let Ok(results) = wmi_con.raw_query::<Win32_PrintJob>("SELECT Document, Name, Owner, JobId, TotalPages FROM Win32_PrintJob") {
                if !results.is_empty() {
                    let mut jobs = Vec::new();
                    for job in results {
                        let doc = job.document.unwrap_or_default();
                        let printer = job.name.unwrap_or_default();
                        let allowed = is_printer_allowed(&printer);

                        jobs.push(json!({
                            "Document": doc,
                            "Printer": printer,
                            "Owner": job.owner.unwrap_or_default(),
                            "JobId": job.job_id.unwrap_or(0),
                            "Pages": job.total_pages.unwrap_or(1),
                            "IsAllowed": allowed,
                            "ActionTaken": if allowed { "Allow" } else { "BlockedVirtualPrinter" }
                        }));
                    }
                    return Some(json!({
                        "Type": "PrinterAudit",
                        "Platform": "Windows",
                        "RecentJobs": jobs,
                        "Timestamp": chrono::Utc::now().to_rfc3339()
                    }));
                }
            }
        }
    }
    None
}
