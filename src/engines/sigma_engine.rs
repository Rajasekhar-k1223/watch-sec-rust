use regex::Regex;
use serde_json::json;
use lazy_static::lazy_static;

lazy_static! {
    static ref SIGMA_RULES: Vec<(&'static str, &'static str, Regex, &'static str)> = vec![
        (
            "SIGMA-PWSH-001",
            "Suspicious PowerShell Encoded Command",
            Regex::new(r"(?i)powershell.*-enc").unwrap(),
            "Critical",
        ),
        (
            "SIGMA-LOTL-001",
            "Certutil Network Connection",
            Regex::new(r"(?i)certutil.*-urlcache").unwrap(),
            "High",
        ),
    ];
}

pub fn evaluate_process(cmdline: &str, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    for (id, name, pattern, severity) in SIGMA_RULES.iter() {
        if pattern.is_match(cmdline) {
            println!("[DETECTION] Sigma Rule Triggered: {}", name);
            
            let alert = json!({
                "EventType": "DetectionAlert",
                "Severity": severity,
                "DetectionName": name,
                "RuleId": id,
                "CommandLine": cmdline,
            });
            
            let _ = event_tx.send(alert);
            
            // Note: If Policy allows, we could instantly kill this process here
            // using crate::engines::ransomware's kill logic, but we will leave
            // it as an alert-only mechanism for Sigma right now.
        }
    }
}
