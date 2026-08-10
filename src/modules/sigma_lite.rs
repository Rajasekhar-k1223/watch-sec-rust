use regex::Regex;
use serde_json::json;
use lazy_static::lazy_static;

#[derive(Clone)]
pub struct SigmaRule {
    pub id: String,
    pub name: String,
    pub pattern: Regex,
    pub severity: String,
}

lazy_static! {
    static ref SIGMA_RULES: Vec<SigmaRule> = vec![
        SigmaRule {
            id: "SIGMA-PWSH-001".to_string(),
            name: "Suspicious PowerShell Encoded Command".to_string(),
            pattern: Regex::new(r"(?i)powershell.*-enc").unwrap(),
            severity: "CRITICAL".to_string(),
        },
        SigmaRule {
            id: "SIGMA-LOTL-001".to_string(),
            name: "Certutil Network Connection".to_string(),
            pattern: Regex::new(r"(?i)certutil.*-urlcache").unwrap(),
            severity: "HIGH".to_string(),
        },
        SigmaRule {
            id: "SIGMA-NET-001".to_string(),
            name: "Unauthorized Outbound Download (curl/wget)".to_string(),
            pattern: Regex::new(r"(?i)(curl|wget).*https?://").unwrap(),
            severity: "MEDIUM".to_string(),
        },
        SigmaRule {
            id: "SIGMA-SYS-002".to_string(),
            name: "Rogue VPN Client Execution".to_string(),
            pattern: Regex::new(r"(?i)(openvpn|wireguard|nordvpn).*--config").unwrap(),
            severity: "HIGH".to_string(),
        },
        SigmaRule {
            id: "SIGMA-RANSOM-003".to_string(),
            name: "VSSAdmin Shadow Copy Deletion".to_string(),
            pattern: Regex::new(r"(?i)vssadmin.*delete shadows").unwrap(),
            severity: "CRITICAL".to_string(),
        },
    ];
}

pub struct SigmaLiteEngine;

impl SigmaLiteEngine {
    pub fn new() -> Self {
        SigmaLiteEngine
    }

    pub fn evaluate_event(&self, event_type: &str, cmdline: &str) -> Option<serde_json::Value> {
        if event_type != "ProcessCreate" {
            return None;
        }

        for rule in SIGMA_RULES.iter() {
            if rule.pattern.is_match(cmdline) {
                println!("[DETECTION] Rule Triggered locally: {}", rule.name);
                
                return Some(json!({
                    "event_type": "DetectionAlert",
                    "severity": rule.severity,
                    "detection_name": rule.name,
                    "rule_id": rule.id,
                    "triggering_event": {
                        "command_line": cmdline
                    },
                    "automated_response": "Pending"
                }));
            }
        }
        None
    }
}
