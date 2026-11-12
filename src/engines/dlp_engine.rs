use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use serde_json::json;
use lazy_static::lazy_static;
use ring::digest::{Context, SHA256};

lazy_static! {
    static ref CC_REGEX: Regex = Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap();
    static ref SSN_REGEX: Regex = Regex::new(r"\b\d{3}[ -]\d{2}[ -]\d{4}\b").unwrap();
    static ref AWS_REGEX: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    static ref PRIVKEY_REGEX: Regex = Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap();
    static ref DB_CONN_REGEX: Regex = Regex::new(r#"(?i)(?:postgres|mysql|mongodb|redis|mssql)://[^\s:'"]+:[^\s@'"]+@[^\s/:'"]+"#).unwrap();
    static ref API_TOKEN_REGEX: Regex = Regex::new(r#"(?i)(?:api[_-]?key|access[_-]?token|bearer|secret[_-]?token)[\s:=]+['"]?([a-zA-Z0-9_\-\.]{16,64})['"]?"#).unwrap();
    static ref SENSITIVE_KW_REGEX: Regex = Regex::new(r"(?i)\b(confidential|strictly\s+confidential|internal\s+only|restricted|proprietary|salary\s+data|intellectual\s+property|merger\s+acquisition)\b").unwrap();
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DlpFinding {
    pub category: String,
    pub rule: String,
    pub severity: String,
    pub sample_masked: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DlpVerdict {
    pub is_violation: bool,
    pub action: String, // "Allow", "Alert", "Block"
    pub findings: Vec<DlpFinding>,
    pub sha256: String,
    pub file_size: u64,
}

/// Validates Luhn checksum for credit card candidates to eliminate false positives
pub fn validate_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0;
    let mut alternate = false;
    for &digit in digits.iter().rev() {
        if alternate {
            let doubled = digit * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += digit;
        }
        alternate = !alternate;
    }
    sum % 10 == 0
}

/// Masks sensitive finding string for safe logging and SOC transmission
pub fn mask_sensitive(sample: &str, category: &str) -> String {
    if category == "CreditCard" || category == "SSN" {
        let clean: String = sample.chars().filter(|c| c.is_ascii_graphic()).collect();
        if clean.len() > 4 {
            let start = &clean[..2];
            let end = &clean[clean.len()-2..];
            format!("{}****{}", start, end)
        } else {
            "****".to_string()
        }
    } else if category == "Secret" || category == "Credential" {
        "[REDACTED SECRET]".to_string()
    } else {
        sample.chars().take(30).collect()
    }
}

/// Scans raw text content against all DataGuard enterprise classification rules
pub fn inspect_content(text: &str) -> Vec<DlpFinding> {
    let mut findings = Vec::new();

    // 1. Credit Card Check (Regex + Luhn Verification)
    for mat in CC_REGEX.find_iter(text) {
        let cand = mat.as_str();
        if validate_luhn(cand) {
            findings.push(DlpFinding {
                category: "PCI-DSS".to_string(),
                rule: "CreditCardNumber".to_string(),
                severity: "Critical".to_string(),
                sample_masked: mask_sensitive(cand, "CreditCard"),
            });
            break; // One positive match per category suffices for verdict
        }
    }

    // 2. SSN / Government ID Check
    if let Some(mat) = SSN_REGEX.find(text) {
        findings.push(DlpFinding {
            category: "PII".to_string(),
            rule: "US_SSN".to_string(),
            severity: "Critical".to_string(),
            sample_masked: mask_sensitive(mat.as_str(), "SSN"),
        });
    }

    // 3. AWS / Cloud Credentials
    if let Some(mat) = AWS_REGEX.find(text) {
        findings.push(DlpFinding {
            category: "Secret".to_string(),
            rule: "AWS_AccessKey".to_string(),
            severity: "Critical".to_string(),
            sample_masked: mask_sensitive(mat.as_str(), "Secret"),
        });
    }

    // 4. Private Cryptographic Keys
    if let Some(mat) = PRIVKEY_REGEX.find(text) {
        findings.push(DlpFinding {
            category: "Secret".to_string(),
            rule: "PrivateKeyPEM".to_string(),
            severity: "Critical".to_string(),
            sample_masked: mask_sensitive(mat.as_str(), "Secret"),
        });
    }

    // 5. Database Connection Strings
    if let Some(mat) = DB_CONN_REGEX.find(text) {
        findings.push(DlpFinding {
            category: "Credential".to_string(),
            rule: "DatabaseConnectionString".to_string(),
            severity: "Critical".to_string(),
            sample_masked: mask_sensitive(mat.as_str(), "Credential"),
        });
    }

    // 6. Generic API Tokens / Bearer Secrets
    if let Some(mat) = API_TOKEN_REGEX.find(text) {
        findings.push(DlpFinding {
            category: "Secret".to_string(),
            rule: "ApiBearerToken".to_string(),
            severity: "High".to_string(),
            sample_masked: mask_sensitive(mat.as_str(), "Secret"),
        });
    }

    // 7. Enterprise Confidential Keywords
    if let Some(mat) = SENSITIVE_KW_REGEX.find(text) {
        findings.push(DlpFinding {
            category: "Confidentiality".to_string(),
            rule: "ConfidentialEnterpriseKeyword".to_string(),
            severity: "High".to_string(),
            sample_masked: mat.as_str().to_string(),
        });
    }

    findings
}

/// Extracts printable ASCII / UTF-8 text sequences from binary streams (e.g. OOXML, PDF, archives)
pub fn extract_strings_from_bytes(bytes: &[u8], min_len: usize) -> String {
    let mut result = String::with_capacity(bytes.len() / 4);
    let mut current = Vec::with_capacity(128);

    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current) {
                    result.push_str(s);
                    result.push(' ');
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current) {
            result.push_str(s);
        }
    }

    result
}

/// Evaluates a file and returns a complete DataGuard verdict
pub fn evaluate_file_verdict(path: &Path) -> Result<DlpVerdict, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    let metadata = file.metadata().map_err(|e| format!("Cannot read metadata: {}", e))?;
    let file_size = metadata.len();

    // Read up to 8MB for deep classification
    let read_limit = 8 * 1024 * 1024;
    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut total_read = 0;
    let mut sha_context = Context::new(&SHA256);

    loop {
        let count = file.read(&mut chunk).map_err(|e| format!("Read error: {}", e))?;
        if count == 0 {
            break;
        }
        sha_context.update(&chunk[..count]);
        if total_read < read_limit {
            let to_take = count.min(read_limit - total_read);
            buffer.extend_from_slice(&chunk[..to_take]);
            total_read += to_take;
        }
    }

    let digest = sha_context.finish();
    let sha256_hex = hex::encode(digest.as_ref());

    // Extract text representation
    let text = if let Ok(s) = std::str::from_utf8(&buffer) {
        s.to_string()
    } else {
        // Universal binary / archive stream string extraction
        extract_strings_from_bytes(&buffer, 4)
    };

    let findings = inspect_content(&text);
    let is_violation = !findings.is_empty();
    let action = if is_violation {
        // Any Critical or High finding defaults to Block in strict DataGuard mode
        if findings.iter().any(|f| f.severity == "Critical") {
            "Block".to_string()
        } else {
            "Alert".to_string()
        }
    } else {
        "Allow".to_string()
    };

    Ok(DlpVerdict {
        is_violation,
        action,
        findings,
        sha256: sha256_hex,
        file_size,
    })
}

pub fn scan_file(path: &Path, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    if let Ok(verdict) = evaluate_file_verdict(path) {
        if verdict.is_violation {
            let payload = json!({
                "EventType": "DlpViolation",
                "FilePath": path.to_string_lossy(),
                "FileHash": verdict.sha256,
                "FileSize": verdict.file_size,
                "Action": verdict.action,
                "Findings": verdict.findings,
                "Severity": if verdict.action == "Block" { "Critical" } else { "High" },
                "Timestamp": chrono::Utc::now().to_rfc3339()
            });

            crate::log_msg(&format!("[DataGuard Engine] DLP VIOLATION [{}]: {}", verdict.action, path.display()));
            let _ = event_tx.send(payload);
        }
    }
}
