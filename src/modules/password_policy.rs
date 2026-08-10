use serde_json::json;
use std::fs;

pub fn audit_password_policy() -> serde_json::Value {
    let mut pass_max_days = "UNKNOWN".to_string();
    let mut pass_min_days = "UNKNOWN".to_string();
    let mut pass_warn_age = "UNKNOWN".to_string();

    if let Ok(content) = fs::read_to_string("/etc/login.defs") {
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with('#') && !line.is_empty() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if parts[0] == "PASS_MAX_DAYS" {
                        pass_max_days = parts[1].to_string();
                    } else if parts[0] == "PASS_MIN_DAYS" {
                        pass_min_days = parts[1].to_string();
                    } else if parts[0] == "PASS_WARN_AGE" {
                        pass_warn_age = parts[1].to_string();
                    }
                }
            }
        }
    }

    json!({
        "EventType": "PasswordPolicyReport",
        "PassMaxDays": pass_max_days,
        "PassMinDays": pass_min_days,
        "PassWarnAge": pass_warn_age
    })
}
