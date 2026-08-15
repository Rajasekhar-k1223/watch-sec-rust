use serde_json::json;

pub fn audit_firewall() -> serde_json::Value {
    let mut input_policy = "UNKNOWN".to_string();
    let mut forward_policy = "UNKNOWN".to_string();
    let mut output_policy = "UNKNOWN".to_string();

    // Check iptables default policies
    if let Ok(output) = crate::hidden_command!("iptables").arg("-L").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("Chain INPUT") {
                if let Some(policy) = line.split("policy ").nth(1) {
                    input_policy = policy.split(')').next().unwrap_or("UNKNOWN").to_string();
                }
            } else if line.starts_with("Chain FORWARD") {
                if let Some(policy) = line.split("policy ").nth(1) {
                    forward_policy = policy.split(')').next().unwrap_or("UNKNOWN").to_string();
                }
            } else if line.starts_with("Chain OUTPUT") {
                if let Some(policy) = line.split("policy ").nth(1) {
                    output_policy = policy.split(')').next().unwrap_or("UNKNOWN").to_string();
                }
            }
        }
    }

    json!({
        "EventType": "FirewallComplianceReport",
        "InputPolicy": input_policy,
        "ForwardPolicy": forward_policy,
        "OutputPolicy": output_policy
    })
}
