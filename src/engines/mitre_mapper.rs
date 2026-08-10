use serde_json::Value;

pub fn enrich_event(mut event: Value) -> Value {
    if let Some(event_type) = event.get("EventType").and_then(|v| v.as_str()) {
        let t_code = match event_type {
            "ScheduledTasksInventory" => "T1053", // Scheduled Task/Job
            "DeceptionTriggered" => "T1040",      // Network Sniffing / Credential Access (Honeypot)
            "AppControlViolation" => "T1562.001", // Impair Defenses: Disable or Modify Tools
            "ProcessSnapshot" => "T1057",         // Process Discovery
            "FileIntegrityAlert" => "T1070.004",  // File Deletion / Modification
            "RansomwareAlert" => "T1486",         // Data Encrypted for Impact
            _ => ""
        };

        if !t_code.is_empty() {
            if let Some(obj) = event.as_object_mut() {
                obj.insert("MitreTCode".to_string(), Value::String(t_code.to_string()));
            }
        }
    }
    event
}
