use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader};

pub fn audit_scheduled_tasks() -> serde_json::Value {
    let mut tasks = Vec::new();

    // 1. Parse /etc/crontab
    if let Ok(file) = fs::File::open("/etc/crontab") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if !l.starts_with('#') && !l.trim().is_empty() {
                    tasks.push(l.trim().to_string());
                }
            }
        }
    }

    println!("[CronAudit] Found {} scheduled tasks", tasks.len());

    json!({
        "EventType": "ScheduledTasksInventory",
        "Tasks": tasks,
        "TaskCount": tasks.len()
    })
}
