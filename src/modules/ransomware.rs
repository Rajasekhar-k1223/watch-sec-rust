use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::json;

pub struct RansomwareShield {
    pub pid_buckets: HashMap<u32, PidBucket>,
}

pub struct PidBucket {
    pub score: u32,
    pub last_updated: u64,
}

impl RansomwareShield {
    pub fn new() -> Self {
        RansomwareShield {
            pid_buckets: HashMap::new(),
        }
    }

    pub fn evaluate_file_action(&mut self, pid: u32, action_type: &str, entropy: f64) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let bucket = self.pid_buckets.entry(pid).or_insert(PidBucket {
            score: 0,
            last_updated: now,
        });

        // Decay score by 1 point per second
        let time_diff = now.saturating_sub(bucket.last_updated);
        if time_diff > 0 {
            bucket.score = bucket.score.saturating_sub(time_diff as u32);
        }
        bucket.last_updated = now;

        // Apply heuristics
        if action_type == "HighEntropyWrite" && entropy > 7.5 {
            bucket.score += 10;
        } else if action_type == "MassRename" {
            bucket.score += 15;
        } else if action_type == "DeleteShadows" {
            bucket.score += 1000; // Instant trigger
        }

        println!("[RANSOMWARE_SHIELD] PID {} Threat Score: {}", pid, bucket.score);

        if bucket.score >= 100 {
            println!("[RANSOMWARE_SHIELD] THRESHOLD BREACHED FOR PID {}! Triggering Quarantine.", pid);
            self.trigger_response(pid);
            return true;
        }

        false
    }

    fn trigger_response(&self, pid: u32) {
        println!("[RESPONSE] Autonomous action: Terminating Malicious PID {}", pid);
        
        // 1. Terminate the process
        let mut system = sysinfo::System::new_all();
        system.refresh_all();
        
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            process.kill();
            println!("[RESPONSE] Successfully terminated PID {}", pid);
        } else {
            println!("[RESPONSE] PID {} already dead.", pid);
        }

        // 2. Isolate Network
        println!("[RESPONSE] Triggering Network Isolation...");
        let _ = super::isolation::isolate_network("agent-api.monitorix.co.in");
        println!("[RESPONSE] Network Isolation complete. Endpoint is now quarantined.");
    }
}
