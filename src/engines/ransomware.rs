use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;

#[derive(Debug)]
struct ProcessBucket {
    score: u32,
    last_updated: u64,
}

lazy_static! {
    static ref BUCKETS: Arc<Mutex<HashMap<u32, ProcessBucket>>> = Arc::new(Mutex::new(HashMap::new()));
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn evaluate_file_action(pid: u32, action_type: &str, entropy: f64) -> bool {
    let now = current_timestamp();
    let mut trigger_quarantine = false;
    #[allow(unused_assignments)]
    let mut current_score = 0;

    {
        let mut buckets = BUCKETS.lock().unwrap();
        let bucket = buckets.entry(pid).or_insert(ProcessBucket {
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

        current_score = bucket.score;
        
        if bucket.score >= 100 {
            trigger_quarantine = true;
            // Reset score to prevent spamming
            bucket.score = 0; 
        }
    }

    if current_score > 0 {
        println!("[RansomwareShield] PID {} Threat Score: {}", pid, current_score);
    }

    if trigger_quarantine {
        println!("[RansomwareShield] CRITICAL: THRESHOLD BREACHED FOR PID {}! Triggering Autonomous Response.", pid);
        trigger_response(pid);
        return true;
    }

    false
}

fn trigger_response(pid: u32) {
    println!("[RESPONSE] Autonomous action triggered for PID {}", pid);
    
    // Check Policy before killing
    if !crate::modules::policy::is_action_allowed("response", "process_kill_permission") {
        println!("[POLICY] Process kill denied by current policy. Agent is in Audit Mode.");
        return;
    }

    // 1. Kill the offending process
    let pid_str = pid.to_string();
    if let Err(e) = crate::modules::process_control::kill_process(&pid_str) {
        eprintln!("[RESPONSE] Failed to kill PID {}: {}", pid, e);
    } else {
        println!("[RESPONSE] Successfully terminated PID {}", pid);
    }

    // 2. Optional: Isolate the network
    // if let Err(e) = crate::modules::isolation::isolate_network("127.0.0.1") {
    //     eprintln!("[RESPONSE] Failed to isolate network: {}", e);
    // }
}
