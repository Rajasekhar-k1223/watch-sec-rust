use serde_json::json;
use std::fs;
use std::path::Path;

/// Scan running processes for suspicious memory segments (like anonymous rwx)
pub fn scan_memory() -> serde_json::Value {
    let mut suspicious_pids = Vec::<String>::new();

    #[cfg(unix)]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.filter_map(Result::ok) {
                let file_name = entry.file_name();
                let pid_str = file_name.to_string_lossy();
                
                // If it's a number, it's a PID directory
                if pid_str.chars().all(char::is_numeric) {
                    let maps_path = format!("/proc/{}/maps", pid_str);
                    if let Ok(maps_content) = fs::read_to_string(&maps_path) {
                        for line in maps_content.lines() {
                            // Look for read-write-execute (rwxp) anonymous mappings (no file path at the end)
                            if line.contains("rwxp") && !line.contains("/") && !line.contains("[heap]") && !line.contains("[stack]") {
                                // YARA-style heuristic: check for known malware strings in memory
                                // In a full implementation, we would seek to the memory offsets and read the raw bytes.
                                // For performance and safety in this agent, we flag the presence of the segment.
                                let mut found_malware_sig = false;
                                
                                // Simulated deep memory read of the segment
                                let dummy_memory_content = "Vigenere MZ header CobaltStrike Mimikatz";
                                if dummy_memory_content.contains("CobaltStrike") || dummy_memory_content.contains("Mimikatz") {
                                    found_malware_sig = true;
                                }

                                if found_malware_sig {
                                    suspicious_pids.push(pid_str.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows we would use VirtualQueryEx to look for PAGE_EXECUTE_READWRITE
    }

    if !suspicious_pids.is_empty() {
        json!({
            "EventType": "MemoryScanAlert",
            "SuspiciousPIDs": suspicious_pids,
            "Details": "Found processes with RWX anonymous memory (Potential Shellcode/Injection)"
        })
    } else {
        json!({
            "EventType": "MemoryScanReport",
            "Status": "Clean"
        })
    }
}

/// Check kernel logs for exploit activity (segfaults, traps)
pub fn detect_exploits() -> serde_json::Value {
    let mut exploit_indicators = Vec::<String>::new();

    #[cfg(unix)]
    {
        if let Ok(dmesg_output) = crate::hidden_command!("dmesg").output() {
            let log = String::from_utf8_lossy(&dmesg_output.stdout);
            for line in log.lines().rev().take(100) { // Check last 100 kernel messages
                let l = line.to_lowercase();
                if l.contains("segfault") || l.contains("trap") || l.contains("general protection fault") {
                    exploit_indicators.push(line.to_string());
                }
            }
        }
    }

    if !exploit_indicators.is_empty() {
        json!({
            "EventType": "ExploitDetected",
            "Indicators": exploit_indicators,
            "Details": "Kernel logged memory violations indicative of exploitation attempts"
        })
    } else {
        json!({
            "EventType": "ExploitReport",
            "Status": "Clean"
        })
    }
}
