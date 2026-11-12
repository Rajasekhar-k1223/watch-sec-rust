use serde_json::json;
#[cfg(unix)]
use std::fs;

/// Scan running processes for suspicious memory segments (like anonymous rwx)
pub fn scan_memory() -> serde_json::Value {
    #[allow(unused_mut)]
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
                                let cmdline_path = format!("/proc/{}/cmdline", pid_str);
                                let cmdline = fs::read_to_string(&cmdline_path).unwrap_or_default();

                                // Real dynamic check on anonymous RWX segment memory
                                if let Some(addr_range) = line.split_whitespace().next() {
                                    if let Some(start_str) = addr_range.split('-').next() {
                                        if let Ok(start_addr) = u64::from_str_radix(start_str, 16) {
                                            let mem_path = format!("/proc/{}/mem", pid_str);
                                            use std::os::unix::fs::FileExt;
                                            if let Ok(mem_file) = fs::File::open(&mem_path) {
                                                let mut buf = [0u8; 1024];
                                                if mem_file.read_at(&mut buf, start_addr).is_ok() {
                                                    let s = String::from_utf8_lossy(&buf);
                                                    if s.contains("CobaltStrike") || s.contains("Mimikatz") || s.contains("eval(base64") || s.contains("/bin/sh") {
                                                        found_malware_sig = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
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
    #[allow(unused_mut)]
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
