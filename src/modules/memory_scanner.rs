#![allow(unused_imports)]
use serde_json::{json, Value};
use sysinfo::System;

#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
#[cfg(windows)]
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(windows)]
use std::ffi::c_void;

/// Known byte signatures for fileless malware in memory
#[cfg(any(windows, target_os = "linux"))]
struct YARASignature {
    name: &'static str,
    pattern: &'static [u8],
}

#[cfg(any(windows, target_os = "linux"))]
const SIGNATURES: &[YARASignature] = &[
    YARASignature {
        name: "CobaltStrike_Beacon_Header",
        pattern: b"\\xFC\\x48\\x83\\xE4\\xF0\\xE8\\xC0\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xD2\\x65\\x48\\x8B\\x52\\x60",
    },
    YARASignature {
        name: "Meterpreter_Reverse_TCP",
        pattern: b"\\xFC\\x48\\x81\\xE4\\xF0\\xFF\\xFF\\xFF\\x48\\x31\\xD2\\x48\\x31\\xF6\\x48\\x31\\xFF\\x48\\x31\\xC0\\x4D\\x31\\xC0\\x4D\\x31\\xC9\\x4D\\x31\\xD2\\x4D\\x31\\xDB\\x4D\\x31\\xE4\\x4D\\x31\\xED\\x4D\\x31\\xF6\\x4D\\x31\\xFF\\x41\\x50\\x41\\x51\\x41\\x52\\x41\\x53\\x41\\x54\\x41\\x55\\x41\\x56\\x41\\x57\\x50\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x48\\x83\\xEC\\x28",
    },
    YARASignature {
        name: "Mimikatz_LogonPasswords",
        pattern: b"sekurlsa::logonpasswords",
    }
];

pub fn scan_memory() -> Vec<Value> {
    #[allow(unused_mut)]
    let mut alerts = Vec::new();

    #[cfg(windows)]
    {
        let mut sys = System::new_all();
        sys.refresh_processes();

        for (pid, process) in sys.processes() {
            let process_id = pid.as_u32();
            
            // Try to open the process for reading memory
            unsafe {
                let handle = match OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, process_id) {
                    Ok(h) => h,
                    Err(_) => continue, // Cannot access this process (likely System/Admin restricted)
                };

                let mut address = 0 as *mut c_void;
                let mut mem_info = MEMORY_BASIC_INFORMATION::default();

                // Walk the process memory regions
                while VirtualQueryEx(
                    handle,
                    Some(address),
                    &mut mem_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) != 0
                {
                    // Only scan executable memory that is committed (where fileless malware lives)
                    if mem_info.State == MEM_COMMIT && 
                      (mem_info.Protect == PAGE_EXECUTE_READWRITE || mem_info.Protect == PAGE_EXECUTE_READ) {
                        
                        // Limit size to prevent massive allocations, max 10MB chunk
                        let chunk_size = std::cmp::min(mem_info.RegionSize, 10 * 1024 * 1024);
                        let mut buffer = vec![0u8; chunk_size];
                        let mut bytes_read = 0;

                        if ReadProcessMemory(
                            handle,
                            mem_info.BaseAddress,
                            buffer.as_mut_ptr() as *mut c_void,
                            chunk_size,
                            Some(&mut bytes_read),
                        ).is_ok() && bytes_read > 0 {
                            
                            // Naive pattern matching (Boyer-Moore would be faster for production)
                            for sig in SIGNATURES {
                                if find_subsequence(&buffer[..bytes_read], sig.pattern).is_some() {
                                    alerts.push(json!({
                                        "EventType": "MemoryMalwareDetected",
                                        "PID": process_id,
                                        "ProcessName": process.name(),
                                        "Signature": sig.name,
                                        "MemoryAddress": format!("0x{:X}", address as usize),
                                        "Severity": "CRITICAL"
                                    }));
                                    
                                    // Optional: Instantly kill the process
                                    crate::log_msg(&format!("[MemoryScanner] Malicious signature {} found in PID {}", sig.name, process_id));
                                }
                            }
                        }
                    }
                    
                    // Move to the next memory region
                    address = (address as usize + mem_info.RegionSize) as *mut c_void;
                }
                
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::{Read, BufRead, BufReader, Seek, SeekFrom};
        
        let mut sys = System::new_all();
        sys.refresh_processes();

        for (pid, process) in sys.processes() {
            let process_id = pid.as_u32();
            
            // Open /proc/PID/maps
            let maps_path = format!("/proc/{}/maps", process_id);
            let mem_path = format!("/proc/{}/mem", process_id);
            
            if let (Ok(maps_file), Ok(mut mem_file)) = (File::open(&maps_path), File::open(&mem_path)) {
                let reader = BufReader::new(maps_file);
                for line in reader.lines().flatten() {
                    // Example line: 7f7e9a9b0000-7f7e9a9b2000 r-xp 00000000 08:01 123456 /usr/bin/foo
                    if line.contains("r-xp") || line.contains("rwxp") || line.contains("r-wp") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(range) = parts.first() {
                            let addrs: Vec<&str> = range.split('-').collect();
                            if addrs.len() == 2 {
                                if let (Ok(start), Ok(end)) = (
                                    usize::from_str_radix(addrs[0], 16),
                                    usize::from_str_radix(addrs[1], 16)
                                ) {
                                    let size = end.saturating_sub(start);
                                    // Limit chunk size to 10MB
                                    let chunk_size = std::cmp::min(size, 10 * 1024 * 1024);
                                    if chunk_size > 0 {
                                        if mem_file.seek(SeekFrom::Start(start as u64)).is_ok() {
                                            let mut buffer = vec![0u8; chunk_size];
                                            if let Ok(bytes_read) = mem_file.read(&mut buffer) {
                                                if bytes_read > 0 {
                                                    for sig in SIGNATURES {
                                                        if find_subsequence(&buffer[..bytes_read], sig.pattern).is_some() {
                                                            alerts.push(json!({
                                                                "EventType": "MemoryMalwareDetected",
                                                                "PID": process_id,
                                                                "ProcessName": process.name(),
                                                                "Signature": sig.name,
                                                                "MemoryAddress": format!("0x{:X}", start),
                                                                "Severity": "CRITICAL"
                                                            }));
                                                            crate::log_msg(&format!("[MemoryScanner] Malicious signature {} found in PID {}", sig.name, process_id));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        // On macOS, reading memory requires the task_for_pid entitlement or root + csrutil.
        // For parity, we would call `vmmap` and parse its regions, then use mach_vm_read.
    }

    alerts
}

/// Simple substring search for byte slices
#[cfg(any(windows, target_os = "linux"))]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
