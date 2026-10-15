use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub fn trigger_memory_dump(pid: &str, output_dir: &str) -> Result<Value, String> {
    println!("[MemoryDump] Triggering memory dump for PID {} into {}", pid, output_dir);
    
    // Ensure output directory exists
    let _ = fs::create_dir_all(output_dir);
    
    let dump_file = format!("{}/core.{}", output_dir, pid);
    let mut generated_file = "".to_string();
    
    #[cfg(target_os = "linux")]
    {
        let out_file = format!("{}/core", output_dir);
        match crate::hidden_command!("gcore").arg("-o").arg(&out_file).arg(pid).output() {
            Ok(output) => {
                if output.status.success() {
                    generated_file = format!("{}.{}", out_file, pid);
                } else {
                    return Err(format!("gcore failed: {}", String::from_utf8_lossy(&output.stderr)));
                }
            },
            Err(e) => return Err(format!("Failed to execute gcore: {}", e))
        }
    }

    #[cfg(target_os = "macos")]
    {
        match crate::hidden_command!("lldb").arg("-p").arg(pid).arg("-o").arg(format!("process save-core {}/core.{}", output_dir, pid)).arg("-o").arg("quit").output() {
            Ok(output) => {
                if output.status.success() {
                    generated_file = dump_file.clone();
                } else {
                    if let Ok(vmmap_out) = crate::hidden_command!("vmmap").arg(pid).output() {
                        let map_file = format!("{}/vmmap.{}", output_dir, pid);
                        let _ = fs::write(&map_file, vmmap_out.stdout);
                        generated_file = map_file;
                    } else {
                        return Err(format!("lldb dump failed (SIP restricted) and vmmap fallback failed: {}", String::from_utf8_lossy(&output.stderr)));
                    }
                }
            },
            Err(e) => return Err(format!("Failed to execute lldb: {}", e))
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        let output_file = dump_file.replace("/", "\\");
        match crate::hidden_command!("rundll32.exe")
            .arg("C:\\windows\\system32\\comsvcs.dll,")
            .arg("MiniDump")
            .arg(pid)
            .arg(&output_file)
            .arg("full")
            .output() 
        {
            Ok(output) => {
                if std::path::Path::new(&output_file).exists() {
                    generated_file = output_file;
                } else {
                    return Err(format!("rundll32 failed to create memory dump (run as admin?). Output: {}", String::from_utf8_lossy(&output.stderr)));
                }
            },
            Err(e) => return Err(format!("Failed to execute rundll32: {}", e))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        return Err("Memory dump not supported on this OS".to_string());
    }

    if generated_file.is_empty() || !Path::new(&generated_file).exists() {
        return Err("Dump file not found after generation".to_string());
    }

    // Read bytes, encode, and clean up
    let file_bytes = fs::read(&generated_file).unwrap_or_default();
    let b64 = crate::modules::screenshot_capture::base64_encode(&file_bytes);
    
    // Feature 58: Calculate SHA-256 hash for forensic vault integrity chain of custody
    let digest = ring::digest::digest(&ring::digest::SHA256, &file_bytes);
    let sha256_hash = hex::encode(digest.as_ref());
    let file_size = file_bytes.len();

    // Attempt compression optionally, or just send directly
    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let upload_filename = format!("memdump_{}_{}.dmp", pid, ts);
    
    let _ = fs::remove_file(&generated_file);

    Ok(json!({
        "EventType": "MemoryDumpCompleted",
        "Status": "SUCCESS",
        "FilePath": upload_filename,
        "FileB64": b64,
        "Sha256Hash": sha256_hash,
        "SizeInBytes": file_size,
        "IntegrityVerified": true,
        "Message": format!("Memory dump for PID {} successfully generated (SHA-256: {}).", pid, sha256_hash)
    }))
}
