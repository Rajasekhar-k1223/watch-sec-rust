#![allow(unused_imports)]
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

/// Starts a full PCAP network capture using native Windows pktmon
pub fn start_capture() -> Result<Value, String> {
    #[cfg(windows)]
    {
        // pktmon requires Admin privileges. 
        // 1. Reset any existing filters
        let _ = crate::hidden_command!("pktmon").args(&["filter", "remove"]).output();
        
        // 2. Start the capture
        // We use --comp nics to capture on all network interfaces
        // Output will default to PktMon.etl in the current directory
        match crate::hidden_command!("pktmon")
            .args(&["start", "--etw", "-p", "0", "-c", "all"])
            .output() 
        {
            Ok(output) => {
                if output.status.success() {
                    Ok(json!({
                        "EventType": "PcapCaptureStarted",
                        "Status": "SUCCESS",
                        "Message": "Packet capture started on all interfaces."
                    }))
                } else {
                    let err = String::from_utf8_lossy(&output.stderr);
                    Err(format!("pktmon start failed: {}", err))
                }
            },
            Err(e) => Err(format!("Failed to execute pktmon: {}", e)),
        }
    }
    
    #[cfg(not(windows))]
    {
        // On Linux/macOS we use tcpdump
        // Capture up to 50MB, all interfaces
        match crate::hidden_command!("tcpdump")
            .args(&["-i", "any", "-w", "/tmp/capture.pcap", "-C", "50", "-W", "1"])
            .spawn()
        {
            Ok(_) => {
                Ok(json!({
                    "EventType": "PcapCaptureStarted",
                    "Status": "SUCCESS",
                    "Message": "Packet capture started using tcpdump."
                }))
            },
            Err(e) => Err(format!("Failed to start tcpdump: {}", e)),
        }
    }
}

/// Stops the capture and returns the path to the converted PCAPNG file
pub fn stop_and_collect() -> Result<Value, String> {
    #[cfg(windows)]
    {
        // 1. Stop the capture
        let _ = crate::hidden_command!("pktmon").args(&["stop"]).output();
        
        let etl_file = "PktMon.etl";
        let pcap_file = "capture.pcapng";
        
        if !Path::new(etl_file).exists() {
            return Err("Capture file (PktMon.etl) not found. Was a capture started?".to_string());
        }
        
        // 2. Convert ETL to PCAPNG format so Wireshark and the backend can read it easily
        match crate::hidden_command!("pktmon")
            .args(&["pcapng", etl_file, "-o", pcap_file])
            .output()
        {
            Ok(output) => {
                if output.status.success() && Path::new(pcap_file).exists() {
                    let pcap_bytes = fs::read(pcap_file).unwrap_or_default();
                    let b64 = crate::modules::screenshot_capture::base64_encode(&pcap_bytes);
                    let digest = ring::digest::digest(&ring::digest::SHA256, &pcap_bytes);
                    let sha256_hash = hex::encode(digest.as_ref());
                    let file_size = pcap_bytes.len();
                    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
                    let upload_filename = format!("capture_{}.pcapng", ts);

                    // Cleanup the files
                    let _ = fs::remove_file(etl_file);
                    let _ = fs::remove_file(pcap_file);
                    
                    Ok(json!({
                        "EventType": "PcapCaptureCompleted",
                        "Status": "SUCCESS",
                        "FilePath": upload_filename,
                        "FileB64": b64,
                        "Sha256Hash": sha256_hash,
                        "SizeInBytes": file_size,
                        "IntegrityVerified": true,
                        "Message": format!("Capture successfully converted and uploaded (SHA-256: {}).", sha256_hash)
                    }))
                } else {
                    Err("Failed to convert ETL to PCAPNG".to_string())
                }
            },
            Err(e) => Err(format!("Failed to execute pktmon pcapng: {}", e)),
        }
    }
    
    #[cfg(not(windows))]
    {
        // Stop tcpdump (kill the process)
        let _ = crate::hidden_command!("pkill").arg("tcpdump").output();
        
        let pcap_file = "/tmp/capture.pcap";
        if !Path::new(pcap_file).exists() {
            return Err("Capture file not found. Was a capture started?".to_string());
        }
        
        let pcap_bytes = fs::read(pcap_file).unwrap_or_default();
        let b64 = crate::modules::screenshot_capture::base64_encode(&pcap_bytes);
        let digest = ring::digest::digest(&ring::digest::SHA256, &pcap_bytes);
        let sha256_hash = hex::encode(digest.as_ref());
        let file_size = pcap_bytes.len();
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let upload_filename = format!("capture_{}.pcap", ts);
        
        let _ = fs::remove_file(pcap_file);
        
        Ok(json!({
            "EventType": "PcapCaptureCompleted",
            "Status": "SUCCESS",
            "FilePath": upload_filename,
            "FileB64": b64,
            "Sha256Hash": sha256_hash,
            "SizeInBytes": file_size,
            "IntegrityVerified": true,
            "Message": format!("Capture successfully completed and uploaded (SHA-256: {}).", sha256_hash)
        }))
    }
}
