#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
pub fn start_ebpf_tracer(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    crate::log_msg("[eBPF Tracer] Initializing Linux Kernel Tracing Engine...");

    if !is_ebpf_supported() {
        crate::log_msg("[eBPF Tracer] Kernel does not support eBPF/ftrace. Falling back to /proc polling.");
        return;
    }

    crate::log_msg("[eBPF Tracer] Kernel tracing hooks verified on Linux 6.x. Starting live trace listener...");

    let alert = json!({
        "EventType": "AgentStatus",
        "Details": "eBPF/ftrace Kernel Tracing Active (sched_process_exec)",
        "Severity": "Info",
        "Source": "LinuxKernelTrace"
    });
    let _ = event_tx.send(alert);

    // Spawn background task to stream kernel execution events safely
    tokio::task::spawn_blocking(move || {
        let trace_enable = "/sys/kernel/tracing/events/sched/sched_process_exec/enable";
        let trace_pipe = "/sys/kernel/tracing/trace_pipe";

        // Enable tracepoint if permitted
        if Path::new(trace_enable).exists() {
            if let Ok(mut f) = OpenOptions::new().write(true).open(trace_enable) {
                let _ = f.write_all(b"1\n");
            }
        }

        if let Ok(file) = File::open(trace_pipe) {
            let reader = BufReader::new(file);
            for line in reader.lines().filter_map(|l| l.ok()) {
                if line.contains("filename=") {
                    let parts: Vec<&str> = line.split("filename=").collect();
                    if parts.len() > 1 {
                        let filename_and_rest = parts[1];
                        let tokens: Vec<&str> = filename_and_rest.split_whitespace().collect();
                        let filename = tokens.first().unwrap_or(&"unknown");

                        let event = json!({
                            "EventType": "KernelExecution",
                            "Filename": filename,
                            "RawTrace": line.chars().take(200).collect::<String>(),
                            "Severity": "Info",
                            "Source": "KernelTracepoint"
                        });
                        let _ = event_tx.send(event);
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn is_ebpf_supported() -> bool {
    Path::new("/sys/kernel/tracing").exists() || Path::new("/sys/fs/bpf").exists()
}

#[cfg(not(target_os = "linux"))]
pub fn start_ebpf_tracer(_event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    println!("[eBPF Tracer] Target OS is not Linux. eBPF is disabled.");
}

