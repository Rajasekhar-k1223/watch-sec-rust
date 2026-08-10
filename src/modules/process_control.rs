use sysinfo::{Pid, System};
use std::str::FromStr;

pub fn kill_process(pid_str: &str) -> Result<String, String> {
    let pid_u32 = u32::from_str(pid_str).map_err(|_| "Invalid PID format".to_string())?;
    
    // In sysinfo 0.30, Pid is a struct wrapping the actual pid type
    let pid = Pid::from_u32(pid_u32);
    
    let mut sys = System::new();
    sys.refresh_processes();
    
    if let Some(process) = sys.process(pid) {
        if process.kill() {
            Ok(format!("Successfully killed process {}", pid_str))
        } else {
            Err(format!("Failed to kill process {}", pid_str))
        }
    } else {
        Err(format!("Process {} not found", pid_str))
    }
}
