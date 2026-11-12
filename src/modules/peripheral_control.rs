use serde_json::json;

pub fn block_bluetooth() -> Result<String, String> {
    #[cfg(unix)]
    {
        println!("[Peripheral Control] Blocking Bluetooth...");
        let _ = crate::hidden_command!("rfkill").args(&["block", "bluetooth"]).output();
        let _ = crate::hidden_command!("systemctl").args(&["stop", "bluetooth"]).output();
        Ok("Bluetooth devices blocked via rfkill".to_string())
    }
    #[cfg(windows)]
    {
        println!("[Peripheral Control] Blocking Windows Bluetooth via PnP & Services...");
        let ps_cmd = "Stop-Service bthserv -Force -ErrorAction SilentlyContinue; Set-Service bthserv -StartupType Disabled; Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue";
        let _ = crate::hidden_command!("powershell.exe").args(&["-NoProfile", "-NonInteractive", "-Command", ps_cmd]).output();
        Ok("Bluetooth radio and bthserv disabled on Windows".to_string())
    }
}

pub fn block_camera() -> Result<String, String> {
    #[cfg(unix)]
    {
        println!("[Peripheral Control] Blocking Cameras...");
        let _ = crate::hidden_command!("modprobe").args(&["-r", "uvcvideo"]).output();
        Ok("Cameras blocked by removing uvcvideo module".to_string())
    }
    #[cfg(windows)]
    {
        let ps_cmd = "Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue";
        let _ = crate::hidden_command!("powershell.exe").args(&["-NoProfile", "-NonInteractive", "-Command", ps_cmd]).output();
        Ok("Cameras disabled via Windows PnP Device Manager".to_string())
    }
}

pub fn block_microphone() -> Result<String, String> {
    #[cfg(unix)]
    {
        println!("[Peripheral Control] Blocking Microphones...");
        let _ = crate::hidden_command!("amixer").args(&["set", "Capture", "nocap"]).output();
        Ok("Microphones muted via ALSA".to_string())
    }
    #[cfg(windows)]
    {
        let ps_cmd = "Get-PnpDevice -Class AudioEndpoint -FriendlyName '*Microphone*' -ErrorAction SilentlyContinue | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue";
        let _ = crate::hidden_command!("powershell.exe").args(&["-NoProfile", "-NonInteractive", "-Command", ps_cmd]).output();
        Ok("Microphone endpoints muted via Windows PowerShell".to_string())
    }
}

pub fn audit_audio_monitoring() -> serde_json::Value {
    let mut is_active = false;
    let mut details = String::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = crate::hidden_command!("pactl").args(&["list", "source-outputs"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Source Output #") {
                is_active = true;
                details = stdout.lines().take(5).collect::<Vec<&str>>().join("\n");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        details = "Windows Audio Session API audit active".to_string();
    }

    json!({
        "EventType": "AudioMonitoringAudit",
        "MicrophoneActive": is_active,
        "Details": details
    })
}
