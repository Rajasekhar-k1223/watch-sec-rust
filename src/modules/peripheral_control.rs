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
        Ok("Bluetooth blocking via PowerShell not fully implemented".to_string())
    }
}

pub fn block_camera() -> Result<String, String> {
    #[cfg(unix)]
    {
        println!("[Peripheral Control] Blocking Cameras...");
        // Unload common webcam drivers
        let _ = crate::hidden_command!("modprobe").args(&["-r", "uvcvideo"]).output();
        Ok("Cameras blocked by removing uvcvideo module".to_string())
    }
    #[cfg(windows)]
    {
        Ok("Camera blocking via Device Manager not fully implemented".to_string())
    }
}

pub fn block_microphone() -> Result<String, String> {
    #[cfg(unix)]
    {
        println!("[Peripheral Control] Blocking Microphones...");
        // This is a naive approach; a robust solution would use PulseAudio/PipeWire APIs
        let _ = crate::hidden_command!("amixer").args(&["set", "Capture", "nocap"]).output();
        Ok("Microphones muted via ALSA".to_string())
    }
    #[cfg(windows)]
    {
        Ok("Microphone blocking not fully implemented".to_string())
    }
}

pub fn audit_audio_monitoring() -> serde_json::Value {
    let mut is_active = false;
    let mut details = String::new();

    #[cfg(target_os = "linux")]
    {
        // Simple check if any process has opened the PCM capture device
        if let Ok(output) = crate::hidden_command!("fuser")
            .arg("/dev/snd/pcmC0D0c")
            .output()
        {
            if output.status.success() {
                is_active = !output.stdout.is_empty();
                details = "Checked via /dev/snd/pcmC0D0c".to_string();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS uses coreaudiod. A heuristic is checking if it's heavily active, 
        // but robustly, we'd check for active input streams. For now, check processes.
        if let Ok(output) = crate::hidden_command!("pmset")
            .args(&["-g", "powerlog"])
            .output()
        {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if out_str.contains("Microphone") || out_str.contains("Audio Input") {
                is_active = true;
            }
            details = "Checked via pmset log".to_string();
        }
    }

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        is_active = false;
        if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone",
            KEY_READ
        ) {
            for key_name_res in hkcu.enum_keys().map(|x| x.unwrap_or_default()) {
                if key_name_res.is_empty() { continue; }
                if let Ok(app_key) = hkcu.open_subkey_with_flags(&key_name_res, KEY_READ) {
                    if let Ok(stop_time) = app_key.get_value::<u64, _>("LastUsedTimeStop") {
                        if stop_time == 0 {
                            is_active = true;
                            break;
                        }
                    }
                }
            }
        }
        details = "Checked via CapabilityAccessManager registry natively".to_string();
    }

    if details.is_empty() {
        details = "Audio monitoring not supported on this platform".to_string();
    }

    json!({
        "EventType": "AudioAudit",
        "MicrophoneActive": is_active,
        "Details": details
    })
}
