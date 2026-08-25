use enigo::{Enigo, MouseControllable, KeyboardControllable, MouseButton, Key};
use std::process::Command;
use serde_json::Value;

pub fn simulate_input(data: &Value) {
    let mut enigo = Enigo::new();
    let cmd_type = data.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match cmd_type {
        "mousemove" => {
            if let (Some(x), Some(y)) = (data.get("x").and_then(|v| v.as_f64()), data.get("y").and_then(|v| v.as_f64())) {
                enigo.mouse_move_to(x as i32, y as i32);
            }
        }
        "click" => {
            if let (Some(x), Some(y)) = (data.get("x").and_then(|v| v.as_f64()), data.get("y").and_then(|v| v.as_f64())) {
                enigo.mouse_move_to(x as i32, y as i32);
            }
            let btn_str = data.get("button").and_then(|v| v.as_str()).unwrap_or("left");
            let btn = match btn_str {
                "right" => MouseButton::Right,
                "middle" => MouseButton::Middle,
                _ => MouseButton::Left,
            };
            enigo.mouse_click(btn);
        }
        "keypress" => {
            if let Some(key_name) = data.get("key").and_then(|v| v.as_str()) {
                match key_name.to_lowercase().as_str() {
                    "enter" => enigo.key_click(Key::Return),
                    "space" => enigo.key_click(Key::Space),
                    "backspace" => enigo.key_click(Key::Backspace),
                    "esc" | "escape" => enigo.key_click(Key::Escape),
                    "tab" => enigo.key_click(Key::Tab),
                    _ => {
                        enigo.key_sequence(key_name);
                    }
                }
            }
        }
        "lock" => lock_workstation(),
        "curtain" => {
            let enabled = data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            toggle_curtain_mode(enabled);
        }
        _ => {}
    }
}

pub fn lock_workstation() {
    #[cfg(target_os = "windows")]
    let _ = crate::hidden_command!("rundll32.exe").arg("user32.dll,LockWorkStation").spawn();

    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-screensaver").arg("lock").spawn();

    #[cfg(target_os = "macos")]
    let _ = Command::new("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession").arg("-suspend").spawn();
}

pub fn toggle_curtain_mode(enable: bool) {
    #[cfg(target_os = "windows")]
    {
        if enable {
            let script = r#"
            $HWND_BROADCAST = [IntPtr]0xFFFF
            $WM_SYSCOMMAND = 0x0112
            $SC_MONITORPOWER = 0xF170
            $POWER_OFF = 2
            Add-Type -TypeDefinition '
            using System;
            using System.Runtime.InteropServices;
            public class Win32 {
                [DllImport("user32.dll")]
                public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
                [DllImport("user32.dll")]
                public static extern bool BlockInput(bool fBlockIt);
            }
            '
            [Win32]::BlockInput($true)
            [Win32]::SendMessage($HWND_BROADCAST, $WM_SYSCOMMAND, [IntPtr]$SC_MONITORPOWER, [IntPtr]$POWER_OFF)
            "#;
            let _ = crate::hidden_command!("powershell").args(&["-Command", script]).spawn();
        } else {
            let script = r#"
            Add-Type -TypeDefinition '
            using System;
            using System.Runtime.InteropServices;
            public class Win32 {
                [DllImport("user32.dll")]
                public static extern bool BlockInput(bool fBlockIt);
            }
            '
            [Win32]::BlockInput($false)
            "#;
            let _ = crate::hidden_command!("powershell").args(&["-Command", script]).spawn();
        }
    }

    #[cfg(target_os = "linux")]
    {
        if enable {
            let _ = Command::new("xset").args(&["dpms", "force", "off"]).spawn();
        } else {
            let _ = Command::new("xset").args(&["dpms", "force", "on"]).spawn();
            let _ = Command::new("xset").args(&["s", "reset"]).spawn();
        }
    }

    #[cfg(target_os = "macos")]
    {
        if enable {
            let _ = Command::new("pmset").arg("displaysleepnow").spawn();
        } else {
            let _ = Command::new("caffeinate").args(&["-u", "-t", "1"]).spawn();
        }
    }
}
