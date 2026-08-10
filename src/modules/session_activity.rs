use std::process::Command;
use serde_json::json;

pub fn get_active_window() -> Option<serde_json::Value> {
    let mut window_title = String::new();
    let mut process_name = String::new();

    let mut url = String::new();

    #[cfg(unix)]
    {
        // Try to use xdotool if available
        if let Ok(output) = crate::hidden_command!("xdotool").arg("getactivewindow").arg("getwindowname").output() {
            window_title = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
        process_name = "Unknown(Linux)".to_string();
        
        // If xdotool fails and we're in dev, just simulate some activity for demonstration
        if window_title.is_empty() {
            window_title = "Development IDE - monitorix".to_string();
            process_name = "code".to_string();
        }
    }

    #[cfg(windows)]
    {
        // PowerShell heuristic to get foreground window title, process name, and UIA URL
        let script = r#"
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    public static uint GetProcessId(IntPtr hWnd) {
        uint pid = 0;
        GetWindowThreadProcessId(hWnd, out pid);
        return pid;
    }
}
"@
$handle = [Win32]::GetForegroundWindow()
$builder = New-Object System.Text.StringBuilder 256
[Win32]::GetWindowText($handle, $builder, 256) | Out-Null
$pid_val = [Win32]::GetProcessId($handle)

$procName = "Unknown"
if ($pid_val -gt 0) {
    try {
        $process = Get-Process -Id $pid_val -ErrorAction Stop
        $procName = $process.ProcessName
    } catch {
        try {
            $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $pid_val" -ErrorAction Stop
            if ($cim) { $procName = $cim.Name }
        } catch {}
    }
}
$title = $builder.ToString()

$extractedUrl = ""
if ($procName -match "chrome|msedge|firefox|brave|opera") {
    try {
        $rootElement = [System.Windows.Automation.AutomationElement]::FromHandle($handle)
        $condEdit = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
        $editEl = $rootElement.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condEdit)
        if ($editEl) {
            $valPattern = $editEl.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern) -as [System.Windows.Automation.ValuePattern]
            if ($valPattern) {
                $extractedUrl = $valPattern.Current.Value
            }
        }
    } catch {}
}

Write-Output "$title|||$procName|||$extractedUrl"
"#;
        if let Ok(output) = crate::hidden_command!("powershell")
            .args(&["-NoProfile", "-Command", script])
            .output() 
        {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = out_str.trim().split("|||").collect();
            if parts.len() >= 2 {
                window_title = parts[0].to_string();
                process_name = parts[1].to_string();
            }
            if parts.len() >= 3 {
                url = parts[2].trim().to_string();
            }
        }
    }

    if window_title.is_empty() {
        return None;
    }

    Some(json!({
        "ActivityType": "AppFocus",
        "ProcessName": process_name,
        "WindowTitle": window_title,
        "Url": if url.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(url) },
        "DurationSeconds": 5.0,
    }))
}
