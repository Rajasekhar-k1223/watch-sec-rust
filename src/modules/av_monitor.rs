use sysinfo::System;
use serde_json::json;

pub fn check_av_status() -> serde_json::Value {
    let mut av_found = false;
    let mut details = String::from("Unknown");

    #[cfg(unix)]
    {
        let mut sys = System::new();
        sys.refresh_processes();
        let av_processes = ["clamd", "falcon-sensor", "trapsd", "bdss", "sophos"]; 
        
        for process in sys.processes().values() {
            let name = process.name().to_string().to_lowercase();
            for av in av_processes.iter() {
                if name.contains(av) {
                    av_found = true;
                    details = format!("Found AV Process: {}", name);
                    break;
                }
            }
            if av_found { break; }
        }
        
        if !av_found {
            details = "No known AV process found".to_string();
        }
    }

    #[cfg(windows)]
    {
        use wmi::{COMLibrary, WMIConnection};
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct AntivirusProduct {
            pub display_name: String,
        }

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::with_namespace_path("ROOT\\SecurityCenter2", com_con.into()) {
                if let Ok(results) = wmi_con.raw_query::<AntivirusProduct>("SELECT * FROM AntivirusProduct") {
                    if let Some(av) = results.into_iter().next() {
                        av_found = true;
                        details = format!("Found AV: {}", av.display_name);
                    } else {
                        details = "No AV registered in SecurityCenter2".to_string();
                    }
                } else {
                    details = "Failed to query SecurityCenter2 WMI".to_string();
                }
            }
        }
    }

    json!({
        "type": "AntivirusStatus",
        "enabled": av_found,
        "details": details,
    })
}
