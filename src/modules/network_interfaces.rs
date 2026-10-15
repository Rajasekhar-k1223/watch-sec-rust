use serde_json::json;
use std::fs;

pub fn audit_interfaces() -> serde_json::Value {
    let mut interfaces = Vec::new();
    
    #[cfg(unix)]
    {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    let mac_path = format!("/sys/class/net/{}/address", name);
                    let operstate_path = format!("/sys/class/net/{}/operstate", name);
                    
                    let mac = fs::read_to_string(&mac_path).unwrap_or_else(|_| "UNKNOWN".to_string()).trim().to_string();
                    let operstate = fs::read_to_string(&operstate_path).unwrap_or_else(|_| "UNKNOWN".to_string()).trim().to_string();
                    
                    interfaces.push(json!({
                        "Interface": name,
                        "MAC": mac,
                        "Status": operstate,
                    }));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use wmi::{COMLibrary, WMIConnection};
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct Win32NetworkAdapterConfiguration {
            pub description: Option<String>,
            pub mac_address: Option<String>,
            pub ip_address: Option<Vec<String>>,
        }

        let mut wmi_success = false;

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con) {
                if let Ok(results) = wmi_con.raw_query::<Win32NetworkAdapterConfiguration>("SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True") {
                    for adapter in results {
                        interfaces.push(json!({
                            "Interface": adapter.description.unwrap_or_default(),
                            "MAC": adapter.mac_address.unwrap_or_else(|| "UNKNOWN".to_string()),
                            "Status": "UP",
                            "IPAddresses": adapter.ip_address.unwrap_or_default(),
                        }));
                    }
                    wmi_success = true;
                }
            }
        }

        if !wmi_success {
            let networks = sysinfo::Networks::new_with_refreshed_list();
            for (interface_name, data) in &networks {
                let mac_str = data.mac_address().to_string();
                    
                interfaces.push(json!({
                    "Interface": interface_name,
                    "MAC": mac_str,
                    "Status": "UP",
                    "IPAddresses": Vec::<String>::new(),
                }));
            }
        }
    }

    json!({
        "EventType": "NetworkInterfaceAudit",
        "InterfaceCount": interfaces.len(),
        "Interfaces": interfaces
    })
}
