use serde_json::json;

pub fn get_local_users() -> serde_json::Value {
    let mut users = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/passwd") {
            for line in contents.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let username = parts[0];
                    let uid = parts[2];
                    let description = parts[4];
                    let shell = parts[6];

                    // Heuristic: skip common system users to reduce noise, unless they have a real shell
                    if uid.parse::<u32>().unwrap_or(1000) >= 1000 || uid == "0" || !shell.contains("nologin") && !shell.contains("false") {
                        users.push(json!({
                            "username": username,
                            "uid": uid,
                            "description": description,
                            "is_admin": uid == "0",
                            "shell": shell,
                        }));
                    }
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
        struct Win32UserAccount {
            pub name: String,
            pub description: Option<String>,
            pub disabled: Option<bool>,
        }

        let mut wmi_success = false;

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con) {
                if let Ok(results) = wmi_con.raw_query::<Win32UserAccount>("SELECT Name, Description, Disabled FROM Win32_UserAccount WHERE LocalAccount=True") {
                    for user in results {
                        users.push(json!({
                            "Name": user.name,
                            "Enabled": !user.disabled.unwrap_or(false),
                            "Description": user.description.unwrap_or_default(),
                        }));
                    }
                    wmi_success = true;
                }
            }
        }

        if !wmi_success {
            let sys_users = sysinfo::Users::new_with_refreshed_list();
            for user in sys_users.list() {
                users.push(json!({
                    "Name": user.name(),
                    "Enabled": true, // sysinfo doesn't easily expose disabled state
                    "Description": "Local user (fallback enumeration)",
                }));
            }
        }
    }

    json!({
        "type": "LocalUsersAudit",
        "users": users,
    })
}
