use serde::{Serialize, Deserialize};
use std::process::Command;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct InstalledSoftware {
    pub name: String,
    pub version: String,
    pub install_date: Option<String>,
}

pub fn get_installed_software() -> String {
    let mut software_list = Vec::new();

    // We use dpkg-query as this agent runs on Linux
    let output = crate::hidden_command!("dpkg-query")
        .arg("-W")
        .arg("-f=${binary:Package} ${Version}\\n")
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let result_str = String::from_utf8_lossy(&output.stdout);
            for line in result_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    software_list.push(InstalledSoftware {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        install_date: None,
                    });
                }
            }
        }
    }

    serde_json::to_string(&software_list).unwrap_or_else(|_| "[]".to_string())
}
