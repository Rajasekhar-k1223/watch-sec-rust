use serde_json::json;
use std::fs;

pub fn get_certificates() -> serde_json::Value {
    let mut certs = Vec::new();
    let cert_dir = "/etc/ssl/certs";

    if let Ok(entries) = fs::read_dir(cert_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() || file_type.is_symlink() {
                    if let Ok(name) = entry.file_name().into_string() {
                        if name.ends_with(".pem") || name.ends_with(".crt") {
                            certs.push(name);
                            if certs.len() >= 100 { // Limit payload to avoid massive websockets
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    json!({
        "EventType": "CertificateInventory",
        "CertificateCount": certs.len(),
        "Certificates": certs
    })
}
