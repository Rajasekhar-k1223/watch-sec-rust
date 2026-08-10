use serde_json::json;
use std::fs;

pub fn audit_peripherals() -> serde_json::Value {
    let mut cameras = Vec::new();
    let mut bluetooth_active = false;

    // Check for cameras /dev/video*
    if let Ok(entries) = fs::read_dir("/dev") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.starts_with("video") {
                    cameras.push(name);
                }
            }
        }
    }

    // Check bluetooth interface (if dir exists and is not empty)
    if let Ok(entries) = fs::read_dir("/sys/class/bluetooth") {
        if entries.count() > 0 {
            bluetooth_active = true;
        }
    }

    json!({
        "EventType": "PeripheralStatusReport",
        "CamerasFound": cameras.len(),
        "CameraDevices": cameras,
        "BluetoothActive": bluetooth_active
    })
}
