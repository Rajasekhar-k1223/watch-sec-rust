use std::sync::Mutex;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref PLUGINS: Mutex<HashMap<String, libloading::Library>> = Mutex::new(HashMap::new());
}

pub fn load_plugin(path: &str) -> Result<String, String> {
    unsafe {
        match libloading::Library::new(path) {
            Ok(lib) => {
                // Try to find a standard entry point, e.g., `plugin_init`
                // This expects the plugin to expose `extern "C" fn plugin_init() -> bool`
                let init_func: Result<libloading::Symbol<unsafe extern "C" fn() -> bool>, _> = lib.get(b"plugin_init");
                
                match init_func {
                    Ok(func) => {
                        let success = func();
                        if success {
                            PLUGINS.lock().unwrap().insert(path.to_string(), lib);
                            Ok(format!("Successfully loaded and initialized plugin: {}", path))
                        } else {
                            Err(format!("Plugin {} initialized but returned failure.", path))
                        }
                    }
                    Err(_) => {
                        // Keep the lib loaded even if no init func exists
                        PLUGINS.lock().unwrap().insert(path.to_string(), lib);
                        Ok(format!("Successfully loaded plugin (no init function): {}", path))
                    }
                }
            }
            Err(e) => Err(format!("Failed to load plugin {}: {}", path, e))
        }
    }
}

pub fn unload_plugin(path: &str) -> Result<String, String> {
    let mut plugins = PLUGINS.lock().unwrap();
    if plugins.remove(path).is_some() {
        Ok(format!("Successfully unloaded plugin: {}", path))
    } else {
        Err(format!("Plugin not found: {}", path))
    }
}
