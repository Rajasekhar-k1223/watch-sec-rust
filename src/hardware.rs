use serde::{Serialize, Deserialize};
use sysinfo::{System, Disks};
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref GLOBAL_SYS: Mutex<System> = Mutex::new(System::new_all());
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BiosInfo {
    pub vendor: String,
    pub version: String,
    pub secure_boot: String,
    pub release_date: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct HardwareInfo {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub ram_total_g_b: f64,
    pub ram_used_g_b: f64,
    pub ram_available_g_b: f64,
    pub ram_percent: f64,
    pub disk_total_g_b: f64,
    pub disk_free_g_b: f64,
    pub bios: BiosInfo,
}

pub struct HardwareStats {
    pub hw_info: HardwareInfo,
    pub cpu_usage: f64,
    pub mem_usage: f64,
    pub disk_usage: f64,
}

pub fn get_hardware_stats() -> HardwareStats {
    let mut sys = GLOBAL_SYS.lock().unwrap();
    // First refresh to initialize CPU counters
    sys.refresh_cpu_usage();
    // sysinfo requires a short sleep between samples to compute an accurate CPU delta.
    // Without this, consecutive calls return 0% or stale values.
    drop(sys); // Release lock during sleep so other threads can run
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut sys = GLOBAL_SYS.lock().unwrap();
    // Second refresh — now CPU % is accurate
    sys.refresh_all();

    // CPU Stats
    let cpus = sys.cpus();
    let mut cpu_model = "Unknown".to_string();
    let mut cpu_cores = 0;
    if !cpus.is_empty() {
        cpu_model = cpus[0].brand().to_string();
        cpu_cores = sys.physical_core_count().unwrap_or(cpus.len());
    }
    let cpu_threads = cpus.len();
    let cpu_usage = sys.global_cpu_info().cpu_usage() as f64;


    // Memory Stats
    let total_mem = sys.total_memory() as f64;
    let used_mem = sys.used_memory() as f64;
    let available_mem = sys.available_memory() as f64;
    
    let gb_div = 1024.0 * 1024.0 * 1024.0;
    
    let mem_usage_percent = if total_mem > 0.0 {
        (used_mem / total_mem) * 100.0
    } else {
        0.0
    };

    // Disk Stats
    let mut disk_total = 0.0;
    let mut disk_free = 0.0;
    let mut disk_usage_percent = 0.0;

    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        disk_total += disk.total_space() as f64;
        disk_free += disk.available_space() as f64;
        if disk_usage_percent == 0.0 && disk.total_space() > 0 {
            disk_usage_percent = ((disk.total_space() - disk.available_space()) as f64 / disk.total_space() as f64) * 100.0;
        }
    }

    let hw_info = HardwareInfo {
        cpu_model,
        cpu_cores,
        cpu_threads,
        ram_total_g_b: total_mem / gb_div,
        ram_used_g_b: used_mem / gb_div,
        ram_available_g_b: available_mem / gb_div,
        ram_percent: mem_usage_percent,
        disk_total_g_b: disk_total / gb_div,
        disk_free_g_b: disk_free / gb_div,
        bios: BiosInfo {
            vendor: "Monitorix Bios".to_string(),
            version: "v1".to_string(),
            secure_boot: "Unknown".to_string(),
            release_date: "Unknown".to_string(),
        },
    };

    HardwareStats {
        hw_info,
        cpu_usage,
        mem_usage: mem_usage_percent,
        disk_usage: disk_usage_percent,
    }
}
/// Lightweight stats: only refreshes CPU + memory. Safe to call every 5 seconds.
/// Does NOT refresh disk, processes, or network — those are expensive.
pub struct QuickStats {
    pub cpu_usage: f64,
    pub mem_usage: f64,
}

pub fn get_quick_stats() -> QuickStats {
    let mut sys = GLOBAL_SYS.lock().unwrap();
    // Cheap double-sample for accurate CPU delta
    sys.refresh_cpu_usage();
    drop(sys);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut sys = GLOBAL_SYS.lock().unwrap();
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let cpu_usage = sys.global_cpu_info().cpu_usage() as f64;
    let total_mem = sys.total_memory() as f64;
    let used_mem = sys.used_memory() as f64;
    let mem_usage = if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 };

    QuickStats {
        cpu_usage: (cpu_usage * 10.0).round() / 10.0,
        mem_usage: (mem_usage * 10.0).round() / 10.0,
    }
}
