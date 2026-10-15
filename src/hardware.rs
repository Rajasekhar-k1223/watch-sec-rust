use serde::{Serialize, Deserialize};
use sysinfo::{System, Disks};
use lazy_static::lazy_static;
use std::sync::{Mutex, Arc, RwLock};
use std::time::Duration;

// ── Single persistent sysinfo instance ───────────────────────────────────────
lazy_static! {
    static ref GLOBAL_SYS: Mutex<System> = Mutex::new(System::new_all());
}

// ── Cached CPU/Memory snapshot updated by the background sampler ─────────────
// All heartbeat and telemetry callers just read this — zero CPU cost per call.
#[derive(Clone)]
pub struct CachedStats {
    pub cpu_usage: f64,
    pub mem_usage: f64,
}

lazy_static! {
    static ref STATS_CACHE: Arc<RwLock<CachedStats>> = Arc::new(RwLock::new(CachedStats {
        cpu_usage: 0.0,
        mem_usage: 0.0,
    }));
}

/// Start the background CPU/memory sampler. Call once at agent startup.
/// Samples every 3 seconds in a dedicated thread — keeps STATS_CACHE fresh.
/// This is the ONLY place that calls refresh_cpu_usage() so there is no
/// contention or duplicate sampling causing CPU spikes.
pub fn start_background_sampler() {
    let cache = Arc::clone(&*STATS_CACHE);
    
    // Initialise memory immediately so the very first heartbeat isn't 0%
    {
        let mut sys = GLOBAL_SYS.lock().unwrap();
        sys.refresh_memory();
        let total = sys.total_memory() as f64;
        let used = sys.used_memory() as f64;
        if let Ok(mut c) = STATS_CACHE.write() {
            c.mem_usage = if total > 0.0 { ((used / total) * 1000.0).round() / 10.0 } else { 0.0 };
        }
    }

    std::thread::spawn(move || {
        loop {
            // First sample — initialise CPU counters
            {
                let mut sys = GLOBAL_SYS.lock().unwrap();
                sys.refresh_cpu_usage();
            }
            // Wait 500ms for accurate delta (sysinfo requirement)
            std::thread::sleep(Duration::from_millis(500));
            // Second sample — now CPU% is accurate
            {
                let mut sys = GLOBAL_SYS.lock().unwrap();
                sys.refresh_cpu_usage();
                sys.refresh_memory();

                let cpu = sys.global_cpu_info().cpu_usage() as f64;
                let total = sys.total_memory() as f64;
                let used = sys.used_memory() as f64;
                let mem = if total > 0.0 { (used / total) * 100.0 } else { 0.0 };

                if let Ok(mut c) = cache.write() {
                    c.cpu_usage = (cpu * 10.0).round() / 10.0;
                    c.mem_usage = (mem * 10.0).round() / 10.0;
                }
            }
            // Sleep before next sample cycle — 3 second cadence
            std::thread::sleep(Duration::from_secs(3));
        }
    });
}

// ── Public structs ───────────────────────────────────────────────────────────

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
    /// Operating system identifier — used by the backend for correct update URL generation.
    /// Values: "linux", "windows", "darwin"
    pub os_system: String,
    /// CPU architecture — used by the backend for arm64 vs x64 detection.
    pub arch: String,
}

pub struct HardwareStats {
    pub hw_info: HardwareInfo,
    pub cpu_usage: f64,
    pub mem_usage: f64,
    pub disk_usage: f64,
}

/// Full hardware stats — reads CPU/memory from the cache (zero extra cost),
/// but still queries disk info (cheap, no kernel sampling needed).
pub fn get_hardware_stats() -> HardwareStats {
    // Read cached CPU + memory — never blocks or samples
    let (cpu_usage, mem_usage_percent) = {
        let c = STATS_CACHE.read().unwrap();
        (c.cpu_usage, c.mem_usage)
    };

    // Read memory details from sysinfo (no refresh needed — sampler keeps it fresh)
    let (cpu_model, cpu_cores, cpu_threads, total_mem, used_mem, available_mem) = {
        let sys = GLOBAL_SYS.lock().unwrap();
        let cpus = sys.cpus();
        let model = if !cpus.is_empty() { cpus[0].brand().to_string() } else { "Unknown".to_string() };
        let cores = sys.physical_core_count().unwrap_or(cpus.len());
        let threads = cpus.len();
        let total = sys.total_memory() as f64;
        let used = sys.used_memory() as f64;
        let avail = sys.available_memory() as f64;
        (model, cores, threads, total, used, avail)
    };

    let gb_div = 1024.0 * 1024.0 * 1024.0;

    // Disk Stats — cheap (no kernel sampling)
    let mut disk_total = 0.0;
    let mut disk_free = 0.0;
    let mut disk_usage_percent = 0.0;
    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        disk_total += disk.total_space() as f64;
        disk_free += disk.available_space() as f64;
        if disk_usage_percent == 0.0 && disk.total_space() > 0 {
            disk_usage_percent = ((disk.total_space() - disk.available_space()) as f64
                / disk.total_space() as f64) * 100.0;
        }
    }

    // Detect OS and architecture at compile time
    #[cfg(target_os = "linux")]
    let os_system = "linux".to_string();
    #[cfg(target_os = "windows")]
    let os_system = "windows".to_string();
    #[cfg(target_os = "macos")]
    let os_system = "darwin".to_string();
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    let os_system = std::env::consts::OS.to_string();

    #[cfg(target_arch = "x86_64")]
    let arch = "x64".to_string();
    #[cfg(target_arch = "aarch64")]
    let arch = "arm64".to_string();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = std::env::consts::ARCH.to_string();

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
        os_system,
        arch,
    };

    HardwareStats {
        hw_info,
        cpu_usage,
        mem_usage: mem_usage_percent,
        disk_usage: disk_usage_percent,
    }
}

/// Lightweight stats — reads directly from the background sampler cache.
/// Zero CPU overhead. Safe to call every second.
pub struct QuickStats {
    pub cpu_usage: f64,
    pub mem_usage: f64,
}

pub fn get_quick_stats() -> QuickStats {
    let c = STATS_CACHE.read().unwrap();
    QuickStats {
        cpu_usage: c.cpu_usage,
        mem_usage: c.mem_usage,
    }
}
