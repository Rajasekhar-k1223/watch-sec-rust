use std::net::UdpSocket;
use serde::Deserialize;
use reqwest::Client;

#[derive(Deserialize, Debug)]
pub struct IpApiLocation {
    pub query: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
}

pub struct NetworkInfo {
    pub local_ip: String,
    pub public_ip: String,
    pub latitude: f64,
    pub longitude: f64,
    pub country: String,
}

use std::sync::OnceLock;

static CACHED_NETWORK_INFO: OnceLock<NetworkInfo> = OnceLock::new();

pub async fn get_network_info(client: &Client) -> NetworkInfo {
    if let Some(cached) = CACHED_NETWORK_INFO.get() {
        return NetworkInfo {
            local_ip: cached.local_ip.clone(),
            public_ip: cached.public_ip.clone(),
            latitude: cached.latitude,
            longitude: cached.longitude,
            country: cached.country.clone(),
        };
    }

    crate::log_msg("[NetworkInfo] Calling get_local_ip()...");
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    
    let mut public_ip = "".to_string();
    let mut latitude = 0.0;
    let mut longitude = 0.0;
    let mut country = "Unknown".to_string();

    crate::log_msg("[NetworkInfo] Calling ip-api.com...");
    match tokio::time::timeout(std::time::Duration::from_secs(5), client.get("http://ip-api.com/json/").send()).await {
        Ok(Ok(res)) => {
            crate::log_msg("[NetworkInfo] Received response from ip-api.com, reading JSON...");
            if let Ok(data) = res.json::<IpApiLocation>().await {
                public_ip = data.query;
                latitude = data.lat;
                longitude = data.lon;
                country = data.country;
            }
        }
        Ok(Err(e)) => {
            crate::log_msg(&format!("[NetworkInfo] Request to ip-api failed: {}", e));
        }
        Err(_) => {
            crate::log_msg("[NetworkInfo] Request to ip-api timed out (tokio timeout)!");
        }
    }
    crate::log_msg("[NetworkInfo] Returning info...");

    let info = NetworkInfo {
        local_ip,
        public_ip,
        latitude,
        longitude,
        country,
    };
    
    let _ = CACHED_NETWORK_INFO.set(NetworkInfo {
        local_ip: info.local_ip.clone(),
        public_ip: info.public_ip.clone(),
        latitude: info.latitude,
        longitude: info.longitude,
        country: info.country.clone(),
    });
    
    info
}

fn get_local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}
use std::sync::Mutex;
use sysinfo::Networks;
use lazy_static::lazy_static;
use std::time::Instant;

lazy_static! {
    static ref NETWORKS: Mutex<Networks> = Mutex::new(Networks::new_with_refreshed_list());
    static ref LAST_TICK: Mutex<Instant> = Mutex::new(Instant::now());
}

pub fn get_network_bandwidth() -> (f64, f64, f64, f64, String) {
    let mut networks = match NETWORKS.lock() {
        Ok(guard) => guard,
        Err(_) => return (0.0, 0.0, 0.0, 0.0, "Unknown".to_string()),
    };
    
    let mut last_tick = match LAST_TICK.lock() {
        Ok(guard) => guard,
        Err(_) => return (0.0, 0.0, 0.0, 0.0, "Unknown".to_string()),
    };
    
    let now = Instant::now();
    let elapsed = now.duration_since(*last_tick).as_secs_f64();
    if elapsed <= 0.0 {
        return (0.0, 0.0, 0.0, 0.0, "Unknown".to_string());
    }
    *last_tick = now;

    networks.refresh(); // Important in sysinfo v0.30

    let mut tick_rx = 0;
    let mut tick_tx = 0;
    let mut total_rx = 0;
    let mut total_tx = 0;
    
    let mut max_traffic = 0;
    let mut active_nic = "Unknown".to_string();

    for (interface_name, data) in networks.iter() {
        let current_tick_traffic = data.received() + data.transmitted();
        tick_rx += data.received();
        tick_tx += data.transmitted();
        total_rx += data.total_received();
        total_tx += data.total_transmitted();
        
        if current_tick_traffic > max_traffic {
            max_traffic = current_tick_traffic;
            active_nic = interface_name.clone();
        }
    }

    // Convert bytes to megabits per second
    let rx_mbps = (tick_rx as f64 * 8.0) / 1_000_000.0 / elapsed;
    let tx_mbps = (tick_tx as f64 * 8.0) / 1_000_000.0 / elapsed;
    
    // Convert total bytes to gigabytes
    let gb_div = 1024.0 * 1024.0 * 1024.0;
    let rx_gb = total_rx as f64 / gb_div;
    let tx_gb = total_tx as f64 / gb_div;

    (rx_mbps, tx_mbps, rx_gb, tx_gb, active_nic)
}
