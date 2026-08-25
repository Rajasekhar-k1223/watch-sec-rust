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

    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    
    let mut public_ip = "".to_string();
    let mut latitude = 0.0;
    let mut longitude = 0.0;
    let mut country = "Unknown".to_string();

    if let Ok(res) = client.get("http://ip-api.com/json/").send().await {
        if let Ok(data) = res.json::<IpApiLocation>().await {
            public_ip = data.query;
            latitude = data.lat;
            longitude = data.lon;
            country = data.country;
        }
    }

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

pub fn get_network_bandwidth() -> (f64, f64) {
    let mut networks = match NETWORKS.lock() {
        Ok(guard) => guard,
        Err(_) => return (0.0, 0.0),
    };
    
    let mut last_tick = match LAST_TICK.lock() {
        Ok(guard) => guard,
        Err(_) => return (0.0, 0.0),
    };
    
    let now = Instant::now();
    let elapsed = now.duration_since(*last_tick).as_secs_f64();
    if elapsed <= 0.0 {
        return (0.0, 0.0);
    }
    *last_tick = now;

    networks.refresh(); // Important in sysinfo v0.30

    let mut total_rx = 0;
    let mut total_tx = 0;

    for (_interface_name, data) in networks.iter() {
        total_rx += data.received();
        total_tx += data.transmitted();
    }

    // Convert bytes to megabits per second
    let rx_mbps = (total_rx as f64 * 8.0) / 1_000_000.0 / elapsed;
    let tx_mbps = (total_tx as f64 * 8.0) / 1_000_000.0 / elapsed;

    (rx_mbps, tx_mbps)
}
