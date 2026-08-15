use sysinfo::Networks;
use std::time::Duration;
use std::thread::sleep;

fn main() {
    let mut networks = Networks::new_with_refreshed_list();
    sleep(Duration::from_secs(1));
    networks.refresh();
    for (name, data) in networks.iter() {
        println!("{}: rx={} tx={}", name, data.received(), data.transmitted());
        println!("{}: total_rx={} total_tx={}", name, data.total_received(), data.total_transmitted());
    }
}
