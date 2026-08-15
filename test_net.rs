use sysinfo::Networks;
use std::time::Duration;
use std::thread::sleep;
fn main() {
    let mut networks = Networks::new_with_refreshed_list();
    sleep(Duration::from_secs(1));
    networks.refresh();
    for (name, data) in networks.iter() {
        println!("{}: rx={}", name, data.received());
        println!("{}: total_rx={}", name, data.total_received());
    }
}
