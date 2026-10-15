
pub fn isolate_network(backend_ip: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        // Zero-Trust Microsegmentation: Drop everything except C2 traffic
        println!("[Lockdown] Enforcing iptables microsegmentation drop rules...");
        let _ = crate::hidden_command!("iptables").args(["-I", "INPUT", "-j", "DROP"]).output();
        let _ = crate::hidden_command!("iptables").args(["-I", "OUTPUT", "-j", "DROP"]).output();
        // Allow Loopback
        let _ = crate::hidden_command!("iptables").args(["-I", "INPUT", "-i", "lo", "-j", "ACCEPT"]).output();
        let _ = crate::hidden_command!("iptables").args(["-I", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]).output();
        // Allow strictly out to C2
        let _ = crate::hidden_command!("iptables").args(["-I", "OUTPUT", "-p", "tcp", "--dport", "443", "-d", backend_ip, "-j", "ACCEPT"]).output();
        // Allow strictly in from C2
        let _ = crate::hidden_command!("iptables").args(["-I", "INPUT", "-p", "tcp", "--sport", "443", "-s", backend_ip, "-j", "ACCEPT"]).output();
        
        Ok(format!("Network Isolated. Allowed only outbound to {}", backend_ip))
    }

    #[cfg(windows)]
    {
        println!("[Lockdown] Enforcing Windows Firewall microsegmentation drop rules...");
        let _ = crate::hidden_command!("netsh")
            .args(["advfirewall", "firewall", "add", "rule", "name=Monitorix Lockdown Block All Outbound", "dir=out", "action=block", "profile=any"])
            .output();
        let _ = crate::hidden_command!("netsh")
            .args(["advfirewall", "firewall", "add", "rule", "name=Monitorix Lockdown Block All Inbound", "dir=in", "action=block", "profile=any"])
            .output();
        let _ = crate::hidden_command!("netsh")
            .args(["advfirewall", "firewall", "add", "rule", "name=Monitorix Allow C2", "dir=out", &format!("remoteip={}", backend_ip), "action=allow"])
            .output();
            
        Ok(format!("Windows Network Isolated. Allowed only outbound to {}", backend_ip))
    }
}

pub fn unisolate_network() -> Result<String, String> {
    #[cfg(unix)]
    {
        println!("[Lockdown] Lifting iptables microsegmentation drop rules...");
        let _ = crate::hidden_command!("iptables").args(["-F"]).output(); // Flush rules
        Ok("Network Unisolated. Restored outbound traffic.".to_string())
    }

    #[cfg(windows)]
    {
        let _ = crate::hidden_command!("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=Monitorix Lockdown Block All Outbound"])
            .output();
        let _ = crate::hidden_command!("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=Monitorix Lockdown Block All Inbound"])
            .output();
        let _ = crate::hidden_command!("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=Monitorix Allow C2"])
            .output();
            
        Ok("Windows Network Unisolated. Removed isolation rules.".to_string())
    }
}

pub fn isolate_host() -> Result<String, String> {
    crate::log_msg("[Lockdown] Instant host isolation triggered by canary tamper guard!");
    isolate_network("127.0.0.1")
}

