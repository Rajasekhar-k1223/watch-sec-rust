
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
        let _ = crate::hidden_command!("powershell")
            .args(["-Command", "New-NetFirewallRule -DisplayName 'Monitorix Lockdown Block All Outbound' -Direction Outbound -Action Block -Profile Any"])
            .output();
        let _ = crate::hidden_command!("powershell")
            .args(["-Command", "New-NetFirewallRule -DisplayName 'Monitorix Lockdown Block All Inbound' -Direction Inbound -Action Block -Profile Any"])
            .output();
        let _ = crate::hidden_command!("powershell")
            .args(["-Command", &format!("New-NetFirewallRule -DisplayName 'Monitorix Allow C2' -Direction Outbound -RemoteAddress '{}' -Action Allow", backend_ip)])
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
        let _ = crate::hidden_command!("powershell")
            .args(["-Command", "Remove-NetFirewallRule -DisplayName 'Monitorix Lockdown Block All Outbound' -ErrorAction SilentlyContinue"])
            .output();
        let _ = crate::hidden_command!("powershell")
            .args(["-Command", "Remove-NetFirewallRule -DisplayName 'Monitorix Lockdown Block All Inbound' -ErrorAction SilentlyContinue"])
            .output();
        let _ = crate::hidden_command!("powershell")
            .args(["-Command", "Remove-NetFirewallRule -DisplayName 'Monitorix Allow C2' -ErrorAction SilentlyContinue"])
            .output();
            
        Ok("Windows Network Unisolated. Removed isolation rules.".to_string())
    }
}
