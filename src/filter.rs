//! IP and port filtering.

use crate::packet::Packet;
use std::net::IpAddr;

/// Packet filter based on IP addresses and ports.
#[derive(Debug, Default)]
pub struct Filter {
    /// IP whitelist — if non-empty, only packets matching at least one IP pass.
    ip_list: Vec<IpAddr>,
    /// Port whitelist — if non-empty, only packets matching at least one port pass.
    port_list: Vec<u16>,
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an IP to the filter whitelist.
    pub fn add_ip(&mut self, ip: IpAddr) {
        self.ip_list.push(ip);
    }

    /// Add a port to the filter whitelist.
    pub fn add_port(&mut self, port: u16) {
        self.port_list.push(port);
    }

    /// Returns true if the filter is inactive (no filters set).
    pub fn is_empty(&self) -> bool {
        self.ip_list.is_empty() && self.port_list.is_empty()
    }

    /// Check whether a packet passes the filter.
    /// IP and port filters are AND-combined: both must match if both are set.
    pub fn matches(&self, packet: &Packet) -> bool {
        let ip_ok = self.ip_list.is_empty()
            || packet.five_tuple.is_some_and(|ft| {
                self.ip_list.iter().any(|ip| *ip == ft.src_ip || *ip == ft.dst_ip)
            });

        let port_ok = self.port_list.is_empty()
            || packet.five_tuple.is_some_and(|ft| {
                self.port_list
                    .iter()
                    .any(|p| *p == ft.src_port || *p == ft.dst_port)
            });

        ip_ok && port_ok
    }
}
