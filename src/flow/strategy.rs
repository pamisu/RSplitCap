//! Grouping strategy implementations.

use crate::cli::GroupArg;
use crate::packet::Packet;

/// Enum over all supported grouping strategies.
pub enum GroupStrategyEnum {
    Session,
    Flow,
    Host,
    Hostpair,
    Mac,
    Bssid,
    Nosplit,
    Seconds(u32),
    Packets(u32),
}

impl GroupStrategyEnum {
    pub fn from_group_arg(arg: &GroupArg) -> Self {
        match arg {
            GroupArg::Session => Self::Session,
            GroupArg::Flow => Self::Flow,
            GroupArg::Host => Self::Host,
            GroupArg::Hostpair => Self::Hostpair,
            GroupArg::Mac => Self::Mac,
            GroupArg::Bssid => Self::Bssid,
            GroupArg::Nosplit => Self::Nosplit,
            GroupArg::Seconds(n) => Self::Seconds(*n),
            GroupArg::Packets(n) => Self::Packets(*n),
        }
    }

    /// Compute the group key(s) for a packet. A packet can belong to multiple groups
    /// (e.g., Host strategy assigns to both src and dst IP groups).
    /// `global_pkt_idx` is used by the Packets strategy for bucketing.
    pub fn group_keys(&self, packet: &Packet, global_pkt_idx: u64) -> Vec<String> {
        match self {
            Self::Session => {
                if let Some(ft) = packet.five_tuple {
                    let sk = ft.session_key();
                    vec![format!(
                        "{}_{}_{}_{}_{}",
                        sk.protocol, sk.src_ip, sk.dst_ip, sk.src_port, sk.dst_port
                    )]
                } else {
                    vec!["no_session".into()]
                }
            }
            Self::Flow => {
                if let Some(ft) = packet.five_tuple {
                    vec![format!(
                        "{}_{}_{}_{}_{}",
                        ft.protocol, ft.src_ip, ft.dst_ip, ft.src_port, ft.dst_port
                    )]
                } else {
                    vec!["no_flow".into()]
                }
            }
            Self::Host => {
                if let Some(ft) = packet.five_tuple {
                    vec![ft.src_ip.to_string(), ft.dst_ip.to_string()]
                } else {
                    vec!["no_host".into()]
                }
            }
            Self::Hostpair => {
                if let Some(ft) = packet.five_tuple {
                    let (a, b) = if ft.src_ip < ft.dst_ip {
                        (ft.src_ip, ft.dst_ip)
                    } else {
                        (ft.dst_ip, ft.src_ip)
                    };
                    vec![format!("{}_{}", a, b)]
                } else {
                    vec!["no_hostpair".into()]
                }
            }
            Self::Mac => {
                let mut keys = Vec::new();
                if let Some(mac) = packet.src_mac {
                    keys.push(format!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    ));
                }
                if let Some(mac) = packet.dst_mac {
                    let s = format!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    );
                    if keys.first() != Some(&s) {
                        keys.push(s);
                    }
                }
                if keys.is_empty() {
                    keys.push("no_mac".into());
                }
                keys
            }
            Self::Bssid => {
                if let Some(bssid) = packet.bssid {
                    vec![format!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
                    )]
                } else {
                    vec!["no_bssid".into()]
                }
            }
            Self::Nosplit => {
                vec!["all".into()]
            }
            Self::Seconds(interval) => {
                let bucket = packet.ts_sec / *interval;
                vec![format!("ts_{}", bucket)]
            }
            Self::Packets(count) => {
                let bucket = global_pkt_idx / *count as u64;
                vec![format!("pkt_{}", bucket)]
            }
        }
    }
}
