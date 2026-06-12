//! Unified packet representation and FiveTuple types.

use bytes::Bytes;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Five-tuple identifier for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub protocol: u8, // 6=TCP, 17=UDP, 1=ICMP
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    /// Return the session key (sorted src/dst so bidirectional traffic maps to same key).
    pub fn session_key(&self) -> Self {
        if self.src_ip < self.dst_ip
            || (self.src_ip == self.dst_ip && self.src_port < self.dst_port)
        {
            *self
        } else {
            Self {
                protocol: self.protocol,
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
            }
        }
    }
}

/// Result of parsing an IP packet for L4 info.
struct IpInfo {
    five_tuple: FiveTuple,
    l7_offset: Option<usize>, // offset within the IP datagram
}

/// A normalized packet representation, independent of capture file format.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Capture timestamp
    pub ts: SystemTime,
    /// Timestamp as (seconds, microseconds) for PCAP frame output
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// Original (wire) length
    pub orig_len: u32,
    /// Captured (snapshot) length
    pub cap_len: u32,
    /// Raw frame data (starts at link layer)
    pub data: Bytes,
    /// Byte offset where L7 payload starts within `data`, if applicable
    pub l7_offset: Option<usize>,
    /// Source MAC address
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC address
    pub dst_mac: Option<[u8; 6]>,
    /// WiFi BSSID
    pub bssid: Option<[u8; 6]>,
    /// L3/L4 five-tuple, if the packet carries IP
    pub five_tuple: Option<FiveTuple>,
}

impl Packet {
    /// Construct a packet from raw PCAP record fields.
    pub fn from_pcap_record(
        ts_sec: u32,
        ts_usec: u32,
        orig_len: u32,
        data: Bytes,
        link_type: u32,
    ) -> Self {
        let cap_len = data.len() as u32;
        let ts = UNIX_EPOCH + std::time::Duration::new(ts_sec as u64, ts_usec * 1000);

        let (src_mac, dst_mac, bssid, five_tuple, l7_offset) = if link_type == 1 {
            // LINKTYPE_ETHERNET
            parse_ethernet(&data)
        } else {
            // Raw IP (no link layer)
            let info = parse_ip_packet(&data);
            (
                None,
                None,
                None,
                info.as_ref().map(|i| i.five_tuple),
                info.and_then(|i| i.l7_offset),
            )
        };

        Self {
            ts,
            ts_sec,
            ts_usec,
            orig_len,
            cap_len,
            data,
            l7_offset,
            src_mac,
            dst_mac,
            bssid,
            five_tuple,
        }
    }

    /// Return the L7 payload slice, if available.
    pub fn l7_data(&self) -> Option<&[u8]> {
        self.l7_offset.map(|off| &self.data[off..])
    }
}

/// Parse Ethernet frame: extract MACs, optional IP info.
fn parse_ethernet(
    data: &[u8],
) -> (
    Option<[u8; 6]>,
    Option<[u8; 6]>,
    Option<[u8; 6]>,
    Option<FiveTuple>,
    Option<usize>,
) {
    if data.len() < 14 {
        return (None, None, None, None, None);
    }
    let dst_mac: [u8; 6] = data[0..6].try_into().unwrap();
    let src_mac: [u8; 6] = data[6..12].try_into().unwrap();
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    let (ip_payload, link_offset) = match ethertype {
        0x0800 | 0x86DD => (&data[14..], 14),
        0x8100 if data.len() >= 18 => {
            // VLAN tagged
            let inner = u16::from_be_bytes([data[16], data[17]]);
            match inner {
                0x0800 | 0x86DD => (&data[18..], 18),
                _ => return (Some(src_mac), Some(dst_mac), None, None, None),
            }
        }
        _ => return (Some(src_mac), Some(dst_mac), None, None, None),
    };

    let info = parse_ip_packet(ip_payload);
    let five_tuple = info.as_ref().map(|i| i.five_tuple);
    let l7_offset = info.and_then(|i| i.l7_offset.map(|o| link_offset + o));

    (Some(src_mac), Some(dst_mac), None, five_tuple, l7_offset)
}

/// Parse an IP packet (starts at IP header). Returns L4 info.
fn parse_ip_packet(data: &[u8]) -> Option<IpInfo> {
    if data.is_empty() {
        return None;
    }
    match data[0] >> 4 {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<IpInfo> {
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let protocol = data[9];
    let src_ip = IpAddr::from([data[12], data[13], data[14], data[15]]);
    let dst_ip = IpAddr::from([data[16], data[17], data[18], data[19]]);

    let mut l7_offset = None;
    let (src_port, dst_port) = match protocol {
        6 | 17 if data.len() >= ihl + 4 => {
            // TCP or UDP
            let sp = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
            let dp = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

            // Compute L7 offset: IP header + TCP/UDP header
            l7_offset = match protocol {
                6 if data.len() >= ihl + 20 => {
                    let doff = ((data[ihl + 12] >> 4) & 0x0F) as usize * 4;
                    Some((ihl + doff).min(data.len()))
                }
                17 => Some((ihl + 8).min(data.len())),
                _ => None,
            };

            (sp, dp)
        }
        1 => (0, 0), // ICMP — no ports
        _ => {
            l7_offset = Some(ihl);
            (0, 0)
        }
    };

    Some(IpInfo {
        five_tuple: FiveTuple {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
        l7_offset,
    })
}

fn parse_ipv6(data: &[u8]) -> Option<IpInfo> {
    if data.len() < 40 {
        return None;
    }
    let protocol = data[6]; // Next Header
    let src_ip = IpAddr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst_ip = IpAddr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    let mut l7_offset = None;
    let (src_port, dst_port) = match protocol {
        6 | 17 if data.len() >= 44 => {
            let sp = u16::from_be_bytes([data[40], data[41]]);
            let dp = u16::from_be_bytes([data[42], data[43]]);

            l7_offset = match protocol {
                6 if data.len() >= 60 => {
                    let doff = ((data[52] >> 4) & 0x0F) as usize * 4;
                    Some((40 + doff).min(data.len()))
                }
                17 => Some(48), // UDP: 40 + 8
                _ => None,
            };

            (sp, dp)
        }
        58 => (0, 0), // ICMPv6
        _ => {
            l7_offset = Some(40);
            (0, 0)
        }
    };

    Some(IpInfo {
        five_tuple: FiveTuple {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
        l7_offset,
    })
}

/// Get TCP/UDP payload offset within an IP packet (for external use).
pub fn payload_offset(data: &[u8]) -> Option<usize> {
    parse_ip_packet(data).and_then(|info| info.l7_offset)
}
