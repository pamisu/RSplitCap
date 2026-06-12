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

        let (src_mac, dst_mac, bssid, five_tuple, l7_offset) = match link_type {
            1 => {
                // LINKTYPE_ETHERNET
                parse_ethernet(&data)
            }
            105 => {
                // LINKTYPE_IEEE802_11 — raw 802.11 frames
                parse_wifi_raw(&data)
            }
            127 => {
                // LINKTYPE_IEEE802_11_RADIOTAP — radiotap + 802.11
                parse_wifi_radiotap(&data)
            }
            _ => {
                // Raw IP (no link layer) or unsupported link type
                let info = parse_ip_packet(&data);
                (
                    None,
                    None,
                    None,
                    info.as_ref().map(|i| i.five_tuple),
                    info.and_then(|i| i.l7_offset),
                )
            }
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

/// Result of parsing a link-layer frame: (src_mac, dst_mac, bssid, five_tuple, l7_offset).
type ParsedFrame = (
    Option<[u8; 6]>,
    Option<[u8; 6]>,
    Option<[u8; 6]>,
    Option<FiveTuple>,
    Option<usize>,
);

/// Parse Ethernet frame: extract MACs, optional IP info.
fn parse_ethernet(data: &[u8]) -> ParsedFrame {
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

/// Parse a raw 802.11 frame (LINKTYPE_IEEE802_11 = 105).
/// Extracts MAC addresses, BSSID, and attempts IP parsing over LLC/SNAP.
fn parse_wifi_raw(data: &[u8]) -> ParsedFrame {
    parse_80211_frame(data, 0)
}

/// Parse a Radiotap + 802.11 frame (LINKTYPE_IEEE802_11_RADIOTAP = 127).
fn parse_wifi_radiotap(data: &[u8]) -> ParsedFrame {
    if data.len() < 4 {
        return (None, None, None, None, None);
    }
    // Radiotap header: version (1B), pad (1B), length (2B LE)
    let version = data[0];
    if version != 0 {
        return (None, None, None, None, None);
    }
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if radiotap_len < 4 || radiotap_len > data.len() {
        return (None, None, None, None, None);
    }
    parse_80211_frame(data, radiotap_len)
}

/// Parse an 802.11 frame at the given offset within `data`.
/// Returns (src_mac, dst_mac, bssid, five_tuple, l7_offset).
fn parse_80211_frame(data: &[u8], offset: usize) -> ParsedFrame {
    if data.len() < offset + 24 {
        // Minimum 802.11 header is 24 bytes
        return (None, None, None, None, None);
    }

    let hdr = &data[offset..];

    // Frame Control (2 bytes, LE)
    let fc = u16::from_le_bytes([hdr[0], hdr[1]]);
    let frame_type = (fc >> 2) & 0x03;
    let to_ds = (fc >> 8) & 0x01;
    let from_ds = (fc >> 9) & 0x01;

    // Address fields (all 6 bytes)
    let addr1: [u8; 6] = hdr[4..10].try_into().unwrap();   // RA/DA
    let addr2: [u8; 6] = hdr[10..16].try_into().unwrap();  // TA/SA
    let addr3: [u8; 6] = hdr[16..22].try_into().unwrap();  // BSSID or DA/SA

    // Determine BSSID based on frame type and DS bits
    let bssid: Option<[u8; 6]> = match frame_type {
        0x00 => {
            // Management frame: Addr3 is always BSSID
            Some(addr3)
        }
        0x02 => {
            // Data frame
            match (to_ds, from_ds) {
                (0, 0) => Some(addr3),       // IBSS: Addr3 = BSSID
                (1, 0) => Some(addr1),       // To AP: Addr1 = BSSID (AP)
                (0, 1) => Some(addr2),       // From AP: Addr2 = BSSID (AP)
                (1, 1) => {
                    // WDS (4-address): BSSID not directly available
                    // Addr1=RA, Addr2=TA, Addr3=DA, Addr4=SA
                    None
                }
                _ => None,
            }
        }
        _ => None, // Control frames: no BSSID
    };

    let src_mac = Some(addr2);
    let dst_mac = Some(addr1);

    // Determine offset to frame body (after 802.11 header)
    // Header is 24 bytes normally, 30 bytes for WDS (4-address)
    let header_len = if frame_type == 0x02 && to_ds == 1 && from_ds == 1 {
        30
    } else {
        // Some management frames have HT Control field or QoS control
        24
    };
    let body_offset = offset + header_len;

    // Try to parse LLC/SNAP → IP for five_tuple
    if data.len() >= body_offset + 8 {
        let llc = &data[body_offset..];
        // Check for LLC/SNAP encapsulation: AA AA 03 00 00 00 XX XX (8 bytes)
        if llc.len() >= 8 && llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03
            && llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00
        {
            let ethertype = u16::from_be_bytes([llc[6], llc[7]]);
            if ethertype == 0x0800 || ethertype == 0x86DD {
                let ip_payload = &llc[8..];
                let info = parse_ip_packet(ip_payload);
                let five_tuple = info.as_ref().map(|i| i.five_tuple);
                let l7_offset = info
                    .and_then(|i| i.l7_offset.map(|o| body_offset + 8 + o));
                return (src_mac, dst_mac, bssid, five_tuple, l7_offset);
            }
        }
    }

    (src_mac, dst_mac, bssid, None, None)
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
    let mut next_header = data[6]; // Next Header field in IPv6 fixed header
    let src_ip = IpAddr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst_ip = IpAddr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    // Walk the IPv6 extension header chain to find the transport-layer header.
    // Each extension header: [next_header: u8, hdr_ext_len: u8, data: (hdr_ext_len + 1) * 8 bytes]
    let mut pos = 40; // start after fixed IPv6 header
    let max_ext_headers = 8; // safety limit — prevents infinite loops on malformed data

    for _ in 0..max_ext_headers {
        match next_header {
            6 | 17 | 58 => break, // TCP, UDP, ICMPv6 — transport layer reached
            59 => return Some(IpInfo {
                // No Next Header — no transport protocol
                five_tuple: FiveTuple {
                    protocol: 59,
                    src_ip,
                    dst_ip,
                    src_port: 0,
                    dst_port: 0,
                },
                l7_offset: None,
            }),
            0 | 43 | 44 | 51 | 60 => {
                // Known extension headers with standard format
                if data.len() < pos + 2 {
                    return None;
                }
                next_header = data[pos];
                let ext_len = data[pos + 1] as usize;
                pos += (ext_len + 1) * 8; // length is in 8-byte units, not counting first 8
            }
            50 => {
                // ESP — encrypted, can't inspect further
                return Some(IpInfo {
                    five_tuple: FiveTuple {
                        protocol: 50,
                        src_ip,
                        dst_ip,
                        src_port: 0,
                        dst_port: 0,
                    },
                    l7_offset: None,
                });
            }
            _ => {
                // Unknown next header — try to treat as transport at current position
                // (could be a non-standard extension)
                break;
            }
        }
    }

    let protocol = next_header;
    let mut l7_offset = None;
    let (src_port, dst_port) = match protocol {
        6 | 17 if data.len() >= pos + 4 => {
            let sp = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let dp = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);

            l7_offset = match protocol {
                6 if data.len() >= pos + 20 => {
                    let doff = ((data[pos + 12] >> 4) & 0x0F) as usize * 4;
                    Some((pos + doff).min(data.len()))
                }
                17 => Some((pos + 8).min(data.len())),
                _ => None,
            };

            (sp, dp)
        }
        58 => (0, 0), // ICMPv6
        _ => {
            l7_offset = Some(pos);
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
