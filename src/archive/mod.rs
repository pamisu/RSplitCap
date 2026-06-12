//! Custom `.rsplit` single-file archive format.
//!
//! Layout:
//! ```text
//! File Header (64B) | Packet Region | Flow Packet Region | Flow Table | Footer (128B)
//! ```
//!
//! All indexes are post-positioned; packets are written sequentially.
//! Delta + LEB128 encoding compresses packet offset lists.

pub mod writer;
pub mod reader;

/// File format constants.
pub const MAGIC: &[u8; 8] = b"RSPLIT02";
pub const FOOTER_MAGIC: &[u8; 8] = b"RSPLFOOT";
pub const HEADER_SIZE: usize = 64;
pub const FOOTER_SIZE: usize = 128;
pub const FLOW_ENTRY_SIZE: usize = 96;
pub const FORMAT_VERSION: u32 = 2;

/// File Header — fixed 64 bytes at file start.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct FileHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub link_type: u32,
    pub ts_resolution: u8, // 0 = microseconds, 1 = nanoseconds
    pub flags: u8,
    pub reserved: [u8; 46],
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            magic: *MAGIC,
            version: FORMAT_VERSION,
            link_type: 1,     // Ethernet
            ts_resolution: 0, // microseconds
            flags: 0,
            reserved: [0u8; 46],
        }
    }
}

impl FileHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.link_type.to_le_bytes());
        buf[16] = self.ts_resolution;
        buf[17] = self.flags;
        // reserved stays zero
        buf
    }
}

/// Flow Table entry — fixed 96 bytes per flow.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FlowEntry {
    pub flow_id: u64,
    pub protocol: u8,
    pub _pad1: [u8; 7],
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad2: [u8; 4],
    pub offset_list_offset: u64,
    pub offset_list_size: u32,
    pub packet_count: u32,
    pub start_ts_us: u64,
    pub end_ts_us: u64,
    pub total_bytes: u64,
}

impl FlowEntry {
    pub fn to_bytes(self) -> [u8; FLOW_ENTRY_SIZE] {
        let mut buf = [0u8; FLOW_ENTRY_SIZE];
        let mut pos = 0;
        buf[pos..pos + 8].copy_from_slice(&self.flow_id.to_le_bytes());
        pos += 8;
        buf[pos] = self.protocol;
        pos += 8; // +7 pad
        buf[pos..pos + 16].copy_from_slice(&self.src_ip);
        pos += 16;
        buf[pos..pos + 16].copy_from_slice(&self.dst_ip);
        pos += 16;
        buf[pos..pos + 2].copy_from_slice(&self.src_port.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&self.dst_port.to_le_bytes());
        pos += 6; // +4 pad
        buf[pos..pos + 8].copy_from_slice(&self.offset_list_offset.to_le_bytes());
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&self.offset_list_size.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.packet_count.to_le_bytes());
        pos += 4;
        buf[pos..pos + 8].copy_from_slice(&self.start_ts_us.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.end_ts_us.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.total_bytes.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < FLOW_ENTRY_SIZE {
            return None;
        }
        let mut pos = 0;
        let flow_id = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let protocol = data[pos];
        pos += 8;
        let src_ip: [u8; 16] = data[pos..pos + 16].try_into().ok()?;
        pos += 16;
        let dst_ip: [u8; 16] = data[pos..pos + 16].try_into().ok()?;
        pos += 16;
        let src_port = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?);
        pos += 2;
        let dst_port = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?);
        pos += 6;
        let offset_list_offset = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let offset_list_size = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
        pos += 4;
        let packet_count = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
        pos += 4;
        let start_ts_us = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let end_ts_us = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let total_bytes = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        Some(Self {
            flow_id,
            protocol,
            _pad1: [0; 7],
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            _pad2: [0; 4],
            offset_list_offset,
            offset_list_size,
            packet_count,
            start_ts_us,
            end_ts_us,
            total_bytes,
        })
    }
}

/// File Footer — fixed 128 bytes at file end.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct FileFooter {
    pub magic: [u8; 8],
    pub version: u32,
    pub _pad1: [u8; 4],
    pub packet_region_offset: u64,
    pub packet_region_size: u64,
    pub flow_packet_offset: u64,
    pub flow_packet_size: u64,
    pub flow_table_offset: u64,
    pub flow_table_size: u64,
    pub flow_count: u64,
    pub secondary_index_offset: u64,
    pub secondary_index_size: u64,
    pub reserved: [u8; 64],
}

impl Default for FileFooter {
    fn default() -> Self {
        Self {
            magic: *FOOTER_MAGIC,
            version: FORMAT_VERSION,
            _pad1: [0; 4],
            packet_region_offset: 0,
            packet_region_size: 0,
            flow_packet_offset: 0,
            flow_packet_size: 0,
            flow_table_offset: 0,
            flow_table_size: 0,
            flow_count: 0,
            secondary_index_offset: 0,
            secondary_index_size: 0,
            reserved: [0; 64],
        }
    }
}

impl FileFooter {
    pub fn to_bytes(&self) -> [u8; FOOTER_SIZE] {
        let mut buf = [0u8; FOOTER_SIZE];
        let mut pos = 0;
        buf[pos..pos + 8].copy_from_slice(&self.magic);
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&self.version.to_le_bytes());
        pos += 8; // +4 pad
        buf[pos..pos + 8].copy_from_slice(&self.packet_region_offset.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.packet_region_size.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.flow_packet_offset.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.flow_packet_size.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.flow_table_offset.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.flow_table_size.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.flow_count.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.secondary_index_offset.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.secondary_index_size.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < FOOTER_SIZE {
            return None;
        }
        let magic: [u8; 8] = data[0..8].try_into().ok()?;
        if &magic != FOOTER_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let packet_region_offset = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let packet_region_size = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let flow_packet_offset = u64::from_le_bytes(data[32..40].try_into().ok()?);
        let flow_packet_size = u64::from_le_bytes(data[40..48].try_into().ok()?);
        let flow_table_offset = u64::from_le_bytes(data[48..56].try_into().ok()?);
        let flow_table_size = u64::from_le_bytes(data[56..64].try_into().ok()?);
        let flow_count = u64::from_le_bytes(data[64..72].try_into().ok()?);
        let secondary_index_offset = u64::from_le_bytes(data[72..80].try_into().ok()?);
        let secondary_index_size = u64::from_le_bytes(data[80..88].try_into().ok()?);
        Some(Self {
            magic,
            version,
            _pad1: [0; 4],
            packet_region_offset,
            packet_region_size,
            flow_packet_offset,
            flow_packet_size,
            flow_table_offset,
            flow_table_size,
            flow_count,
            secondary_index_offset,
            secondary_index_size,
            reserved: [0; 64],
        })
    }
}

/// Encode a sorted list of u64 offsets using Delta + LEB128 compression.
pub fn encode_offsets(offsets: &[u64]) -> Vec<u8> {
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(offsets.len() * 3);
    // First offset stored as full u64 LE
    buf.extend_from_slice(&offsets[0].to_le_bytes());
    // Subsequent offsets as LEB128 delta
    for w in offsets.windows(2) {
        let delta = w[1] - w[0];
        leb128::write::unsigned(&mut buf, delta).unwrap();
    }
    buf
}

/// Decode a Delta+LEB128 encoded offset list.
pub fn decode_offsets(data: &[u8], count: usize) -> Vec<u64> {
    if count == 0 || data.len() < 8 {
        return Vec::new();
    }
    let mut offsets = Vec::with_capacity(count);
    let first = u64::from_le_bytes(data[0..8].try_into().unwrap());
    offsets.push(first);
    let mut pos = 8;
    while offsets.len() < count && pos < data.len() {
        if let Ok(delta) = leb128::read::unsigned(&mut &data[pos..]) {
            let delta_bytes = leb128_bytes_len(delta);
            pos += delta_bytes;
            let next = offsets.last().unwrap() + delta;
            offsets.push(next);
        } else {
            break;
        }
    }
    offsets
}

// ── Secondary Indexes ──

/// Header for the secondary indexes region (36 bytes).
pub const SEC_IDX_HEADER_SIZE: usize = 36;

/// Build all three secondary indexes from flow entries.
#[derive(Default)]
pub struct SecondaryIndexBuilder {
    /// (ip_bytes, flow_id)
    ip_entries: Vec<([u8; 16], u64)>,
    /// (port, flow_id)
    port_entries: Vec<(u16, u64)>,
    /// (protocol, flow_id)
    proto_entries: Vec<(u8, u64)>,
}

impl SecondaryIndexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_flow(&mut self, entry: &FlowEntry) {
        self.ip_entries.push((entry.src_ip, entry.flow_id));
        self.ip_entries.push((entry.dst_ip, entry.flow_id));
        self.port_entries.push((entry.src_port, entry.flow_id));
        self.port_entries.push((entry.dst_port, entry.flow_id));
        self.proto_entries.push((entry.protocol, entry.flow_id));
    }

    /// Encode all indexes into a byte buffer. Returns (header_36b, index_data).
    pub fn build(mut self) -> (Vec<u8>, Vec<u8>) {
        // Sort and dedup
        self.ip_entries.sort_by_key(|(ip, id)| (*ip, *id));
        self.ip_entries.dedup();
        self.port_entries.sort_by_key(|(p, id)| (*p, *id));
        self.port_entries.dedup();
        self.proto_entries.sort_by_key(|(p, id)| (*p, *id));
        self.proto_entries.dedup();

        let mut data = Vec::new();
        let ip_off = data.len() as u64;
        encode_ip_index(&self.ip_entries, &mut data);
        let ip_size = data.len() as u32 - ip_off as u32;

        let port_off = data.len() as u64;
        encode_port_index(&self.port_entries, &mut data);
        let port_size = data.len() as u32 - port_off as u32;

        let proto_off = data.len() as u64;
        encode_proto_index(&self.proto_entries, &mut data);
        let proto_size = data.len() as u32 - proto_off as u32;

        let mut header = Vec::with_capacity(SEC_IDX_HEADER_SIZE);
        header.extend_from_slice(&ip_off.to_le_bytes());
        header.extend_from_slice(&ip_size.to_le_bytes());
        header.extend_from_slice(&port_off.to_le_bytes());
        header.extend_from_slice(&port_size.to_le_bytes());
        header.extend_from_slice(&proto_off.to_le_bytes());
        header.extend_from_slice(&proto_size.to_le_bytes());

        (header, data)
    }
}

fn encode_ip_index(entries: &[([u8; 16], u64)], out: &mut Vec<u8>) {
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut i = 0;
    while i < entries.len() {
        let ip = entries[i].0;
        let mut ids = Vec::new();
        while i < entries.len() && entries[i].0 == ip {
            ids.push(entries[i].1);
            i += 1;
        }
        ids.sort();
        ids.dedup();
        out.extend_from_slice(&ip);
        out.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in &ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
    }
}

fn encode_port_index(entries: &[(u16, u64)], out: &mut Vec<u8>) {
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut i = 0;
    while i < entries.len() {
        let port = entries[i].0;
        let mut ids = Vec::new();
        while i < entries.len() && entries[i].0 == port {
            ids.push(entries[i].1);
            i += 1;
        }
        ids.sort();
        ids.dedup();
        out.extend_from_slice(&port.to_le_bytes());
        out.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in &ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
    }
}

fn encode_proto_index(entries: &[(u8, u64)], out: &mut Vec<u8>) {
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut i = 0;
    while i < entries.len() {
        let proto = entries[i].0;
        let mut ids = Vec::new();
        while i < entries.len() && entries[i].0 == proto {
            ids.push(entries[i].1);
            i += 1;
        }
        ids.sort();
        ids.dedup();
        out.push(proto);
        out.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in &ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
    }
}

/// Parse secondary indexes from raw bytes (header + data).
pub struct SecondaryIndexes {
    data: Vec<u8>,
    ip_off: u64,
    ip_size: u32,
    port_off: u64,
    port_size: u32,
    proto_off: u64,
    proto_size: u32,
}

impl SecondaryIndexes {
    pub fn parse(header_and_data: &[u8]) -> Option<Self> {
        if header_and_data.len() < SEC_IDX_HEADER_SIZE {
            return None;
        }
        let ip_off = u64::from_le_bytes(header_and_data[0..8].try_into().ok()?);
        let ip_size = u32::from_le_bytes(header_and_data[8..12].try_into().ok()?);
        let port_off = u64::from_le_bytes(header_and_data[12..20].try_into().ok()?);
        let port_size = u32::from_le_bytes(header_and_data[20..24].try_into().ok()?);
        let proto_off = u64::from_le_bytes(header_and_data[24..32].try_into().ok()?);
        let proto_size = u32::from_le_bytes(header_and_data[32..36].try_into().ok()?);
        Some(Self {
            data: header_and_data.to_vec(),
            ip_off,
            ip_size,
            port_off,
            port_size,
            proto_off,
            proto_size,
        })
    }

    /// Look up flow IDs by IP. Returns sorted, deduplicated list.
    pub fn lookup_ip(&self, ip_bytes: &[u8; 16]) -> Vec<u64> {
        lookup_generic(&self.data, self.ip_off, self.ip_size, 16, ip_bytes)
    }

    /// Look up flow IDs by port.
    pub fn lookup_port(&self, port: u16) -> Vec<u64> {
        let key = port.to_le_bytes();
        lookup_generic(&self.data, self.port_off, self.port_size, 2, &key)
    }

    /// Look up flow IDs by protocol.
    pub fn lookup_proto(&self, proto: u8) -> Vec<u64> {
        lookup_generic(&self.data, self.proto_off, self.proto_size, 1, &[proto])
    }
}

/// Generic linear scan (sorted keys) for secondary index lookup.
/// `offset` and `size` are relative to the data portion (after the 36-byte header).
fn lookup_generic(data: &[u8], offset: u64, size: u32, key_len: usize, key: &[u8]) -> Vec<u64> {
    if size < 4 || key_len == 0 {
        return Vec::new();
    }
    // Offsets are relative to data portion, but `data` includes the 36-byte header
    let base = SEC_IDX_HEADER_SIZE;
    let start = base + offset as usize;
    let end = start + size as usize;
    if end > data.len() {
        return Vec::new();
    }
    let count = u32::from_le_bytes(data[start..start + 4].try_into().unwrap()) as usize;
    let mut pos = start + 4;

    for _ in 0..count {
        if pos + key_len + 4 > end {
            break;
        }
        let entry_key = &data[pos..pos + key_len];
        pos += key_len;
        let flow_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let ids_end = pos + flow_count * 8;
        if ids_end > end {
            break;
        }
        if entry_key == key {
            let mut ids = Vec::with_capacity(flow_count);
            for j in 0..flow_count {
                let id = u64::from_le_bytes(
                    data[pos + j * 8..pos + j * 8 + 8].try_into().unwrap(),
                );
                ids.push(id);
            }
            return ids;
        }
        pos = ids_end;
    }
    Vec::new()
}

fn leb128_bytes_len(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let mut v = value;
    let mut len = 0;
    while v > 0 {
        len += 1;
        v >>= 7;
    }
    len
}
