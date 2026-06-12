//! Archive writer — streams packets to a `.rsplit` file with post-positioned indexes.

use super::{
    encode_offsets, FileFooter, FileHeader, FlowEntry, SecondaryIndexBuilder, HEADER_SIZE,
    FLOW_ENTRY_SIZE,
};
use crate::packet::Packet;
use anyhow::{Context, Result};
use hashbrown::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;

/// In-memory flow tracking during archive writing.
pub struct FlowState {
    pub flow_id: u64,
    pub five_tuple: Option<crate::packet::FiveTuple>,
    pub packet_offsets: Vec<u64>,
    pub packet_count: u32,
    pub total_bytes: u64,
    pub start_ts_us: u64,
    pub end_ts_us: u64,
}

impl FlowState {
    fn new(flow_id: u64, pkt: &Packet, offset: u64) -> Self {
        Self {
            flow_id,
            five_tuple: pkt.five_tuple,
            packet_offsets: vec![offset],
            packet_count: 1,
            total_bytes: pkt.orig_len as u64,
            start_ts_us: pkt.ts_sec as u64 * 1_000_000 + pkt.ts_usec as u64,
            end_ts_us: pkt.ts_sec as u64 * 1_000_000 + pkt.ts_usec as u64,
        }
    }

    fn add_packet(&mut self, pkt: &Packet, offset: u64) {
        self.packet_offsets.push(offset);
        self.packet_count += 1;
        self.total_bytes += pkt.orig_len as u64;
        self.end_ts_us = pkt.ts_sec as u64 * 1_000_000 + pkt.ts_usec as u64;
    }
}

/// Two-phase archive writer.
///
/// Phase 1: stream packets sequentially, tracking per-flow offsets.
/// Phase 2: finalize — write offset lists, flow table, secondary indexes, footer,
///          then atomically rename temp file to final path.
pub struct ArchiveWriter {
    writer: BufWriter<File>,
    file_pos: u64,
    packet_region_start: u64,
    flows: HashMap<String, FlowState>,
    next_flow_id: u64,
    build_secondary_index: bool,
    tmp_path: String,
    final_path: String,
}

impl ArchiveWriter {
    /// Create a new archive writer. Writes to a temp file, renames on finalize.
    pub fn create(path: &str, link_type: u32, build_secondary_index: bool) -> Result<Self> {
        let final_path = path.to_string();
        let tmp_path = format!("{}.tmp", path);
        let file = File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp archive file: {}", tmp_path))?;
        let mut writer = BufWriter::with_capacity(256 * 1024, file);

        let header = FileHeader {
            link_type,
            ..Default::default()
        };
        writer
            .write_all(&header.to_bytes())
            .context("Failed to write header")?;

        Ok(Self {
            writer,
            file_pos: HEADER_SIZE as u64,
            packet_region_start: HEADER_SIZE as u64,
            flows: HashMap::new(),
            next_flow_id: 1,
            build_secondary_index,
            tmp_path,
            final_path,
        })
    }

    /// Write a single packet to the archive (PCAP frame format).
    /// `group_key` identifies which flow this packet belongs to.
    pub fn write_packet(&mut self, group_key: &str, pkt: &Packet) -> Result<()> {
        let offset = self.file_pos;

        // Write PCAP frame: ts_sec, ts_usec, incl_len, orig_len, data
        self.writer
            .write_all(&pkt.ts_sec.to_le_bytes())?;
        self.writer
            .write_all(&pkt.ts_usec.to_le_bytes())?;
        self.writer
            .write_all(&(pkt.data.len() as u32).to_le_bytes())?;
        self.writer
            .write_all(&pkt.orig_len.to_le_bytes())?;
        self.writer.write_all(&pkt.data)?;

        let frame_size = 16 + pkt.data.len() as u64;
        self.file_pos += frame_size;

        // Track offset for this flow
        if let Some(flow) = self.flows.get_mut(group_key) {
            flow.add_packet(pkt, offset);
        } else {
            let id = self.next_flow_id;
            self.next_flow_id += 1;
            self.flows
                .insert(group_key.to_string(), FlowState::new(id, pkt, offset));
        }

        Ok(())
    }

    /// Finalize the archive: write offset lists, flow table, and footer.
    pub fn finalize(mut self) -> Result<()> {
        let packet_region_size = self.file_pos - self.packet_region_start;

        // ── Flow Packet Region ──
        let flow_packet_offset = self.file_pos;
        // Sort by flow_id for deterministic output
        let mut sorted_flows: Vec<&FlowState> = self.flows.values().collect();
        sorted_flows.sort_by_key(|f| f.flow_id);

        // Build offset lists
        // (flow_id, offset_of_encoded_list, size_of_encoded_list)
        let mut list_positions: Vec<(u64, u64, u32)> = Vec::new();

        for flow in &sorted_flows {
            let encoded = encode_offsets(&flow.packet_offsets);
            let list_pos = self.file_pos;
            self.writer.write_all(&encoded)?;
            self.file_pos += encoded.len() as u64;
            list_positions.push((flow.flow_id, list_pos, encoded.len() as u32));
        }

        let flow_packet_size = self.file_pos - flow_packet_offset;

        // ── Flow Table ──
        let flow_table_offset = self.file_pos;
        let mut entries: Vec<([u8; FLOW_ENTRY_SIZE], u64)> = Vec::new();

        for flow in &sorted_flows {
            let lp = list_positions
                .iter()
                .find(|(id, ..)| *id == flow.flow_id)
                .unwrap();
            let entry = flow_to_entry(flow, lp.1, lp.2);
            let bytes = entry.to_bytes();
            entries.push((bytes, flow.flow_id));
        }

        // Sort entries by flow_id and write
        entries.sort_by_key(|(_, id)| *id);
        for (entry_bytes, _) in &entries {
            self.writer.write_all(entry_bytes)?;
        }

        let flow_count = entries.len() as u64;
        let flow_table_size = flow_count * FLOW_ENTRY_SIZE as u64;
        self.file_pos += flow_table_size;
        self.writer.flush()?;

        // ── Secondary Indexes (optional) ──
        let (sec_idx_offset, sec_idx_size) = if self.build_secondary_index {
            let offset = self.file_pos;
            let mut builder = SecondaryIndexBuilder::new();
            for (entry_bytes, _) in &entries {
                if let Some(entry) = FlowEntry::from_bytes(entry_bytes) {
                    builder.add_flow(&entry);
                }
            }
            let (header, data) = builder.build();
            self.writer.write_all(&header)?;
            self.writer.write_all(&data)?;
            let size = (header.len() + data.len()) as u64;
            self.file_pos += size;
            self.writer.flush()?;
            tracing::info!("Secondary indexes: {} bytes", size);
            (offset, size)
        } else {
            (0u64, 0u64)
        };

        // ── Footer ──
        let footer = FileFooter {
            packet_region_offset: self.packet_region_start,
            packet_region_size,
            flow_packet_offset,
            flow_packet_size,
            flow_table_offset,
            flow_table_size,
            flow_count,
            secondary_index_offset: sec_idx_offset,
            secondary_index_size: sec_idx_size,
            ..Default::default()
        };

        self.writer
            .write_all(&footer.to_bytes())
            .context("Failed to write footer")?;
        self.writer.flush()?;

        tracing::info!(
            "Archive finalized: {} flows, packet region {} bytes, flow table {} bytes",
            flow_count,
            packet_region_size,
            flow_table_size
        );

        // Atomic rename: temp -> final
        drop(self.writer);
        std::fs::rename(&self.tmp_path, &self.final_path)
            .with_context(|| format!("Failed to rename {} -> {}", self.tmp_path, self.final_path))?;

        Ok(())
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

fn flow_to_entry(flow: &FlowState, offset_list_offset: u64, offset_list_size: u32) -> FlowEntry {
    let mut entry = FlowEntry {
        flow_id: flow.flow_id,
        offset_list_offset,
        offset_list_size,
        packet_count: flow.packet_count,
        start_ts_us: flow.start_ts_us,
        end_ts_us: flow.end_ts_us,
        total_bytes: flow.total_bytes,
        ..Default::default()
    };

    if let Some(ft) = &flow.five_tuple {
        entry.protocol = ft.protocol;
        entry.src_port = ft.src_port;
        entry.dst_port = ft.dst_port;
        entry.src_ip = ip_to_bytes(ft.src_ip);
        entry.dst_ip = ip_to_bytes(ft.dst_ip);
    }

    entry
}

fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[10..12].copy_from_slice(&[0xff, 0xff]); // IPv4-mapped IPv6 prefix
            buf[12..16].copy_from_slice(&v4.octets());
            buf
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}
