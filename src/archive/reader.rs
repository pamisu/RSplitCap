//! Archive reader — open a `.rsplit` file, parse indexes, extract flows.

use super::{decode_offsets, FileFooter, FlowEntry, FOOTER_SIZE, FLOW_ENTRY_SIZE};
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

/// Opened archive with memory-mapped access.
pub struct ArchiveReader {
    mmap: Mmap,
    footer: FileFooter,
    link_type: u32,
    /// Parsed flow entries for quick lookup.
    entries: Vec<FlowEntry>,
}

impl ArchiveReader {
    /// Open a `.rsplit` archive file.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).context("Failed to open archive")?;
        let file_size = file.metadata()?.len();

        if file_size < FOOTER_SIZE as u64 {
            anyhow::bail!("File too small to be a valid archive");
        }

        // Memory-map the entire file
        let mmap = unsafe { Mmap::map(&file).context("Failed to mmap archive")? };

        // Read header to get link_type
        let link_type = if mmap.len() >= 64 {
            u32::from_le_bytes(mmap[12..16].try_into().unwrap())
        } else {
            1 // default Ethernet
        };

        // Read footer (last 128 bytes)
        let footer_start = file_size as usize - FOOTER_SIZE;
        let footer =
            FileFooter::from_bytes(&mmap[footer_start..]).context("Invalid archive footer")?;

        // Parse flow table
        let ft_start = footer.flow_table_offset as usize;
        let ft_end = ft_start + footer.flow_table_size as usize;
        if ft_end > mmap.len() {
            anyhow::bail!("Flow table extends beyond file");
        }
        let mut entries = Vec::with_capacity(footer.flow_count as usize);
        let mut pos = ft_start;
        while pos + FLOW_ENTRY_SIZE <= ft_end {
            if let Some(entry) = FlowEntry::from_bytes(&mmap[pos..pos + FLOW_ENTRY_SIZE]) {
                entries.push(entry);
            }
            pos += FLOW_ENTRY_SIZE;
        }

        tracing::info!(
            "Opened archive: {} flows, packet region {} bytes",
            entries.len(),
            footer.packet_region_size
        );

        Ok(Self {
            mmap,
            footer,
            link_type,
            entries,
        })
    }

    /// Return the number of flows in the archive.
    pub fn flow_count(&self) -> usize {
        self.entries.len()
    }

    /// List all flow entries.
    pub fn list_flows(&self) -> &[FlowEntry] {
        &self.entries
    }

    /// Get a flow entry by ID.
    pub fn get_flow(&self, flow_id: u64) -> Option<&FlowEntry> {
        self.entries.iter().find(|e| e.flow_id == flow_id)
    }

    /// Find flows matching an IP address.
    pub fn find_by_ip(&self, ip: IpAddr) -> Vec<&FlowEntry> {
        let ip_bytes = ip_to_bytes(ip);
        self.entries
            .iter()
            .filter(|e| e.src_ip == ip_bytes || e.dst_ip == ip_bytes)
            .collect()
    }

    /// Find flows matching a port number.
    pub fn find_by_port(&self, port: u16) -> Vec<&FlowEntry> {
        self.entries
            .iter()
            .filter(|e| e.src_port == port || e.dst_port == port)
            .collect()
    }

    /// Find flows matching a protocol.
    pub fn find_by_protocol(&self, proto: u8) -> Vec<&FlowEntry> {
        self.entries.iter().filter(|e| e.protocol == proto).collect()
    }

    /// Decode the packet offsets for a given flow entry.
    pub fn get_packet_offsets(&self, entry: &FlowEntry) -> Result<Vec<u64>> {
        let start = entry.offset_list_offset as usize;
        let end = start + entry.offset_list_size as usize;
        if end > self.mmap.len() {
            anyhow::bail!("Offset list extends beyond file");
        }
        Ok(decode_offsets(
            &self.mmap[start..end],
            entry.packet_count as usize,
        ))
    }

    /// Extract a single flow into a valid PCAP file.
    pub fn extract_flow_to_writer(
        &self,
        entry: &FlowEntry,
        writer: &mut impl Write,
    ) -> Result<()> {
        let offsets = self.get_packet_offsets(entry)?;

        // Write PCAP global header
        writer.write_all(&0xA1B2C3D4u32.to_le_bytes())?; // magic
        writer.write_all(&2u16.to_le_bytes())?; // version major
        writer.write_all(&4u16.to_le_bytes())?; // version minor
        writer.write_all(&0i32.to_le_bytes())?; // timezone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&65535u32.to_le_bytes())?; // snaplen
        writer.write_all(&self.link_type.to_le_bytes())?; // link type

        // Copy each PCAP frame from the packet region
        for &offset in &offsets {
            let pos = offset as usize;
            // PCAP frame: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) + data
            if pos + 16 > self.mmap.len() {
                break;
            }
            let incl_len =
                u32::from_le_bytes(self.mmap[pos + 8..pos + 12].try_into().unwrap()) as usize;
            let frame_end = pos + 16 + incl_len;
            if frame_end > self.mmap.len() {
                break;
            }
            writer.write_all(&self.mmap[pos..frame_end])?;
        }

        Ok(())
    }

    /// Extract a flow to a file.
    pub fn extract_flow_to_file(&self, entry: &FlowEntry, output_path: &Path) -> Result<()> {
        let file = File::create(output_path)?;
        let mut writer = std::io::BufWriter::new(file);
        self.extract_flow_to_writer(entry, &mut writer)?;
        Ok(())
    }
}

// Re-export ip_to_bytes for reader use
pub fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[10..12].copy_from_slice(&[0xff, 0xff]);
            buf[12..16].copy_from_slice(&v4.octets());
            buf
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}
