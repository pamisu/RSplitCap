//! Output writers — split PCAP output, L7 output, and .rsplit archive.

use crate::flow::FlowState;
use anyhow::Result;
use std::path::Path;

mod split;
// TODO: mod l7;
// TODO: mod archive;

/// Common trait for all output writers.
pub trait OutputWriter {
    /// Write a packet to the given group.
    fn write_packet(&mut self, group_key: &str, data: &[u8]) -> Result<()>;
    /// Flush all pending writes.
    fn flush_all(&mut self) -> Result<()>;
    /// Close and finalize all output.
    fn close(&mut self) -> Result<()>;
}

/// Write a complete flow to a PCAP file.
pub fn write_flow_pcap(output_dir: &Path, flow: &FlowState, link_type: u32) -> Result<()> {
    use std::fs;
    use std::io::Write;

    fs::create_dir_all(output_dir)?;

    let key = flow
        .five_tuple
        .map(|ft| {
            let sk = ft.session_key();
            format!(
                "{}_{}_{}_{}_{}",
                sk.protocol, sk.src_ip, sk.dst_ip, sk.src_port, sk.dst_port
            )
        })
        .unwrap_or_else(|| format!("flow_{}", flow.flow_id));

    let filename = sanitize_filename(&key);
    let path = output_dir.join(format!("{}.pcap", filename));

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    // If file is empty (new), write PCAP global header
    let metadata = file.metadata()?;
    if metadata.len() == 0 {
        write_pcap_header(&mut file, link_type)?;
    }

    // Append all packet records
    for pkt in &flow.packets {
        file.write_all(&pkt.ts_sec.to_le_bytes())?;
        file.write_all(&pkt.ts_usec.to_le_bytes())?;
        file.write_all(&pkt.cap_len.to_le_bytes())?;
        file.write_all(&pkt.orig_len.to_le_bytes())?;
        file.write_all(&pkt.data)?;
    }

    Ok(())
}

fn write_pcap_header(writer: &mut impl std::io::Write, link_type: u32) -> Result<()> {
    // PCAP Global Header (24 bytes)
    writer.write_all(&0xA1B2C3D4u32.to_le_bytes())?; // magic
    writer.write_all(&2u16.to_le_bytes())?; // version major
    writer.write_all(&4u16.to_le_bytes())?; // version minor
    writer.write_all(&0i32.to_le_bytes())?; // thiszone (UTC)
    writer.write_all(&0u32.to_le_bytes())?; // sigfigs
    writer.write_all(&65535u32.to_le_bytes())?; // snaplen
    writer.write_all(&link_type.to_le_bytes())?; // link type
    Ok(())
}

fn sanitize_filename(name: &str) -> String {
    name.replace(
        |c: char| {
            c.is_ascii_control()
                || c == '/'
                || c == '\\'
                || c == ':'
                || c == '*'
                || c == '?'
                || c == '"'
                || c == '<'
                || c == '>'
                || c == '|'
        },
        "_",
    )
}
