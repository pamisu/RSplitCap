//! Output writers — split PCAP output, L7 output, and .rsplit archive.

use crate::flow::FlowState;
use anyhow::{Context, Result};
use std::io::{BufWriter, Write};
use std::path::Path;

mod split;

pub use split::{OutputMode, SplitWriter};

/// Write a complete flow to a PCAP file using atomic temp-file + rename.
pub fn write_flow_pcap(
    output_dir: &Path,
    flow: &FlowState,
    link_type: u32,
    buffer_size: usize,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;

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
    let final_path = output_dir.join(format!("{}.pcap", filename));

    // Write to temp file first, then rename atomically
    let tmp_path = output_dir.join(format!(".{}.pcap.tmp", filename));
    let file = std::fs::File::create(&tmp_path)
        .with_context(|| format!("Failed to create temp file {:?}", tmp_path))?;
    let mut writer = BufWriter::with_capacity(buffer_size, file);

    write_pcap_header(&mut writer, link_type)?;

    for pkt in &flow.packets {
        writer.write_all(&pkt.ts_sec.to_le_bytes())?;
        writer.write_all(&pkt.ts_usec.to_le_bytes())?;
        writer.write_all(&pkt.cap_len.to_le_bytes())?;
        writer.write_all(&pkt.orig_len.to_le_bytes())?;
        writer.write_all(&pkt.data)?;
    }

    writer.flush()?;
    drop(writer);

    std::fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("Failed to rename {:?} -> {:?}", tmp_path, final_path))?;

    Ok(())
}

/// Write L7 payload for a flow to a file (atomic temp-file + rename).
pub fn write_flow_l7(output_dir: &Path, flow: &FlowState, buffer_size: usize) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let filename = flow
        .five_tuple
        .map(|ft| {
            let sk = ft.session_key();
            format!(
                "{}_{}_{}_{}_{}",
                sk.protocol, sk.src_ip, sk.dst_ip, sk.src_port, sk.dst_port
            )
        })
        .unwrap_or_else(|| format!("flow_{}", flow.flow_id));

    let safe_name = sanitize_filename(&filename);
    let final_path = output_dir.join(format!("{}.l7", safe_name));
    let tmp_path = output_dir.join(format!(".{}.l7.tmp", safe_name));

    let file = std::fs::File::create(&tmp_path)?;
    let mut writer = BufWriter::with_capacity(buffer_size, file);

    for pkt in &flow.packets {
        if let Some(l7) = pkt.l7_data() {
            writer.write_all(l7)?;
        }
    }

    writer.flush()?;
    drop(writer);

    if std::fs::metadata(&tmp_path).map(|m| m.len() > 0).unwrap_or(false) {
        std::fs::rename(&tmp_path, &final_path)?;
    } else {
        std::fs::remove_file(&tmp_path)?;
    }

    Ok(())
}

pub fn write_pcap_header(writer: &mut impl Write, link_type: u32) -> Result<()> {
    writer.write_all(&0xA1B2C3D4u32.to_le_bytes())?;
    writer.write_all(&2u16.to_le_bytes())?;
    writer.write_all(&4u16.to_le_bytes())?;
    writer.write_all(&0i32.to_le_bytes())?;
    writer.write_all(&0u32.to_le_bytes())?;
    writer.write_all(&65535u32.to_le_bytes())?;
    writer.write_all(&link_type.to_le_bytes())?;
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
