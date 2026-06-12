//! Streaming split-file output writer (buffered, atomic writes).
//! Used for pipelined split mode where packets are written as they arrive
//! instead of being accumulated in memory.

use crate::output::write_pcap_header;
use crate::packet::Packet;
use anyhow::Result;
use hashbrown::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

/// Buffered per-group writer with atomic temp-file + rename.
/// Supports PCAP and L7 output, with LRU eviction of idle writers.
pub struct SplitWriter {
    output_dir: PathBuf,
    output_mode: OutputMode,
    link_type: u32,
    buffer_size: usize,
    max_writers: u32,
    writers: HashMap<String, WriterState>,
    /// Track temp paths for atomic rename on close.
    temp_paths: HashMap<String, (PathBuf, PathBuf)>, // (tmp, final)
    /// LRU generation counter.
    lru_gen: u64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum OutputMode {
    Pcap,
    L7,
}

struct WriterState {
    writer: BufWriter<File>,
    last_access: u64,
    /// Track whether we've written any payload for L7 mode.
    has_content: bool,
}

impl SplitWriter {
    pub fn new(
        output_dir: PathBuf,
        link_type: u32,
        output_mode: OutputMode,
        buffer_size: usize,
        max_writers: u32,
    ) -> Result<Self> {
        std::fs::create_dir_all(&output_dir)?;
        Ok(Self {
            output_dir,
            output_mode,
            link_type,
            buffer_size,
            max_writers,
            writers: HashMap::new(),
            temp_paths: HashMap::new(),
            lru_gen: 0,
        })
    }

    /// Write a packet to the appropriate flow file.
    pub fn write_packet_for_key(&mut self, group_key: &str, pkt: &Packet) -> Result<()> {
        self.maybe_evict();
        self.lru_gen += 1;

        if let Some(state) = self.writers.get_mut(group_key) {
            state.last_access = self.lru_gen;
            match self.output_mode {
                OutputMode::Pcap => {
                    write_pcap_frame(state, pkt)?;
                }
                OutputMode::L7 => {
                    if let Some(l7) = pkt.l7_data() {
                        state.writer.write_all(l7)?;
                        state.has_content = true;
                    }
                }
            }
        } else {
            let safe = sanitize_key(group_key);
            let ext = match self.output_mode {
                OutputMode::Pcap => "pcap",
                OutputMode::L7 => "l7",
            };
            let final_path = self.output_dir.join(format!("{safe}.{ext}"));
            let tmp_path = self.output_dir.join(format!(".{safe}.{ext}.tmp"));

            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::with_capacity(self.buffer_size, file);

            if matches!(self.output_mode, OutputMode::Pcap) {
                write_pcap_header(&mut writer, self.link_type)?;
            }

            let mut has_content = false;
            match self.output_mode {
                OutputMode::Pcap => {
                    write_pcap_frame_raw(
                        &mut writer,
                        pkt.ts_sec,
                        pkt.ts_usec,
                        pkt.cap_len,
                        pkt.orig_len,
                        &pkt.data,
                    )?;
                }
                OutputMode::L7 => {
                    if let Some(l7) = pkt.l7_data() {
                        writer.write_all(l7)?;
                        has_content = true;
                    }
                }
            }

            self.writers.insert(
                group_key.to_string(),
                WriterState {
                    writer,
                    last_access: self.lru_gen,
                    has_content,
                },
            );
            self.temp_paths
                .insert(group_key.to_string(), (tmp_path, final_path));
        }

        Ok(())
    }

    /// Flush all open writers.
    pub fn flush_all(&mut self) -> Result<()> {
        for state in self.writers.values_mut() {
            state.writer.flush()?;
        }
        Ok(())
    }

    /// Close all files and atomically rename temp -> final.
    pub fn close(mut self) -> Result<()> {
        self.flush_all()?;
        for (_, state) in self.writers.drain() {
            drop(state.writer);
        }
        for (_, (tmp, final_path)) in self.temp_paths.drain() {
            if tmp.exists() {
                if self.output_mode == OutputMode::L7 {
                    // For L7, only keep files with content
                    let size = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
                    if size == 0 {
                        let _ = std::fs::remove_file(&tmp);
                        continue;
                    }
                }
                std::fs::rename(&tmp, &final_path)?;
            }
        }
        Ok(())
    }

    /// Evict the least-recently-used writer when over threshold.
    fn maybe_evict(&mut self) {
        if self.writers.len() < self.max_writers as usize {
            return;
        }
        let mut min_gen = u64::MAX;
        let mut lru_key: Option<String> = None;
        for (key, state) in self.writers.iter() {
            if state.last_access < min_gen {
                min_gen = state.last_access;
                lru_key = Some(key.clone());
            }
        }
        if let Some(key) = lru_key {
            if let Some(state) = self.writers.remove(&key) {
                drop(state.writer);
                // Keep the temp file — it may get more packets later.
                // If not, it'll be renamed on close.
                // Re-open if this key gets another packet.
            }
        }
    }

    /// Number of currently open writers.
    pub fn writer_count(&self) -> usize {
        self.writers.len()
    }
}

fn write_pcap_frame(state: &mut WriterState, pkt: &Packet) -> Result<()> {
    write_pcap_frame_raw(
        &mut state.writer,
        pkt.ts_sec,
        pkt.ts_usec,
        pkt.cap_len,
        pkt.orig_len,
        &pkt.data,
    )
}

fn write_pcap_frame_raw(
    w: &mut impl Write,
    ts_sec: u32,
    ts_usec: u32,
    cap_len: u32,
    orig_len: u32,
    data: &[u8],
) -> Result<()> {
    w.write_all(&ts_sec.to_le_bytes())?;
    w.write_all(&ts_usec.to_le_bytes())?;
    w.write_all(&cap_len.to_le_bytes())?;
    w.write_all(&orig_len.to_le_bytes())?;
    w.write_all(data)?;
    Ok(())
}

fn sanitize_key(key: &str) -> String {
    key.replace(
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
