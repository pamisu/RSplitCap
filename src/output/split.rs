//! Split-file PCAP output writer (buffered, atomic writes).
//! Used for streaming output where flows are written incrementally.
//! Currently the main split path uses `write_flow_pcap` directly;
//! this module provides the building blocks for future streaming split mode.

use crate::output::write_pcap_header;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

/// Buffered per-group PCAP writer with atomic temp-file + rename.
pub struct SplitWriter {
    output_dir: PathBuf,
    link_type: u32,
    buffer_size: usize,
    writers: HashMap<String, BufWriter<File>>,
    /// Track temp paths for atomic rename on close.
    temp_paths: HashMap<String, (PathBuf, PathBuf)>, // (tmp, final)
}

impl SplitWriter {
    pub fn new(output_dir: PathBuf, link_type: u32, buffer_size: usize) -> Result<Self> {
        std::fs::create_dir_all(&output_dir)?;
        Ok(Self {
            output_dir,
            link_type,
            buffer_size,
            writers: HashMap::new(),
            temp_paths: HashMap::new(),
        })
    }

    pub fn write_packet(
        &mut self,
        group_key: &str,
        ts_sec: u32,
        ts_usec: u32,
        cap_len: u32,
        orig_len: u32,
        data: &[u8],
    ) -> Result<()> {
        if !self.writers.contains_key(group_key) {
            let safe = sanitize_key(group_key);
            let final_path = self.output_dir.join(format!("{}.pcap", safe));
            let tmp_path = self.output_dir.join(format!(".{}.pcap.tmp", safe));

            let file = File::create(&tmp_path)?;
            let mut w = BufWriter::with_capacity(self.buffer_size, file);
            write_pcap_header(&mut w, self.link_type)?;
            self.writers.insert(group_key.to_string(), w);
            self.temp_paths
                .insert(group_key.to_string(), (tmp_path, final_path));
        }

        let w = self.writers.get_mut(group_key).unwrap();
        w.write_all(&ts_sec.to_le_bytes())?;
        w.write_all(&ts_usec.to_le_bytes())?;
        w.write_all(&cap_len.to_le_bytes())?;
        w.write_all(&orig_len.to_le_bytes())?;
        w.write_all(data)?;
        Ok(())
    }

    pub fn flush_all(&mut self) -> Result<()> {
        for w in self.writers.values_mut() {
            w.flush()?;
        }
        Ok(())
    }

    /// Close all files and atomically rename temp -> final.
    pub fn close(mut self) -> Result<()> {
        self.flush_all()?;
        for (_, w) in self.writers.drain() {
            drop(w);
        }
        for (_, (tmp, final_path)) in self.temp_paths.drain() {
            if tmp.exists() {
                std::fs::rename(&tmp, &final_path)?;
            }
        }
        Ok(())
    }
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
