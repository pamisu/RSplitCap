//! Split-file PCAP output writer.
//! Writes each flow/group to a separate PCAP file, buffering writes.

use super::OutputWriter;
use crate::output::write_pcap_header;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

pub struct SplitWriter {
    output_dir: PathBuf,
    link_type: u32,
    buffer_size: usize,
    writers: HashMap<String, BufWriter<File>>,
}

impl SplitWriter {
    pub fn new(output_dir: PathBuf, link_type: u32, buffer_size: usize) -> Result<Self> {
        fs::create_dir_all(&output_dir)?;
        Ok(Self {
            output_dir,
            link_type,
            buffer_size,
            writers: HashMap::new(),
        })
    }

    fn get_writer(&mut self, key: &str) -> Result<&mut BufWriter<File>> {
        let dir = self.output_dir.clone();
        let lt = self.link_type;
        let bs = self.buffer_size;
        if !self.writers.contains_key(key) {
            let filename = sanitize_key(key);
            let path = dir.join(format!("{}.pcap", filename));
            let file = OpenOptions::new().create(true).append(true).open(&path)?;

            let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
            let mut writer = BufWriter::with_capacity(bs, file);
            if needs_header {
                write_pcap_header(&mut writer, lt)?;
            }
            self.writers.insert(key.to_string(), writer);
        }
        Ok(self.writers.get_mut(key).unwrap())
    }
}

impl OutputWriter for SplitWriter {
    fn write_packet(&mut self, group_key: &str, data: &[u8]) -> Result<()> {
        let w = self.get_writer(group_key)?;
        w.write_all(data)?;
        Ok(())
    }

    fn flush_all(&mut self) -> Result<()> {
        for (_, w) in self.writers.iter_mut() {
            w.flush()?;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.flush_all()?;
        self.writers.clear();
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
