//! PCAP file format reader.

use super::{CaptureReader, ParseError};
use crate::packet::Packet;
use bytes::Bytes;

/// Magic numbers that identify PCAP byte order.
const MAGIC_LE: u32 = 0xA1B2C3D4;
const MAGIC_BE: u32 = 0xD4C3B2A1;

/// PCAP Global Header (24 bytes).
#[derive(Debug)]
struct PcapHeader {
    pub link_type: u32,
    pub snap_len: u32,
    pub ts_resolution_is_nano: bool,
    pub byte_swap: bool,
}

/// PCAP Packet Record Header (16 bytes).
#[derive(Debug)]
struct PcapRecordHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

/// Read a u32 from a byte slice, optionally swapping endianness.
fn read_u32(data: &[u8], offset: usize, swap: bool) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
    if swap {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

fn read_u16(data: &[u8], offset: usize, swap: bool) -> u16 {
    let bytes: [u8; 2] = data[offset..offset + 2].try_into().unwrap();
    if swap {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }
}

/// PCAP file reader.
pub struct PcapReader {
    data: Bytes,
    pos: usize,
    link_type: u32,
    snap_len: u32,
    ts_nano: bool,
    byte_swap: bool,
}

impl PcapReader {
    pub fn new(data: Bytes) -> Result<Self, ParseError> {
        if data.len() < 24 {
            return Err(ParseError::PcapFormat("file too small for global header".into()));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let byte_swap = match magic {
            MAGIC_LE => false,
            MAGIC_BE => true,
            _ => unreachable!(), // open_reader already checks magic
        };

        let version_major = read_u16(&data, 4, byte_swap);
        let version_minor = read_u16(&data, 6, byte_swap);

        // Check for nanosecond timestamp variant
        // Magic 0xA1B23C4D means nanosecond PCAP; version (2,4) also indicates nano
        let ts_nano = magic == 0xA1B23C4D
            || magic == 0x4D3CB2A1
            || (version_major == 2 && version_minor == 4);

        let snap_len = read_u32(&data, 16, byte_swap);
        let link_type = read_u32(&data, 20, byte_swap);

        Ok(Self {
            data,
            pos: 24,
            link_type,
            snap_len,
            ts_nano,
            byte_swap,
        })
    }
}

impl CaptureReader for PcapReader {
    fn link_type(&self) -> u32 {
        self.link_type
    }

    fn next_packet(&mut self) -> Result<Option<Packet>, ParseError> {
        if self.pos + 16 > self.data.len() {
            return Ok(None);
        }

        let ts_sec = read_u32(&self.data, self.pos, self.byte_swap);
        let ts_usec_raw = read_u32(&self.data, self.pos + 4, self.byte_swap);
        let incl_len = read_u32(&self.data, self.pos + 8, self.byte_swap);
        let orig_len = read_u32(&self.data, self.pos + 12, self.byte_swap);
        self.pos += 16;

        // Sanity check
        if incl_len as usize > self.data.len() - self.pos {
            return Err(ParseError::PcapFormat(format!(
                "packet incl_len {} exceeds remaining data at offset {}",
                incl_len, self.pos
            )));
        }

        let pkt_data = self.data.slice(self.pos..self.pos + incl_len as usize);
        self.pos += incl_len as usize;

        // Convert to microseconds if nanosecond resolution
        let ts_usec = if self.ts_nano {
            ts_usec_raw / 1000
        } else {
            ts_usec_raw
        };

        Ok(Some(Packet::from_pcap_record(
            ts_sec, ts_usec, orig_len, pkt_data, self.link_type,
        )))
    }
}
