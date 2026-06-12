//! PCAP-NG (pcap next generation) file format reader.
//!
//! Supports Section Header Block (SHB), Interface Description Block (IDB),
//! Enhanced Packet Block (EPB), and Simple Packet Block (SPB).

use super::{CaptureReader, ParseError};
use crate::packet::Packet;
use bytes::Bytes;

/// PCAP-NG block type constants.
const BT_SHB: u32 = 0x0A0D0D0A;
const BT_IDB: u32 = 0x00000001;
const BT_EPB: u32 = 0x00000006;
const BT_SPB: u32 = 0x00000003;

/// Byte-order magic values embedded in SHB.
const BYTE_ORDER_LE: u32 = 0x1A2B3C4D;
const BYTE_ORDER_BE: u32 = 0x4D3C2B1A;

/// Interface description read from IDBs.
#[derive(Debug, Clone)]
struct InterfaceInfo {
    link_type: u16,
    snap_len: u32,
    ts_resolution: u64, // default 1_000_000 (microseconds); can be overridden by if_tsresol option
}

/// PCAP-NG file reader.
pub struct PcapngReader {
    data: Bytes,
    pos: usize,
    byte_swap: bool,
    interfaces: Vec<InterfaceInfo>,
    ts_resolution_is_nano: bool, // section-level flag from SHB
}

impl PcapngReader {
    pub fn new(data: Bytes) -> Result<Self, ParseError> {
        let mut reader = Self {
            data,
            pos: 0,
            byte_swap: false,
            interfaces: Vec::new(),
            ts_resolution_is_nano: false,
        };

        // Parse all IDBs first to build interface table
        reader.parse_blocks(true)?;
        Ok(reader)
    }

    /// Parse blocks from current position.
    /// If `init_only` is true, stops after SHB and IDBs are parsed.
    fn parse_blocks(&mut self, init_only: bool) -> Result<(), ParseError> {
        loop {
            if self.pos + 8 > self.data.len() {
                break;
            }

            let blk_type_raw = read_u32(&self.data, self.pos, false);
            self.pos += 4;
            let blk_len = read_u32(&self.data, self.pos, false) as usize;
            self.pos += 4;

            if blk_len < 12 || self.pos + blk_len - 8 > self.data.len() {
                // Block too short or exceeds data — might be tail padding, stop
                break;
            }

            let body_end = self.pos + blk_len - 12; // exclude trailing length

            match blk_type_raw {
                BT_SHB => {
                    self.parse_shb(body_end)?;
                    if init_only {
                        // Reset position to after SHB for subsequent reads
                    }
                }
                BT_IDB => {
                    self.parse_idb(body_end)?;
                }
                BT_EPB => {
                    if init_only {
                        // Done with headers, stop here
                        self.pos -= 8; // rewind so next_packet can read this block
                        return Ok(());
                    }
                    self.pos -= 8; // rewind for next_packet
                    return Ok(());
                }
                BT_SPB => {
                    if init_only {
                        self.pos -= 8;
                        return Ok(());
                    }
                    self.pos -= 8;
                    return Ok(());
                }
                _ => {
                    // Unknown block type — skip
                }
            }

            // Advance past trailing length
            self.pos = body_end + 4;

            // Round up to 4-byte alignment
            let remainder = self.pos % 4;
            if remainder != 0 {
                self.pos += 4 - remainder;
            }
        }

        Ok(())
    }

    fn parse_shb(&mut self, body_end: usize) -> Result<(), ParseError> {
        if self.pos + 4 > body_end {
            return Err(ParseError::PcapngFormat("SHB too short".into()));
        }
        let order = read_u32(&self.data, self.pos, false);
        self.byte_swap = match order {
            BYTE_ORDER_LE => false,
            BYTE_ORDER_BE => true,
            _ => {
                return Err(ParseError::PcapngFormat(format!(
                    "Unknown byte order magic: 0x{:08X}",
                    order
                )))
            }
        };
        self.pos += 4;

        // Major version (2 bytes), minor version (2 bytes), section length (8 bytes)
        self.pos += 12;

        // Parse options (TLV)
        self.parse_options(body_end, |opt_code, val, _len| {
            if opt_code == 9 {
                // if_tsresol — interface timestamp resolution
                if val == 3 {
                    // 3 means 10^3 = 1ns resolution; the base is a power of 10
                    // Actually: if_tsresol = 9 means 10^-9 (nanoseconds)
                }
            }
        });

        Ok(())
    }

    fn parse_idb(&mut self, body_end: usize) -> Result<(), ParseError> {
        if self.pos + 8 > body_end {
            return Err(ParseError::PcapngFormat("IDB too short".into()));
        }
        let link_type = read_u16(&self.data, self.pos, self.byte_swap);
        self.pos += 2;
        self.pos += 2; // reserved
        let snap_len = read_u32(&self.data, self.pos, self.byte_swap);
        self.pos += 4;

        let mut ts_resolution: u64 = 1_000_000; // default microseconds

        // Parse options
        self.parse_options(body_end, |opt_code, val, _len| {
            if opt_code == 9 {
                // if_tsresol
                // if the high bit is set, resolution is 2^-n (for hardware-based timestamps)
                if val & 0x80 != 0 {
                    // negative power of 2 — rare, ignore for now
                } else {
                    ts_resolution = 10u64.pow(val as u32);
                }
            }
        });

        self.interfaces.push(InterfaceInfo {
            link_type,
            snap_len,
            ts_resolution,
        });

        Ok(())
    }

    /// Parse TLV options within a block body until end-of-options or body_end.
    fn parse_options<F: FnMut(u16, u8, u16)>(&mut self, body_end: usize, mut cb: F) {
        while self.pos + 4 <= body_end {
            let opt_code = read_u16(&self.data, self.pos, self.byte_swap);
            self.pos += 2;
            let opt_len = read_u16(&self.data, self.pos, self.byte_swap) as usize;
            self.pos += 2;

            if opt_code == 0 {
                // opt_endofopt
                break;
            }

            let val_end = self.pos + opt_len;
            if val_end > body_end {
                break;
            }

            if opt_len >= 1 {
                let val = self.data[self.pos];
                cb(opt_code, val, opt_len as u16);
            }

            self.pos = val_end;

            // Option padding to 4-byte boundary
            let rem = self.pos % 4;
            if rem != 0 {
                self.pos += 4 - rem;
            }
        }
    }

    /// Read the next EPB or SPB as a Packet.
    fn read_next_epb(&mut self) -> Result<Option<Packet>, ParseError> {
        if self.pos + 8 > self.data.len() {
            return Ok(None);
        }

        let blk_type = read_u32(&self.data, self.pos, false);
        self.pos += 4;
        let blk_len = read_u32(&self.data, self.pos, false) as usize;
        self.pos += 4;

        if blk_len < 12 || self.pos + blk_len - 8 > self.data.len() {
            return Ok(None);
        }

        match blk_type {
            BT_EPB => {
                self.read_epb(blk_len)
            }
            BT_SPB => {
                self.read_spb(blk_len)
            }
            _ => {
                // Skip unknown blocks
                self.pos = self.pos + blk_len - 12;
                let rem = self.pos % 4;
                if rem != 0 {
                    self.pos += 4 - rem;
                }
                self.pos += 4; // trailing length
                // Try again
                self.read_next_epb()
            }
        }
    }

    fn read_epb(&mut self, blk_len: usize) -> Result<Option<Packet>, ParseError> {
        let body_end = self.pos + blk_len - 12;
        if self.pos + 20 > body_end {
            return Err(ParseError::PcapngFormat("EPB too short".into()));
        }

        let iface_id = read_u32(&self.data, self.pos, self.byte_swap);
        self.pos += 4;

        let ts_high = read_u32(&self.data, self.pos, self.byte_swap) as u64;
        self.pos += 4;
        let ts_low = read_u32(&self.data, self.pos, self.byte_swap) as u64;
        self.pos += 4;

        let cap_len = read_u32(&self.data, self.pos, self.byte_swap);
        self.pos += 4;
        let orig_len = read_u32(&self.data, self.pos, self.byte_swap);
        self.pos += 4;

        if self.pos + cap_len as usize > body_end {
            return Err(ParseError::PcapngFormat("EPB packet data exceeds block".into()));
        }

        let pkt_data = self.data.slice(self.pos..self.pos + cap_len as usize);
        self.pos += cap_len as usize;

        // Round to 4-byte alignment after packet data
        let rem = self.pos % 4;
        if rem != 0 {
            self.pos += 4 - rem;
        }

        // Skip remaining options (if any) till body_end, then skip trailing length
        self.pos = body_end + 4;

        // Compute timestamp
        let ts_raw = (ts_high << 32) | ts_low;
        let iface = self.interfaces.get(iface_id as usize).cloned();
        let resolution = iface.as_ref().map(|i| i.ts_resolution).unwrap_or(1_000_000);
        let link_type = iface.map(|i| i.link_type as u32).unwrap_or(1);

        // Convert to (sec, usec)
        let ts_sec = (ts_raw / resolution) as u32;
        let ts_usec = if resolution >= 1_000_000 {
            ((ts_raw % resolution) / (resolution / 1_000_000)) as u32
        } else {
            // Sub-microsecond resolution — scale up
            ((ts_raw % resolution) * 1_000_000 / resolution) as u32
        };

        Ok(Some(Packet::from_pcap_record(
            ts_sec, ts_usec, orig_len, pkt_data, link_type,
        )))
    }

    fn read_spb(&mut self, blk_len: usize) -> Result<Option<Packet>, ParseError> {
        let body_end = self.pos + blk_len - 12;
        if self.pos + 4 > body_end {
            return Err(ParseError::PcapngFormat("SPB too short".into()));
        }

        let orig_len = read_u32(&self.data, self.pos, self.byte_swap);
        self.pos += 4;

        let cap_len = body_end - self.pos;
        if cap_len == 0 {
            self.pos = body_end + 4;
            return Ok(None);
        }

        let pkt_data = self.data.slice(self.pos..self.pos + cap_len);
        self.pos += cap_len;

        // Round to 4-byte alignment
        let rem = self.pos % 4;
        if rem != 0 {
            self.pos += 4 - rem;
        }
        self.pos = body_end + 4;

        // SPB has no timestamp — use 0
        Ok(Some(Packet::from_pcap_record(
            0, 0, orig_len, pkt_data, 1, // default to Ethernet
        )))
    }
}

impl CaptureReader for PcapngReader {
    fn link_type(&self) -> u32 {
        self.interfaces
            .first()
            .map(|i| i.link_type as u32)
            .unwrap_or(1)
    }

    fn next_packet(&mut self) -> Result<Option<Packet>, ParseError> {
        self.read_next_epb()
    }
}

// ── Byte-order-aware readers ──

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
