//! Packet capture file parsing — supports PCAP and PCAP-NG formats.

use crate::packet::Packet;
use bytes::Bytes;

mod pcap;
mod pcapng;

pub use pcap::PcapReader;
pub use pcapng::PcapngReader;

/// Error type for capture file parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid PCAP format: {0}")]
    PcapFormat(String),
    #[error("Invalid PCAP-NG format: {0}")]
    PcapngFormat(String),
    #[error("Unsupported file format (unknown magic number)")]
    UnknownFormat,
}

/// Trait for reading packets from a capture file.
pub trait CaptureReader: Send {
    /// Get the link-layer type (e.g., LINKTYPE_ETHERNET = 1).
    fn link_type(&self) -> u32;
    /// Read the next packet. Returns `None` at end-of-file.
    fn next_packet(&mut self) -> Result<Option<Packet>, ParseError>;
}

/// Auto-detect format and open the appropriate reader.
/// PCAP magic: 0xA1B2C3D4 (LE micro), 0xD4C3B2A1 (BE micro), 0xA1B23C4D (LE nano), 0x4D3CB2A1 (BE nano)
/// PCAP-NG magic: 0x0A0D0D0A (Section Header Block type)
pub fn open_reader(data: Bytes) -> Result<Box<dyn CaptureReader>, ParseError> {
    if data.len() < 4 {
        return Err(ParseError::UnknownFormat);
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match magic {
        // PCAP (all variants)
        0xA1B2C3D4 | 0xD4C3B2A1 | 0xA1B23C4D | 0x4D3CB2A1 => {
            Ok(Box::new(PcapReader::new(data)?))
        }
        // PCAP-NG (SHB block type)
        0x0A0D0D0A => Ok(Box::new(PcapngReader::new(data)?)),
        _ => Err(ParseError::UnknownFormat),
    }
}
