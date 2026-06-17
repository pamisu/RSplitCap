//! PyO3 bindings for rsplitcap.
//!
//! Provides native Python classes: Archive, Flow, Packet
//! and functions: create_archive, split, pipe_archive.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;
use std::sync::Arc;

use crate::archive::reader::ArchiveReader;
use crate::archive::writer::ArchiveWriter;
use crate::archive::FlowEntry;
use crate::filter::Filter;
use crate::flow::FlowManager;
use crate::output::{OutputMode, SplitWriter};
use crate::parser::open_reader;
use crate::packet::Packet as RsPacket;

use crate::cli;

// ── Helpers ──────────────────────────────────────────────────────────

fn ip_bytes_to_str(ip_bytes: &[u8; 16]) -> String {
    if ip_bytes[0..10] == [0u8; 10] && ip_bytes[10..12] == [0xff, 0xff] {
        format!(
            "{}.{}.{}.{}",
            ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
        )
    } else {
        let segments: Vec<String> = ip_bytes
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect();
        segments.join(":")
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "?",
    }
}

fn read_input_bytes(path: &str) -> anyhow::Result<bytes::Bytes> {
    use memmap2::Mmap;
    use std::fs::File;
    use std::io::Read;
    use bytes::Bytes;

    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(Bytes::from(buf))
    } else {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(Bytes::from_owner(mmap))
    }
}

fn build_filter(ip_filters: &[String], port_filters: &[u16]) -> Filter {
    let mut filter = Filter::new();
    for ip_str in ip_filters {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            filter.add_ip(ip);
        }
    }
    for &port in port_filters {
        filter.add_port(port);
    }
    filter
}

fn make_temp_archive_path() -> String {
    format!("/tmp/rsplitcap_py_{}.rsplit", std::process::id())
}

// ── Packet ────────────────────────────────────────────────────────────

#[pyclass(name = "Packet")]
pub struct PacketPy {
    #[pyo3(get)]
    pub ts_sec: u32,
    #[pyo3(get)]
    pub ts_usec: u32,
    #[pyo3(get)]
    pub length: u32,
    #[pyo3(get)]
    pub orig_len: u32,
    data: Vec<u8>,
}

#[pymethods]
impl PacketPy {
    #[getter]
    fn ts(&self) -> f64 {
        self.ts_sec as f64 + self.ts_usec as f64 / 1_000_000.0
    }

    /// Raw L2 frame data (Ethernet frame or equivalent).
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.data)
    }

    fn __repr__(&self) -> String {
        format!(
            "Packet(ts={:.6}, length={}, orig_len={})",
            self.ts(), self.length, self.orig_len
        )
    }
}

// ── Flow ──────────────────────────────────────────────────────────────

#[pyclass(name = "Flow")]
pub struct FlowPy {
    archive: Arc<ArchiveReader>,
    entry: FlowEntry,
}

#[pymethods]
impl FlowPy {
    #[getter]
    fn id(&self) -> u64 {
        self.entry.flow_id
    }

    #[getter]
    fn proto(&self) -> u8 {
        self.entry.protocol
    }

    #[getter]
    fn proto_name(&self) -> &'static str {
        proto_name(self.entry.protocol)
    }

    #[getter]
    fn src_addr(&self) -> String {
        ip_bytes_to_str(&self.entry.src_ip)
    }

    #[getter]
    fn dst_addr(&self) -> String {
        ip_bytes_to_str(&self.entry.dst_ip)
    }

    #[getter]
    fn src_port(&self) -> u16 {
        self.entry.src_port
    }

    #[getter]
    fn dst_port(&self) -> u16 {
        self.entry.dst_port
    }

    #[getter]
    fn packet_count(&self) -> u32 {
        self.entry.packet_count
    }

    #[getter]
    fn total_bytes(&self) -> u64 {
        self.entry.total_bytes
    }

    #[getter]
    fn start_ts(&self) -> f64 {
        self.entry.start_ts_us as f64 / 1_000_000.0
    }

    #[getter]
    fn end_ts(&self) -> f64 {
        self.entry.end_ts_us as f64 / 1_000_000.0
    }

    /// Return all packets in this flow as a list of Packet objects.
    fn packets(&self) -> PyResult<Vec<PacketPy>> {
        let offsets = self
            .archive
            .get_packet_offsets(&self.entry)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

        let mut packets = Vec::with_capacity(offsets.len());
        for &offset in &offsets {
            if let Some(frame) = self.archive.read_frame_bytes(offset) {
                if frame.len() >= 16 {
                    let ts_sec = u32::from_le_bytes(frame[0..4].try_into().unwrap());
                    let ts_usec = u32::from_le_bytes(frame[4..8].try_into().unwrap());
                    let length = u32::from_le_bytes(frame[8..12].try_into().unwrap());
                    let orig_len = u32::from_le_bytes(frame[12..16].try_into().unwrap());
                    packets.push(PacketPy {
                        ts_sec,
                        ts_usec,
                        length,
                        orig_len,
                        data: frame[16..16 + length as usize].to_vec(),
                    });
                }
            }
        }
        Ok(packets)
    }

    fn __repr__(&self) -> String {
        format!(
            "Flow(id={}, {} {}:{} -> {}:{}, {} pkts, {} bytes)",
            self.entry.flow_id,
            proto_name(self.entry.protocol),
            ip_bytes_to_str(&self.entry.src_ip),
            self.entry.src_port,
            ip_bytes_to_str(&self.entry.dst_ip),
            self.entry.dst_port,
            self.entry.packet_count,
            self.entry.total_bytes,
        )
    }
}

// ── Archive ───────────────────────────────────────────────────────────

#[pyclass(name = "Archive")]
pub struct ArchivePy {
    reader: Arc<ArchiveReader>,
    /// Temp file path for cleanup (only set by read_flows).
    _temp_file: Option<String>,
}

#[pymethods]
impl ArchivePy {
    /// Open a .rsplit archive file.
    #[staticmethod]
    fn open(path: &str) -> PyResult<Self> {
        let reader = ArchiveReader::open(&PathBuf::from(path))
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;
        Ok(Self {
            reader: Arc::new(reader),
            _temp_file: None,
        })
    }

    #[getter]
    fn flow_count(&self) -> usize {
        self.reader.list_flows().len()
    }

    #[getter]
    fn link_type(&self) -> u32 {
        self.reader.link_type()
    }

    /// Return all flows as a list of Flow objects.
    fn flows(&self) -> Vec<FlowPy> {
        self.reader
            .list_flows()
            .iter()
            .map(|entry| FlowPy {
                archive: Arc::clone(&self.reader),
                entry: *entry,
            })
            .collect()
    }

    /// Get a specific flow by ID.
    fn get_flow(&self, flow_id: u64) -> Option<FlowPy> {
        self.reader.get_flow(flow_id).map(|entry| FlowPy {
            archive: Arc::clone(&self.reader),
            entry: *entry,
        })
    }

    /// Find flows matching an IP address (src or dst).
    fn find_by_ip(&self, ip_str: &str) -> PyResult<Vec<FlowPy>> {
        let ip: std::net::IpAddr = ip_str
            .parse()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let ids = self.reader.find_by_ip(ip);
        Ok(ids
            .into_iter()
            .filter_map(|id| self.reader.get_flow(id))
            .map(|entry| FlowPy {
                archive: Arc::clone(&self.reader),
                entry: *entry,
            })
            .collect())
    }

    /// Find flows matching a port number (src or dst).
    fn find_by_port(&self, port: u16) -> Vec<FlowPy> {
        let ids = self.reader.find_by_port(port);
        ids.into_iter()
            .filter_map(|id| self.reader.get_flow(id))
            .map(|entry| FlowPy {
                archive: Arc::clone(&self.reader),
                entry: *entry,
            })
            .collect()
    }

    /// Find flows matching a protocol: "tcp", "udp", or "icmp".
    fn find_by_protocol(&self, proto_str: &str) -> PyResult<Vec<FlowPy>> {
        let proto_num = match proto_str.to_lowercase().as_str() {
            "tcp" => 6u8,
            "udp" => 17,
            "icmp" => 1,
            "icmpv6" => 58,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown protocol: {}. Valid: tcp, udp, icmp, icmpv6",
                    other
                )));
            }
        };
        let ids = self.reader.find_by_protocol(proto_num);
        Ok(ids
            .into_iter()
            .filter_map(|id| self.reader.get_flow(id))
            .map(|entry| FlowPy {
                archive: Arc::clone(&self.reader),
                entry: *entry,
            })
            .collect())
    }

    fn __repr__(&self) -> String {
        format!(
            "Archive(flows={}, link_type={})",
            self.flow_count(),
            self.link_type()
        )
    }

    fn __len__(&self) -> usize {
        self.flow_count()
    }
}

impl Drop for ArchivePy {
    fn drop(&mut self) {
        if let Some(ref path) = self._temp_file {
            let _ = std::fs::remove_file(path);
        }
    }
}

// ── Top-level functions ───────────────────────────────────────────────

/// Create a .rsplit archive from a pcap/pcapng file.
#[pyfunction]
#[pyo3(signature = (input_path, output_path, strategy = "session", max_sessions = 10000, ip_filters = vec![], port_filters = vec![]))]
fn create_archive(
    input_path: &str,
    output_path: &str,
    strategy: &str,
    max_sessions: u32,
    ip_filters: Vec<String>,
    port_filters: Vec<u16>,
) -> PyResult<()> {
    let group = cli::parse_strategy(strategy)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    let data = read_input_bytes(input_path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;

    let mut reader =
        open_reader(data).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
    let link_type = reader.link_type();
    let mut flow_mgr = FlowManager::new(&group, max_sessions);
    let filter = build_filter(&ip_filters, &port_filters);
    let mut writer = ArchiveWriter::create(output_path, link_type, true)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;

    while let Some(packet) = reader
        .next_packet()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?
    {
        if !filter.matches(&packet) {
            continue;
        }
        let keys = flow_mgr.classify(&packet);
        for key in &keys {
            writer
                .write_packet(key, &packet)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        }
    }

    writer
        .finalize()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

    Ok(())
}

/// Split a pcap/pcapng file into per-flow pcap or L7 files.
#[pyfunction]
#[pyo3(signature = (input_path, output_dir, strategy = "session", max_sessions = 10000, buffer_bytes = 10000, ip_filters = vec![], port_filters = vec![], output_type = "pcap"))]
fn split(
    input_path: &str,
    output_dir: &str,
    strategy: &str,
    max_sessions: u32,
    buffer_bytes: usize,
    ip_filters: Vec<String>,
    port_filters: Vec<u16>,
    output_type: &str,
) -> PyResult<()> {
    let group = cli::parse_strategy(strategy)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    let output_mode = match output_type.to_lowercase().as_str() {
        "pcap" => OutputMode::Pcap,
        "l7" => OutputMode::L7,
        other => return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Unknown output_type: {}. Valid: pcap, l7", other)
        )),
    };

    let data = read_input_bytes(input_path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;

    let mut reader =
        open_reader(data).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
    let link_type = reader.link_type();
    let filter = build_filter(&ip_filters, &port_filters);

    let out_dir = PathBuf::from(output_dir);
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;

    // Use crossbeam channel for pipelined processing
    let (tx, rx) =
        crossbeam_channel::bounded::<Result<RsPacket, crate::parser::ParseError>>(4096);

    let producer = std::thread::spawn(move || -> Result<(), crate::parser::ParseError> {
        while let Some(packet) = reader.next_packet()? {
            if tx.send(Ok(packet)).is_err() {
                break;
            }
        }
        Ok(())
    });

    let input_stem = PathBuf::from(input_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut flow_mgr = FlowManager::new(&group, max_sessions);
    let mut split_writer = SplitWriter::new(
        out_dir,
        Some(input_stem),
        link_type,
        output_mode,
        buffer_bytes,
        max_sessions,
    )
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

    for result in rx {
        let packet =
            result.map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        if !filter.matches(&packet) {
            continue;
        }
        let keys = flow_mgr.classify(&packet);
        for key in &keys {
            flow_mgr.add_packet(key, &packet);
            split_writer
                .write_packet_for_key(key, &packet)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        }
    }

    match producer.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)));
        }
        Err(_) => {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Producer thread panicked",
            ));
        }
    }

    split_writer
        .close()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

    Ok(())
}

/// Yield each flow from a .rsplit archive as a complete pcap file (bytes).
/// Returns a list of bytes; each bytes object is a standalone pcap file.
#[pyfunction]
fn pipe_archive(archive_path: &str) -> PyResult<Vec<PyObject>> {
    Python::with_gil(|py| {
        let reader = ArchiveReader::open(&PathBuf::from(archive_path))
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;
        let link_type = reader.link_type();

        let mut results = Vec::with_capacity(reader.list_flows().len());
        for entry in reader.list_flows() {
            let offsets = reader
                .get_packet_offsets(entry)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;

            // Build complete pcap in memory
            let mut pcap = Vec::with_capacity(24 + offsets.len() * 1500);

            // PCAP global header
            pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
            pcap.extend_from_slice(&2u16.to_le_bytes());
            pcap.extend_from_slice(&4u16.to_le_bytes());
            pcap.extend_from_slice(&0i32.to_le_bytes());
            pcap.extend_from_slice(&0u32.to_le_bytes());
            pcap.extend_from_slice(&65535u32.to_le_bytes());
            pcap.extend_from_slice(&link_type.to_le_bytes());

            for &offset in &offsets {
                if let Some(frame) = reader.read_frame_bytes(offset) {
                    pcap.extend_from_slice(frame);
                }
            }

            results.push(PyBytes::new(py, &pcap).into());
        }
        Ok(results)
    })
}

/// Directly read a pcap/pcapng file and return all flows as an Archive.
///
/// Internally creates a temporary .rsplit archive, opens it, and returns
/// the Archive. The temp file is cleaned up when the Archive is garbage collected.
#[pyfunction]
#[pyo3(signature = (input_path, strategy = "session", max_sessions = 10000, ip_filters = vec![], port_filters = vec![]))]
fn read_flows(
    input_path: &str,
    strategy: &str,
    max_sessions: u32,
    ip_filters: Vec<String>,
    port_filters: Vec<u16>,
) -> PyResult<ArchivePy> {
    let tmp_path = make_temp_archive_path();
    create_archive(input_path, &tmp_path, strategy, max_sessions, ip_filters, port_filters)?;
    let reader = ArchiveReader::open(&PathBuf::from(&tmp_path))
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;
    Ok(ArchivePy {
        reader: Arc::new(reader),
        _temp_file: Some(tmp_path),
    })
}

// ── Module definition ─────────────────────────────────────────────────

#[pymodule]
fn rsplitcap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ArchivePy>()?;
    m.add_class::<FlowPy>()?;
    m.add_class::<PacketPy>()?;
    m.add_function(wrap_pyfunction!(create_archive, m)?)?;
    m.add_function(wrap_pyfunction!(split, m)?)?;
    m.add_function(wrap_pyfunction!(pipe_archive, m)?)?;
    m.add_function(wrap_pyfunction!(read_flows, m)?)?;
    Ok(())
}
