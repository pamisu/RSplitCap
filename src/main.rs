//! RSplitCap — A fast PCAP/PCAP-NG splitter with archive capabilities.
//!
//! Entry point: parse CLI, set up pipeline, dispatch mode.

#![allow(dead_code, unused_imports)]

mod archive;
mod cli;
mod filter;
mod flow;
mod output;
mod packet;
mod parser;

use crate::cli::{GroupArg, Mode, OutputType};
use crate::filter::Filter;
use crate::flow::FlowManager;
use crate::output::{write_flow_l7, write_flow_pcap, OutputMode, SplitWriter};
use crate::parser::{open_reader, CaptureReader, ParseError};
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use crossbeam_channel as cb;
use memmap2::Mmap;
use std::fs::{self, File};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn main() -> Result<()> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // ── CLI parsing pipeline ──
    // 1. Collect raw args
    let raw_args: Vec<String> = std::env::args().collect();

    // 2. Extract -s group strategy (may consume sub-args like -s seconds 3600)
    let (group_strategy, after_s) = cli::parse_s_group(&raw_args);
    let has_s = raw_args.iter().any(|a| a == "-s");

    // 3. Normalize SplitCap multi-char flags (-ip, -port, -recursive)
    let normalized = cli::normalize_args(&after_s);

    // 4. Parse with clap
    let cli = cli::Cli::parse_from(normalized);

    // 5. Parse string enums
    let group = if has_s {
        group_strategy
    } else {
        cli::parse_strategy(&cli.group_strategy).unwrap_or(GroupArg::Session)
    };
    let output_type = cli::parse_output_type(&cli.output_type).unwrap_or(OutputType::Pcap);
    let mode = cli::parse_mode(&cli.mode).unwrap_or(Mode::Split);

    tracing::info!("RSplitCap — mode: {:?}, strategy: {:?}", mode, group);

    // Collect input files (handles single file, directory, recursive)
    let input_files = collect_input_files(&cli.input_file, cli.recursive)?;
    tracing::info!("Processing {} input file(s)", input_files.len());

    // Dispatch
    match mode {
        Mode::Split => {
            for input_path in &input_files {
                run_split(&cli, &group, output_type, &PathBuf::from(&cli.output_dir), input_path)?;
            }
        }
        Mode::Archive => run_archive(&cli, &group)?,
        Mode::Extract => run_extract(&cli)?,
    }

    Ok(())
}

/// Collect all input files: single file, directory (non-recursive), or recursive directory scan.
fn collect_input_files(input: &str, recursive: bool) -> Result<Vec<PathBuf>> {
    if input == "-" {
        return Ok(vec![PathBuf::from("-")]);
    }
    let path = PathBuf::from(input);
    if path.is_file() {
        return Ok(vec![path]);
    }
    if path.is_dir() {
        let mut files = Vec::new();
        if recursive {
            walk_dir(&path, &mut files)?;
        } else {
            // Non-recursive: only top-level pcap/pcapng files
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_file() && is_pcap_file(&p) {
                    files.push(p);
                }
            }
        }
        files.sort();
        return Ok(files);
    }
    anyhow::bail!("Input not found: {}", input);
}

fn walk_dir(dir: &PathBuf, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, files)?;
        } else if is_pcap_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_pcap_file(path: &Path) -> bool {
    path.extension()
        .map(|e| {
            let s = e.to_str().unwrap_or("");
            s.eq_ignore_ascii_case("pcap")
                || s.eq_ignore_ascii_case("pcapng")
                || s.eq_ignore_ascii_case("cap")
                || s.eq_ignore_ascii_case("ntar")
        })
        .unwrap_or(false)
}

/// ── Split mode ──
fn run_split(
    cli: &cli::Cli,
    group: &GroupArg,
    output_type: OutputType,
    output_dir: &PathBuf,
    input_path: &PathBuf,
) -> Result<()> {
    if cli.no_pipeline {
        return run_split_legacy(cli, group, output_type, output_dir, input_path);
    }
    run_split_pipelined(cli, group, output_type, output_dir, input_path)
}

/// Legacy split mode: accumulate all packets in memory, then write.
fn run_split_legacy(
    cli: &cli::Cli,
    group: &GroupArg,
    output_type: OutputType,
    output_dir: &PathBuf,
    input_path: &PathBuf,
) -> Result<()> {
    // Clean output directory if requested
    if cli.clean_output && output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }

    // Build filter
    let filter = build_filter(cli)?;

    // Read input
    let data = read_input(&input_path.to_string_lossy())?;
    let file_size = data.len();
    tracing::info!("Read {} bytes from {:?}", file_size, input_path);

    let start = Instant::now();

    let mut reader = open_reader(data)?;
    let link_type = reader.link_type();
    let mut flow_mgr = FlowManager::new(group, cli.max_sessions);

    // Collect all packets into flows (phase 1: classification)
    let mut processed = 0u64;
    let mut filtered = 0u64;
    while let Some(packet) = reader.next_packet()? {
        processed += 1;

        if !filter.matches(&packet) {
            filtered += 1;
            continue;
        }

        let keys = flow_mgr.classify(&packet);
        for key in &keys {
            flow_mgr.add_packet(key, &packet);
        }

        if processed.is_multiple_of(1_000_000) {
            tracing::info!(
                "Processed {} packets, {} flows",
                processed,
                flow_mgr.flow_count()
            );
        }
    }

    let classify_elapsed = start.elapsed();
    tracing::info!(
        "Classification complete: {} packets ({} filtered), {} flows in {:?}",
        processed,
        filtered,
        flow_mgr.flow_count(),
        classify_elapsed
    );

    // Phase 2: write output
    match output_type {
        OutputType::Pcap => {
            write_split_pcap(output_dir, flow_mgr.into_flows(), link_type, cli.buffer_bytes)?;
        }
        OutputType::L7 => {
            write_split_l7(output_dir, flow_mgr.into_flows(), cli.buffer_bytes)?;
        }
    }

    let total_elapsed = start.elapsed();
    tracing::info!("Done in {:?}", total_elapsed);

    Ok(())
}

/// Pipelined split mode: parse in background thread, classify + write in main thread.
/// Uses bounded crossbeam channel for backpressure, SplitWriter for streaming output.
fn run_split_pipelined(
    cli: &cli::Cli,
    group: &GroupArg,
    output_type: OutputType,
    output_dir: &PathBuf,
    input_path: &PathBuf,
) -> Result<()> {
    // Clean output directory if requested
    if cli.clean_output && output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(output_dir)?;

    let filter = build_filter(cli)?;
    let output_mode = match output_type {
        OutputType::Pcap => OutputMode::Pcap,
        OutputType::L7 => OutputMode::L7,
    };

    // Read input
    let data = read_input(&input_path.to_string_lossy())?;
    let file_size = data.len();
    tracing::info!("Read {} bytes from {:?}", file_size, input_path);

    let start = Instant::now();

    let mut reader = open_reader(data)?;
    let link_type = reader.link_type();

    // Bounded channel: 4096 packets deep for backpressure
    let (tx, rx) = cb::bounded::<Result<crate::packet::Packet, ParseError>>(4096);

    // ── Producer thread: parse packets ──
    let producer = std::thread::spawn(move || -> Result<(), ParseError> {
        while let Some(packet) = reader.next_packet()? {
            if tx.send(Ok(packet)).is_err() {
                // Receiver dropped (consumer finished early)
                break;
            }
        }
        Ok(())
    });

    // ── Consumer: filter, classify, write via SplitWriter ──
    let mut flow_mgr = FlowManager::new(group, cli.max_sessions);
    let mut split_writer = SplitWriter::new(
        output_dir.clone(),
        link_type,
        output_mode,
        cli.buffer_bytes,
        cli.max_sessions,
    )?;

    let mut processed = 0u64;
    let mut filtered = 0u64;

    for result in rx {
        let packet = result.context("Parse error in producer thread")?;
        processed += 1;

        if !filter.matches(&packet) {
            filtered += 1;
            continue;
        }

        let keys = flow_mgr.classify(&packet);
        for key in &keys {
            // Track flow metadata (for LRU eviction, stats)
            flow_mgr.add_packet(key, &packet);
            // Write packet immediately (streaming output)
            split_writer.write_packet_for_key(key, &packet)?;
        }

        if processed.is_multiple_of(1_000_000) {
            tracing::info!(
                "Processed {} packets, {} flows",
                processed,
                flow_mgr.flow_count()
            );
        }
    }

    // Join producer thread and propagate errors
    match producer.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => anyhow::bail!("Producer thread panicked"),
    }

    let classify_elapsed = start.elapsed();
    tracing::info!(
        "Pipelined processing: {} packets ({} filtered), {} flows in {:?}",
        processed,
        filtered,
        flow_mgr.flow_count(),
        classify_elapsed
    );

    // Finalize all split files with atomic rename
    split_writer.close()?;

    let total_elapsed = start.elapsed();
    tracing::info!("Done in {:?}", total_elapsed);

    Ok(())
}

fn build_filter(cli: &cli::Cli) -> Result<Filter> {
    let mut filter = Filter::new();
    for ip_str in &cli.ip_filters {
        let ip: IpAddr = ip_str.parse().context("Invalid IP filter")?;
        filter.add_ip(ip);
    }
    for &port in &cli.port_filters {
        filter.add_port(port);
    }
    Ok(filter)
}

fn read_input(path: &str) -> Result<Bytes> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read from stdin")?;
        Ok(Bytes::from(buf))
    } else {
        let file = File::open(path).context("Failed to open input file")?;
        // Safety: mmap gives raw access to file bytes. The file could be modified
        // externally while mapped, but for a read-only PCAP processing tool this is
        // acceptable — the OS guarantees consistency for the mapped pages.
        let mmap = unsafe { Mmap::map(&file).context("Failed to mmap input file")? };
        tracing::debug!("Mapped {} bytes from {:?}", mmap.len(), path);
        Ok(Bytes::from_owner(mmap))
    }
}

fn write_split_pcap(
    output_dir: &PathBuf,
    flows: impl IntoIterator<Item = (String, flow::FlowState)>,
    link_type: u32,
    buffer_size: usize,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    for (_key, flow) in flows {
        if flow.packet_count > 0 {
            write_flow_pcap(output_dir, &flow, link_type, buffer_size)?;
        }
    }
    tracing::info!("PCAP output written to {:?}", output_dir);
    Ok(())
}

fn write_split_l7(
    output_dir: &PathBuf,
    flows: impl IntoIterator<Item = (String, flow::FlowState)>,
    buffer_size: usize,
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    for (_key, flow) in flows {
        if flow.packet_count > 0 {
            write_flow_l7(output_dir, &flow, buffer_size)?;
        }
    }
    tracing::info!("L7 output written to {:?}", output_dir);
    Ok(())
}

/// ── Archive mode: stream packets into a single .rsplit file ──
fn run_archive(cli: &cli::Cli, group: &GroupArg) -> Result<()> {
    use crate::archive::writer::ArchiveWriter;
    use std::net::IpAddr;

    let archive_path = cli
        .archive_file
        .as_deref()
        .unwrap_or("output.rsplit");

    // Build filter
    let mut filter = Filter::new();
    for ip_str in &cli.ip_filters {
        let ip: IpAddr = ip_str.parse().context("Invalid IP filter")?;
        filter.add_ip(ip);
    }
    for &port in &cli.port_filters {
        filter.add_port(port);
    }

    // Read input
    let data = read_input(&cli.input_file)?;
    tracing::info!("Read {} bytes from input", data.len());

    let start = Instant::now();
    let mut reader = open_reader(data)?;
    let link_type = reader.link_type();
    let mut flow_mgr = FlowManager::new(group, cli.max_sessions);
    let build_sec = !cli.no_secondary_index;
    let mut writer = ArchiveWriter::create(archive_path, link_type, build_sec)?;

    let mut processed = 0u64;
    let mut filtered = 0u64;
    while let Some(packet) = reader.next_packet()? {
        processed += 1;

        if !filter.matches(&packet) {
            filtered += 1;
            continue;
        }

        let keys = flow_mgr.classify(&packet);
        for key in &keys {
            writer.write_packet(key, &packet)?;
        }

        if processed.is_multiple_of(1_000_000) {
            tracing::info!(
                "Processed {} packets, {} flows",
                processed,
                writer.flow_count()
            );
        }
    }

    tracing::info!(
        "Streaming complete: {} packets ({} filtered), {} flows in {:?}",
        processed,
        filtered,
        writer.flow_count(),
        start.elapsed()
    );

    writer.finalize()?;
    tracing::info!("Archive written to {} in {:?}", archive_path, start.elapsed());
    Ok(())
}

/// ── Extract mode: read .rsplit archive and extract flows ──
fn run_extract(cli: &cli::Cli) -> Result<()> {
    use crate::archive::reader::ArchiveReader;
    use std::net::IpAddr;

    let archive_path = cli.archive_file.as_deref().context("--archive <FILE> is required for extract mode")?;
    let reader = ArchiveReader::open(&PathBuf::from(archive_path))?;

    // List flows
    if cli.list_flows {
        println!("{:<6} {:<6} {:<22} {:<22} {:<8} {:<10} {:<12}",
            "ID", "Proto", "Src IP", "Dst IP", "Packets", "Bytes", "Start Time");
        println!("{}", "-".repeat(90));
        for entry in reader.list_flows() {
            let src = ip_from_bytes(&entry.src_ip);
            let dst = ip_from_bytes(&entry.dst_ip);
            let proto = match entry.protocol {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                _ => "?",
            };
            println!(
                "{:<6} {:<6} {:<22} {:<22} {:<8} {:<10} {:<12}",
                entry.flow_id,
                proto,
                src,
                dst,
                entry.packet_count,
                entry.total_bytes,
                entry.start_ts_us / 1_000_000
            );
        }
        return Ok(());
    }

    // Extract single flow by ID
    if let Some(flow_id) = cli.extract_flow {
        let entry = reader
            .get_flow(flow_id)
            .context(format!("Flow {} not found", flow_id))?;
        let output_path = PathBuf::from(&cli.output_dir);
        if output_path.is_dir() {
            let fname = output_path.join(format!("flow_{}.pcap", flow_id));
            reader.extract_flow_to_file(entry, &fname)?;
            tracing::info!("Extracted flow {} to {:?}", flow_id, fname);
        } else {
            reader.extract_flow_to_file(entry, &output_path)?;
            tracing::info!("Extracted flow {} to {:?}", flow_id, output_path);
        }
        return Ok(());
    }

    // Filter-based extraction
    let mut target_flows: Vec<u64> = Vec::new();

    if !cli.filter_ip.is_empty() {
        for ip_str in &cli.filter_ip {
            let ip: IpAddr = ip_str.parse().context("Invalid filter IP")?;
            let ids = reader.find_by_ip(ip);
            if target_flows.is_empty() {
                target_flows = ids;
            } else {
                target_flows.retain(|id| ids.contains(id));
            }
        }
    }

    if !cli.filter_port.is_empty() {
        for &port in &cli.filter_port {
            let ids = reader.find_by_port(port);
            if target_flows.is_empty() {
                target_flows = ids;
            } else {
                target_flows.retain(|id| ids.contains(id));
            }
        }
    }

    if let Some(ref proto_str) = cli.filter_proto {
        let proto_num = match proto_str.to_lowercase().as_str() {
            "tcp" => 6u8,
            "udp" => 17,
            "icmp" => 1,
            _ => anyhow::bail!("Unknown protocol: {}", proto_str),
        };
        let ids = reader.find_by_protocol(proto_num);
        if target_flows.is_empty() {
            target_flows = ids;
        } else {
            target_flows.retain(|id| ids.contains(id));
        }
    }

    if target_flows.is_empty() {
        anyhow::bail!("No filter specified for extraction. Use --extract, --filter-ip, --filter-port, or --filter-proto.");
    }

    let output_dir = PathBuf::from(&cli.output_dir);
    fs::create_dir_all(&output_dir)?;
    for flow_id in &target_flows {
        if let Some(entry) = reader.get_flow(*flow_id) {
            let fname = output_dir.join(format!("flow_{}.pcap", flow_id));
            reader.extract_flow_to_file(entry, &fname)?;
        }
    }
    tracing::info!(
        "Extracted {} flows to {:?}",
        target_flows.len(),
        output_dir
    );

    Ok(())
}

fn ip_from_bytes(bytes: &[u8; 16]) -> IpAddr {
    // Check if it's an IPv4-mapped IPv6 address
    if bytes[0..10] == [0u8; 10] && bytes[10..12] == [0xff, 0xff] {
        IpAddr::from([bytes[12], bytes[13], bytes[14], bytes[15]])
    } else {
        IpAddr::from(*bytes)
    }
}
