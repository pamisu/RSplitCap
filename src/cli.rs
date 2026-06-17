//! CLI argument parsing.
//!
//! We preprocess raw args to normalize SplitCap-compatible multi-char short flags
//! (e.g., `-ip`, `-port`, `-recursive`) into clap-compatible long flags.

use clap::Parser;

/// RSplitCap — A fast PCAP/PCAP-NG splitter with archive capabilities.
#[derive(Parser, Debug)]
#[command(name = "rsplitcap", version, about)]
pub struct Cli {
    /// Input pcap/pcapng file, "-" for stdin
    #[arg(short = 'r', default_value = "-")]
    pub input_file: String,

    /// Output directory
    #[arg(short = 'o', default_value = ".")]
    pub output_dir: String,

    /// Clean output directory before processing
    #[arg(short = 'd')]
    pub clean_output: bool,

    /// Max concurrent sessions in memory (default: 10000)
    #[arg(short = 'p', default_value = "10000")]
    pub max_sessions: u32,

    /// Output file buffer size in bytes (default: 10000)
    #[arg(short = 'b', default_value = "10000")]
    pub buffer_bytes: usize,

    /// Grouping strategy
    #[arg(short = 's', default_value = "session")]
    pub group_strategy: String, // Parsed manually later

    /// IP address filter (can repeat). Use -ip or --ip
    #[arg(long = "ip", value_name = "IP_ADDRESS")]
    pub ip_filters: Vec<String>,

    /// Port filter (can repeat). Use -port or --port
    #[arg(long = "port", value_name = "PORT_NUMBER")]
    pub port_filters: Vec<u16>,

    /// Output file type: pcap or L7
    #[arg(short = 'y', default_value = "pcap")]
    pub output_type: String,

    /// Recursively process directories
    #[arg(long = "recursive", default_value = "false")]
    pub recursive: bool,

    // ── Extended options ──

    /// Operating mode: split / archive / extract
    #[arg(long = "mode", default_value = "split")]
    pub mode: String,

    /// Archive file path (for archive/extract modes)
    #[arg(long = "archive", value_name = "FILE")]
    pub archive_file: Option<String>,

    /// List all flows in archive
    #[arg(long = "list-flows")]
    pub list_flows: bool,

    /// Extract flow by ID
    #[arg(long = "extract", value_name = "FLOW_ID")]
    pub extract_flow: Option<u64>,

    /// Extract: filter flows by IP (can repeat)
    #[arg(long = "filter-ip", value_name = "IP")]
    pub filter_ip: Vec<String>,

    /// Extract: filter flows by port (can repeat)
    #[arg(long = "filter-port", value_name = "PORT")]
    pub filter_port: Vec<u16>,

    /// Extract: filter flows by protocol (tcp/udp/icmp)
    #[arg(long = "filter-proto", value_name = "PROTO")]
    pub filter_proto: Option<String>,

    /// Skip generating secondary index in archive
    #[arg(long = "no-secondary-index")]
    pub no_secondary_index: bool,

    /// Number of worker threads (default: CPU cores)
    #[arg(long = "threads", value_name = "NUM")]
    pub threads: Option<usize>,

    /// Disable memory mapping
    #[arg(long = "no-mmap")]
    pub no_mmap: bool,

    /// Disable pipelined streaming output (fall back to accumulate-then-write)
    #[arg(long = "no-pipeline")]
    pub no_pipeline: bool,

    /// Pipe mode: output each flow to stdout as length-prefixed pcap
    #[arg(long = "pipe")]
    pub pipe: bool,

    /// Verbose output
    #[arg(long = "verbose", short = 'v')]
    pub verbose: bool,
}

/// Grouping strategy argument.
#[derive(Debug, Clone)]
pub enum GroupArg {
    Session,
    Flow,
    Host,
    Hostpair,
    Mac,
    Bssid,
    Nosplit,
    Seconds(u32),
    Packets(u32),
}

/// Output type.
#[derive(Debug, Clone, Copy)]
pub enum OutputType {
    Pcap,
    L7,
}

/// Operating mode.
#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Split,
    Archive,
    Extract,
}

/// Normalize SplitCap-compatible multi-char flags to clap long flags.
/// Examples: `-ip 1.2.3.4` → `--ip 1.2.3.4`, `-port 80` → `--port 80`
pub fn normalize_args(raw: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(raw.len());
    let args: Vec<&str> = raw.iter().map(|s| s.as_str()).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-ip" => {
                out.push("--ip".into());
            }
            "-port" => {
                out.push("--port".into());
            }
            "-recursive" => {
                out.push("--recursive".into());
                out.push("true".into());
            }
            a if a.starts_with("-ip=") => {
                out.push(format!("--ip={}", &a[4..]));
            }
            a if a.starts_with("-port=") => {
                out.push(format!("--port={}", &a[5..]));
            }
            other => {
                out.push(other.to_string());
            }
        }
        i += 1;
    }
    out
}

/// Parse the -s argument including its optional sub-value.
/// Clap doesn't handle `-s seconds 3600` natively, so we parse raw args.
pub fn parse_s_group(raw: &[String]) -> (GroupArg, Vec<String>) {
    let mut i = 0;
    let mut strategy: Option<GroupArg> = None;
    let mut remaining: Vec<String> = Vec::new();

    while i < raw.len() {
        let arg = &raw[i];
        if arg == "-s" && i + 1 < raw.len() {
            i += 1;
            let val = &raw[i];
            match val.to_lowercase().as_str() {
                "seconds" if i + 1 < raw.len() => {
                    i += 1;
                    if let Ok(n) = raw[i].parse::<u32>() {
                        strategy = Some(GroupArg::Seconds(n));
                    }
                }
                "packets" if i + 1 < raw.len() => {
                    i += 1;
                    if let Ok(n) = raw[i].parse::<u32>() {
                        strategy = Some(GroupArg::Packets(n));
                    }
                }
                other => {
                    if let Ok(g) = parse_strategy(other) {
                        strategy = Some(g);
                    }
                }
            }
        } else {
            remaining.push(arg.clone());
        }
        i += 1;
    }

    (strategy.unwrap_or(GroupArg::Session), remaining)
}

pub fn parse_strategy(s: &str) -> Result<GroupArg, String> {
    match s.to_lowercase().as_str() {
        "session" => Ok(GroupArg::Session),
        "flow" => Ok(GroupArg::Flow),
        "host" => Ok(GroupArg::Host),
        "hostpair" => Ok(GroupArg::Hostpair),
        "mac" => Ok(GroupArg::Mac),
        "bssid" => Ok(GroupArg::Bssid),
        "nosplit" => Ok(GroupArg::Nosplit),
        _ => Err(format!("Unknown strategy: {}", s)),
    }
}

pub fn parse_output_type(s: &str) -> Result<OutputType, String> {
    match s.to_lowercase().as_str() {
        "pcap" => Ok(OutputType::Pcap),
        "l7" => Ok(OutputType::L7),
        _ => Err(format!("Unknown output type: {}. Valid values: pcap, L7", s)),
    }
}

pub fn parse_mode(s: &str) -> Result<Mode, String> {
    match s.to_lowercase().as_str() {
        "split" => Ok(Mode::Split),
        "archive" => Ok(Mode::Archive),
        "extract" => Ok(Mode::Extract),
        _ => Err(format!("Unknown mode: {}. Valid values: split, archive, extract", s)),
    }
}
