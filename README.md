# RSplitCap

[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fast PCAP/PCAP-NG splitter with custom archive capabilities, written in Rust.  
**100% CLI-compatible with the original [SplitCap](https://www.netresec.com/?page=SplitCap).**

## Why RSplitCap?

SplitCap is a classic Windows tool for splitting PCAP files by session, IP, port, or time.  
RSplitCap reimagines it with:

- **Native PCAP-NG support** — no need for `editcap` conversion
- **Single-file archive format (`.rsplit`)** — all flows in one file with fast indexed extraction
- **Zero-copy & mmap** — handles 100GB+ files with bounded memory (~200MB)
- **Cross-platform** — Linux, macOS, Windows, no Mono/.NET runtime needed
- **Memory safety** — Rust's ownership model eliminates buffer overflows and use-after-free

## Quick Start

```bash
# Build from source (requires Rust 1.95+)
cargo build --release

# Split a PCAP file by session (default)
./target/release/rsplitcap -r capture.pcap -s session -o output/

# Split by IP host (each IP gets its own file)
./target/release/rsplitcap -r capture.pcap -s host -o per_ip/

# Filter by IP and port, output single file
./target/release/rsplitcap -r capture.pcap -ip 10.0.0.1 -port 80 -port 443 -s nosplit

# Time-based splitting (every 3600 seconds = 1 hour)
./target/release/rsplitcap -r capture.pcap -s seconds 3600 -o hourly/

# Read from pipe
tcpdump -i eth0 -w - | ./target/release/rsplitcap -r - -s session -o live_output/

# PCAP-NG native support
./target/release/rsplitcap -r capture.pcapng -s session -o output/
```

## Archive Mode (`.rsplit`)

The custom `.rsplit` format stores all flows in a single file with an embedded index, enabling fast extraction without splitting into hundreds of files.

```bash
# Create archive from a PCAP/PCAP-NG file
./target/release/rsplitcap -r large.pcapng --mode archive --archive out.rsplit -s session

# List all flows in the archive
./target/release/rsplitcap --mode extract --archive out.rsplit --list-flows

# Extract a specific flow by ID
./target/release/rsplitcap --mode extract --archive out.rsplit --extract 123 -o flow_123.pcap

# Extract all flows matching a port
./target/release/rsplitcap --mode extract --archive out.rsplit --filter-port 443 -o https_flows/

# Extract by IP + port combination
./target/release/rsplitcap --mode extract --archive out.rsplit --filter-ip 192.168.1.100 --filter-port 80 -o result/
```

### Archive Format Design

```
┌─────────────────────┐  ← offset 0
│   File Header (64B) │  Magic, version, link type
├─────────────────────┤
│   Packet Region     │  All packets in PCAP frame format (sequential write)
├─────────────────────┤
│ Flow Packet Region  │  Per-flow offset lists (Delta + LEB128 compressed)
├─────────────────────┤
│   Flow Table        │  Fixed-length entries (96B each): 5-tuple, stats, index pointers
├─────────────────────┤
│   File Footer (128B)│  Pointers to all regions, flow count
└─────────────────────┘  ← end of file
```

Key properties:
- **Stream-friendly**: packets written sequentially, no random I/O during creation
- **Memory-efficient**: only flow metadata in RAM, not packet contents
- **Fast extraction**: mmap + direct offset lookup, zero-copy
- **Compact index**: Delta + LEB128 encoding reduces index size by ~75%

## CLI Reference

### SplitCap-Compatible Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r <file>` | Input PCAP/PCAP-NG file, `-` for stdin | `-` |
| `-o <dir>` | Output directory | `.` |
| `-d` | Clean output directory before processing | off |
| `-p <n>` | Max concurrent flows in memory | `10000` |
| `-b <n>` | Output file buffer size (bytes) | `10000` |
| `-s <strategy>` | Grouping strategy (see below) | `session` |
| `-ip <addr>` | IP address filter (repeatable) | none |
| `-port <n>` | Port filter (repeatable) | none |
| `-y <type>` | Output type: `pcap` or `L7` | `pcap` |
| `-recursive` | Recursively process directories | off |

### Grouping Strategies (`-s`)

| Strategy | Description |
|----------|-------------|
| `session` | Bidirectional flow (sorted 5-tuple) — **default** |
| `flow` | Unidirectional 5-tuple |
| `host` | Per IP address (packets go to both src & dst files) |
| `hostpair` | Per communicating IP pair |
| `mac` | Per MAC address |
| `bssid` | Per WiFi BSSID |
| `nosplit` | Single output file (filter only) |
| `seconds <n>` | Time-based buckets of n seconds |
| `packets <n>` | Packet-count-based buckets |

### Extended Options

| Flag | Description |
|------|-------------|
| `--mode <m>` | `split` (default), `archive`, or `extract` |
| `--archive <f>` | Archive file path |
| `--list-flows` | List all flows in archive |
| `--extract <id>` | Extract flow by ID |
| `--filter-ip <ip>` | Extract: filter by IP |
| `--filter-port <p>` | Extract: filter by port |
| `--filter-proto <p>` | Extract: filter by protocol (`tcp`/`udp`/`icmp`) |
| `--no-secondary-index` | Skip secondary index generation |
| `--threads <n>` | Worker thread count (for future multi-threaded classification) |
| `--no-mmap` | Disable memory mapping |
| `--no-pipeline` | Use legacy accumulate-then-write mode |
| `-v, --verbose` | Verbose logging |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  CLI Layer (clap)                │
│     SplitCap-compatible args + extended opts     │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              Parser Layer                        │
│  ┌──────────┐  ┌───────────┐  ┌──────────────┐ │
│  │  PCAP    │  │  PCAP-NG  │  │  CaptureReader│ │
│  │  Reader  │  │  Reader   │  │  (trait)      │ │
│  └──────────┘  └───────────┘  └──────────────┘ │
│         ↓              ↓              ↓         │
│      mmap + Bytes::from_owner (zero-copy)       │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│         Packet Parsing (packet.rs)               │
│  Ethernet | IPv4 | IPv6 ext hdrs | 802.11+radio │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              Filter (IP + Port AND logic)        │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│         Flow Manager + Group Strategies          │
│  session | flow | host | hostpair | mac | bssid │
│  nosplit | seconds N | packets N                │
│  LRU eviction                                   │
└────────┬───────────────────────┬────────────────┘
         │                       │
┌────────▼────────┐   ┌──────────▼──────────────┐
│  Split Output   │   │  Archive Output (.rsplit)│
│  - PCAP files   │   │  - Stream writer         │
│  - L7 payloads  │   │  - Delta+LEB128 index    │
│  - Per-flow     │   │  - Secondary indexes     │
│  (atomic rename)│   │  - Post-positioned footer│
└─────────────────┘   └─────────────────────────┘
```

## Project Structure

```
src/
├── main.rs              # Entry point, mode dispatch
├── cli.rs               # CLI argument parsing + SplitCap compat
├── packet.rs            # Packet & FiveTuple types, Ethernet/IPv4/IPv6 ext hdrs/WiFi 802.11 + radiotap
├── filter.rs            # IP/port filter logic
├── parser/
│   ├── mod.rs           # CaptureReader trait, format auto-detect
│   ├── pcap.rs          # PCAP format reader
│   └── pcapng.rs        # PCAP-NG format reader (SHB/IDB/EPB/SPB)
├── flow/
│   ├── mod.rs           # FlowManager with LRU eviction
│   └── strategy.rs      # 9 grouping strategies
├── output/
│   ├── mod.rs           # PCAP header writer, L7 output helpers
│   └── split.rs         # Buffered per-flow PCAP writer
└── archive/
    ├── mod.rs           # .rsplit format types, LEB128 codec, secondary indexes
    ├── writer.rs        # Archive stream writer (2-phase)
    └── reader.rs        # Archive reader (mmap, extraction with index lookup)
```

## Build & Test

```bash
# Build (Linux/macOS)
cargo build --release

# Build (Windows — MSVC toolchain recommended)
cargo build --release

# Run tests
cargo test

# Run benchmarks
python bench/bench_rsplitcap.py --data-dir <path_to_pcaps> \
    --rsplitcap ./target/release/rsplitcap \
    --splitcap ./path/to/SplitCap.exe \
    --output ./bench_report
```

## Benchmarks

Comprehensive benchmarks comparing RSplitCap with the original SplitCap (via Wine on Linux, native on Windows), using the [USTC-TFC2016](https://github.com/yungshenglu/USTC-TFC2016) dataset (20 PCAPs, 2.5MB–288MB, benign + malware traffic).

### Linux (WSL2, RSplitCap native vs SplitCap via Wine)

| Strategy | RSplitCap | SplitCap (Wine) | Speedup |
|----------|-----------|-----------------|---------|
| session | 0.30s | 9.54s | **31.8×** |
| flow | 0.29s | 9.27s | **32.0×** |
| host | 0.52s | 17.01s | **32.6×** |
| hostpair | 0.31s | 9.43s | **30.4×** |
| L7 | 0.30s | 18.42s | **61.5×** |
| **Geometric mean** | | | **121.3×** |

> RSplitCap: 88/88 passed. SplitCap: 52/52 passed. 6 files, 44 scenarios, 264 total runs.

### Windows 11 (both native)

| Strategy | RSplitCap (mingw) | SplitCap (native) | Winner |
|----------|-------------------|-------------------|--------|
| session | 2.32s | 1.39s | SplitCap 1.7× |
| flow | 2.31s | 1.50s | SplitCap 1.5× |
| mac | 0.03s | 0.17s | **RSplitCap 5.6×** |
| nosplit | 0.02s | 0.16s | **RSplitCap 7.9×** |

> Note: Windows RSplitCap was cross-compiled with `x86_64-pc-windows-gnu` (mingw). Native MSVC compilation should restore the 30×+ advantage seen on Linux.

### RSplitCap Unique Features (Linux)

| Feature | Performance |
|---------|-------------|
| Pipeline vs Legacy | Small files: legacy ~1.5× faster; Large files: pipeline faster |
| mmap vs no-mmap | Small files: ~same; Files >100MB: mmap advantage |
| Archive creation | 0.01–0.02s (2.5MB input → 3.4MB .rsplit) |
| Archive with index | Same speed as without index |

## Compatibility

RSplitCap aims for 100% CLI compatibility with [SplitCap](https://www.netresec.com/?page=SplitCap).  
Existing scripts using SplitCap can replace the binary directly:

```bash
# Original SplitCap command
SplitCap -r dump.pcap -s session -o output/

# RSplitCap — identical usage
rsplitcap -r dump.pcap -s session -o output/
```

## Roadmap

- [x] PCAP reader & writer
- [x] PCAP-NG reader (SHB, IDB, EPB, SPB)
- [x] All 9 SplitCap-compatible grouping strategies
- [x] IP/port filtering
- [x] L7 payload extraction
- [x] `.rsplit` archive format (write + read + extract)
- [x] mmap-based archive reading and file input (zero-copy, OS-paged)
- [x] Flow listing and metadata query
- [x] Secondary indexes (IP/port/protocol) with sort+dedup+linear scan
- [x] WiFi 802.11 frame parsing for BSSID strategy (raw + radiotap)
- [x] IPv6 extension header chain traversal
- [x] Pipelined streaming (parser thread + bounded channel + SplitWriter)
- [x] Cross-platform benchmark suite (RSplitCap vs SplitCap, HTML report)
- [x] Windows cross-compilation support (x86_64-pc-windows-gnu)
- [ ] Windows MSVC native build performance validation
- [ ] PCAP-NG WiFi data-packet IP parsing over LLC/SNAP
- [ ] Compression support in archive
- [ ] Python bindings

## License

MIT License. See [LICENSE](LICENSE) for details.
