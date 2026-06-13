# CLAUDE.md — RSplitCap project guide for Claude Code

## Project Overview
RSplitCap is a Rust rewrite of SplitCap (Windows PCAP splitting tool), with added support for PCAP-NG and a custom single-file archive format (`.rsplit`).

## Build & Test Commands
```bash
cargo build                    # Debug build
cargo build --release          # Release build (LTO, single codegen unit)
cargo test                     # Run all tests (16 tests: 6 integration + 10 fuzz/robustness)
cargo clippy -- -D warnings    # Lint (zero warnings enforced)
RUST_LOG=debug cargo run -- <args>  # Verbose run

# Windows cross-compile (from Linux/WSL2, requires mingw-w64)
rustup target add x86_64-pc-windows-gnu
# Install mingw-w64, then:
cargo build --release --target x86_64-pc-windows-gnu

# Benchmark (requires Python 3.8+, matplotlib optional)
python bench/bench_rsplitcap.py --data-dir <path_to_pcaps> \
    --rsplitcap ./target/release/rsplitcap \
    --splitcap ./path/to/SplitCap.exe \
    --output ./bench_report
```

## Benchmark Script (`bench/bench_rsplitcap.py`)
- **Shared tests**: 6 grouping strategies × up to 3 files, IP/port filter tests, L7 output — RSplitCap vs SplitCap
- **RSplitCap-unique tests**: BSSID strategy, archive create/extract, pipeline vs legacy, mmap vs no-mmap
- **Metrics**: wall time, CPU time, peak RSS (via `/usr/bin/time -v`), output file count/size, packet count
- **Output**: `report.html` (interactive charts with matplotlib) + `report.json` (machine-readable)
- **Key options**: `--quick` (1+1 runs), `--max-files N`, `--no-splitcap`, `--skip-*`, `--timeout N`
- On WSL2, SplitCap paths are auto-converted via `wslpath -w`; wine fallback if no WSL interop

## Architecture (layered)
1. **CLI** (`src/cli.rs`) — clap-based, normalizes SplitCap multi-char flags (`-ip`→`--ip`)
2. **Parser** (`src/parser/`) — `CaptureReader` trait, PCAP + PCAP-NG (SHB/IDB/EPB/SPB)
3. **Packet** (`src/packet.rs`) — unified Packet struct, Ethernet/IPv4/IPv6 parsing, WiFi 802.11 + radiotap
4. **Filter** (`src/filter.rs`) — IP + port AND-logic whitelist
5. **Flow Manager** (`src/flow/`) — 9 grouping strategies, LRU eviction via generation counter
6. **Output** — Split mode (per-flow PCAP/L7), Archive mode (`.rsplit` with secondary indexes)

## Key Design Decisions
- Input files are mmap'd via `memmap2` + `Bytes::from_owner` — zero-copy, OS-managed paging for >memory files.
- Split mode uses pipelined streaming: parser in background thread (crossbeam bounded channel) → classify + write in main thread via `SplitWriter`. Packets written as they arrive, not accumulated.
- Archive uses 2-phase write: sequential packets → post-positioned indexes (Delta+LEB128).
- FlowEntry is fixed 96 bytes — enables O(1) random access in Flow Table.
- IP addresses stored as 16 bytes (IPv4-mapped IPv6) for uniform handling.
- `-s seconds N` and `-s packets N` use the `-s` flag with a sub-argument — manually parsed.
- Secondary indexes: sorted key→[flow_id] maps for IP/port/protocol in archive (binary-searchable).
- All file writes use atomic temp-file + rename pattern to prevent corruption on interrupt.
- `--no-pipeline` flag falls back to legacy accumulate-then-write mode.

## Module Map
```
main.rs ── cli ── filter ── flow (strategy + manager) ── output (split + mod)
         ── parser (pcap + pcapng)                       ── archive (writer + reader + format)
         ── packet (ethernet, ipv4, ipv6 ext hdrs, wifi 802.11 + radiotap)
```

## Known Gaps
- LRU eviction is O(n) per eviction (fast in practice for default 10k max_sessions)
- PCAP-NG: single interface only, no name resolution blocks
- No WiFi data-frame IP parsing over LLC/SNAP (BSSID/mac extraction works; five-tuple returns None)
- **Windows performance**: Cross-compiled `x86_64-pc-windows-gnu` binary is ~8× slower than Linux native. MSVC native build should restore full performance but has not been benchmarked yet. SplitCap runs 7.6× faster natively on Windows than via WSL2/Wine.

## Test Coverage
- `tests/integration.rs`: 6 tests (split, filter, L7, PCAP-NG, archive roundtrip, list-flows)
- `tests/fuzz_parsers.rs`: 10 tests (random data PCAP/PCAP-NG parsers, malformed packets, LEB128 codec, FlowEntry roundtrip, corrupt archive rejection, WiFi radiotap/management BSSID, WiFi malformed, IPv6 extension header chain)
