# CLAUDE.md — RSplitCap project guide for Claude Code

## Project Overview
RSplitCap is a Rust rewrite of SplitCap (Windows PCAP splitting tool), with added support for PCAP-NG and a custom single-file archive format (`.rsplit`).

## Build & Test Commands
```bash
cargo build                    # Debug build
cargo build --release          # Release build (LTO, single codegen unit)
cargo test                     # Run all tests (12 tests: 6 integration + 6 fuzz/robustness)
cargo clippy -- -D warnings    # Lint
RUST_LOG=debug cargo run -- <args>  # Verbose run
```

## Architecture (layered)
1. **CLI** (`src/cli.rs`) — clap-based, normalizes SplitCap multi-char flags (`-ip`→`--ip`)
2. **Parser** (`src/parser/`) — `CaptureReader` trait, PCAP + PCAP-NG (SHB/IDB/EPB/SPB)
3. **Filter** (`src/filter.rs`) — IP + port AND-logic whitelist
4. **Flow Manager** (`src/flow/`) — grouping strategies, LRU eviction via generation counter
5. **Output** — Split mode (per-flow PCAP/L7), Archive mode (`.rsplit` with secondary indexes)

## Key Design Decisions
- Entire input loaded into `Bytes` (zero-copy). TODO: streaming I/O for >memory files.
- Archive uses 2-phase write: sequential packets → post-positioned indexes (Delta+LEB128).
- FlowEntry is fixed 96 bytes — enables O(1) random access in Flow Table.
- IP addresses stored as 16 bytes (IPv4-mapped IPv6) for uniform handling.
- `-s seconds N` and `-s packets N` use the `-s` flag with a sub-argument — manually parsed.
- Secondary indexes: sorted key→[flow_id] maps for IP/port/protocol in archive (binary-searchable).
- All file writes use atomic temp-file + rename pattern to prevent corruption on interrupt.

## Module Map
```
main.rs ── cli ── filter ── flow (strategy + manager) ── output (split + mod)
         ── parser (pcap + pcapng)                       ── archive (writer + reader + format)
```

## Known Gaps
- BSSID strategy returns empty (no WiFi frame parser yet)
- No streaming file I/O (memory-maps or loads entire file into Bytes)
- PCAP-NG: limited to single interface, no name resolution blocks, no extension headers for IPv6
- Pipeline concurrency not implemented (crossbeam-channel dependency available but unused)
- LRU eviction is O(n) per eviction; could use a linked hash map for O(1)

## Test Coverage
- `tests/integration.rs`: 6 tests (split, filter, L7, PCAP-NG, archive roundtrip, list-flows)
- `tests/fuzz_parsers.rs`: 6 tests (random data PCAP/PCAP-NG parsers, malformed packets, LEB128 codec, FlowEntry roundtrip, corrupt archive rejection)
