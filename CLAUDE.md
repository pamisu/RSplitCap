# CLAUDE.md — RSplitCap project guide for Claude Code

## Project Overview
RSplitCap is a Rust rewrite of SplitCap (Windows PCAP splitting tool), with PCAP-NG support, a custom `.rsplit` single-file archive format, Python bindings (PyO3), and CLI pipe streaming.

## Build & Test
```bash
cargo build                    # Debug build
cargo build --release          # Release build (LTO, single codegen unit)
cargo test                     # 16 tests: 6 integration + 10 fuzz/robustness

# Python bindings
cargo build --release --features python  # requires -L <libpython dir>
maturin develop --release                 # build+install into venv

# Cross-compile Windows (from Linux, requires mingw-w64)
cargo build --release --target x86_64-pc-windows-gnu
```

## Architecture
```
src/
├── main.rs              # Entry point, mode dispatch (split/archive/extract/pipe)
├── cli.rs               # CLI parsing (clap), SplitCap flag normalization
├── packet.rs            # Packet & FiveTuple, Ethernet/IPv4/IPv6/WiFi parsing
├── filter.rs            # IP + port AND-logic whitelist
├── parser/
│   ├── mod.rs, pcap.rs, pcapng.rs   # CaptureReader trait, PCAP/PCAP-NG readers
├── flow/
│   ├── mod.rs, strategy.rs          # FlowManager (LRU), 9 grouping strategies
├── output/
│   ├── mod.rs, split.rs             # PCAP/L7 output, SplitWriter (streaming)
├── archive/
│   ├── mod.rs, writer.rs, reader.rs # .rsplit format, Delta+LEB128, secondary indexes
└── python/
    └── mod.rs           # PyO3 bindings (cfg-gated with --features python)
tests/
├── integration.rs       # 6 end-to-end tests
└── fuzz_parsers.rs      # 10 fuzz/robustness tests
bench/                   # Python benchmark suite
python/
├── rsplit_pipe_reader.py     # CLI --pipe mode stdin reader
└── rsplitcap/
    ├── __init__.py, __init__.pyi   # Python package entry + type stubs
```

## Key Design Decisions
- Input files mmap'd via `memmap2` + `Bytes::from_owner` (zero-copy, OS-paged).
- Split mode: pipelined streaming via crossbeam bounded channel (parser thread → main).
- Archive: 2-phase write (sequential packets → post-positioned Delta+LEB128 indexes).
- FlowEntry: fixed 96 bytes for O(1) random access in Flow Table.
- IP addresses: 16-byte IPv4-mapped IPv6 uniform representation.
- File writes: atomic temp-file + rename pattern.
- Tracing: writes to stderr so stdout stays clean for `--pipe` mode.
- Python bindings: cfg-gated (`--features python`), `extension-module` for manylinux.

## Python Bindings (`src/python/mod.rs`)
- **ArchivePy**: wraps `ArchiveReader`, `open()`, `flows()`, `find_by_*()`, `get_flow()`
- **FlowPy**: holds `Arc<ArchiveReader>` + `FlowEntry`, metadata + `packets()` → list[Packet]
- **PacketPy**: `ts`, `data` (bytes), `length`, `orig_len`
- **read_flows(path)**: pcap → temp .rsplit → Archive (temp auto-cleaned on Drop)
- **create_archive/split/pipe_archive**: correspond to CLI modes

## CI/CD (GitHub Actions)
- Push → `cargo test`
- Release → build CLI binaries (Linux x86_64, macOS ARM64, Windows x86_64) + Python wheels (3 platforms) → attach to release + publish to PyPI
- PyPI secret: `PYPI_API_TOKEN`

## Known Gaps
- LRU eviction O(n) per eviction (fine for default 10k max_sessions)
- PCAP-NG: single interface, no name resolution blocks
- No WiFi data-frame IP parsing over LLC/SNAP
- No compression in archive
- Python bindings: `--no-secondary-index` not exposed, packets() copies data (no zero-copy)
