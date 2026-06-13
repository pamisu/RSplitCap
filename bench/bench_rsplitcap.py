#!/usr/bin/env python3
"""
RSplitCap Benchmark Suite
==========================
Comprehensive benchmark comparing RSplitCap with the original SplitCap.
Generates an HTML report with charts for visual performance comparison.

Quick start:
    python bench_rsplitcap.py --data-dir /path/to/pcaps \\
                              --rsplitcap ./target/release/rsplitcap \\
                              --splitcap /path/to/SplitCap.exe \\
                              --output ./benchmark_report

Requirements:
    Python 3.8+, matplotlib (pip install matplotlib), wine (for SplitCap on Linux)

Features tested:
  ─ Shared features (RSplitCap vs SplitCap):
    session, flow, host, hostpair, mac, nosplit grouping strategies
    IP/port filtering, L7 output
  ─ RSplitCap-unique features:
    PCAP-NG support, archive/extract modes, pipelined streaming,
    mmap I/O, BSSID strategy, time/packet-based bucketing,
    secondary indexes
"""

import argparse
import base64
import io
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── Optional matplotlib import ──────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[WARN] matplotlib not available — charts will be skipped.", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

IS_WINDOWS = platform.system() == "Windows"

# Environment variable names for tool paths
ENV_RSPLITCAP = "RSPLITCAP_BIN"
ENV_SPLITCAP = "SPLITCAP_BIN"

# Output filename prefix conventions
STEM_MARKER = "<STEM>_"

# Default max_sessions for benchmarks
DEFAULT_MAX_SESSIONS = 10000
DEFAULT_BUFFER_BYTES = 10000


# ═══════════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BenchResult:
    """Single benchmark run result."""
    test_name: str
    tool: str                          # "rsplitcap" | "splitcap"
    strategy: str
    input_file: str
    file_size_mb: float
    elapsed_sec: float
    cpu_sec: float
    peak_memory_mb: float
    exit_code: int
    output_file_count: int = 0
    output_size_mb: float = 0.0
    packets_processed: int = 0
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)  # additional metadata


@dataclass
class ComparisonPair:
    """Matched pair of RSplitCap and SplitCap results for the same test."""
    test_name: str
    rsplitcap: Optional[BenchResult]
    splitcap: Optional[BenchResult]


# ═══════════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════════

def fmt_mb(n: float) -> str:
    return f"{n:.1f} MB"

def fmt_sec(n: float) -> str:
    if n < 1:
        return f"{n * 1000:.0f} ms"
    elif n < 60:
        return f"{n:.2f}s"
    else:
        return f"{int(n // 60)}m {n % 60:.0f}s"

def fmt_ratio(a: float, b: float) -> str:
    """a relative to b, e.g. '2.5× faster' or '0.8×'"""
    if b == 0:
        return "N/A"
    ratio = b / a  # how many times a is faster than b
    if ratio >= 1.05:
        return f"{ratio:.1f}× faster"
    elif ratio <= 0.95:
        return f"{1 / ratio:.1f}× slower"
    else:
        return "~same"

def file_md5(path: Path) -> str:
    """Return MD5 hex digest of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def sanitize_filename(name: str) -> str:
    """Replace dots and other problematic chars with underscores."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)

def collect_files(
    root: Path, extensions: tuple = (".pcap", ".pcapng", ".cap", ".ntar"), recurse: bool = True
) -> list[Path]:
    """Collect all capture files under root directory."""
    files = []
    if root.is_file():
        return [root]
    iterator = root.rglob if recurse else root.glob
    for ext in extensions:
        files.extend(iterator(f"*{ext}"))
        files.extend(iterator(f"*{ext.upper()}"))
    return sorted(set(files), key=lambda p: p.stat().st_size)


def group_files_by_size_bucket(
    files: list[Path], buckets: list[tuple[float, float, str]]
) -> dict[str, list[Path]]:
    """
    Group files into size buckets.
    buckets: list of (min_mb, max_mb, label), max_mb=0 means no upper bound.
    """
    groups: dict[str, list[Path]] = {label: [] for _, _, label in buckets}
    for f in files:
        size_mb = f.stat().st_size / (1024 * 1024)
        for min_mb, max_mb, label in buckets:
            if size_mb >= min_mb and (max_mb == 0 or size_mb < max_mb):
                groups[label].append(f)
                break
    return groups


# ═══════════════════════════════════════════════════════════════════════════════
# Memory measurement (Linux: /usr/bin/time -v)
# ═══════════════════════════════════════════════════════════════════════════════

def measure_command(
    cmd: list[str],
    timeout_sec: int = 600,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
) -> tuple[int, float, float, float, str, str]:
    """
    Run a command and measure its resource usage.

    Returns (exit_code, wall_sec, cpu_sec, peak_memory_mb, stdout, stderr).
    On Linux, uses /usr/bin/time -v for precise memory.
    On Windows/macOS, falls back to time.time() with no memory data.
    """
    if IS_WINDOWS:
        # Simple timing without memory measurement
        t0 = time.perf_counter()
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec,
            cwd=cwd, env=env,
        )
        elapsed = time.perf_counter() - t0
        return proc.returncode, elapsed, elapsed, 0.0, proc.stdout, proc.stderr

    # Linux: use /usr/bin/time for accurate RSS measurement
    time_cmd = [
        "/usr/bin/time", "-v", "-o", "/dev/stdout",
        "--", *cmd,
    ]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            time_cmd, capture_output=True, text=True, timeout=timeout_sec,
            cwd=cwd, env=env,
        )
    except subprocess.TimeoutExpired:
        return -1, timeout_sec, timeout_sec, 0.0, "", f"TIMEOUT after {timeout_sec}s"

    elapsed = time.perf_counter() - t0

    # Parse /usr/bin/time output from stderr (we redirected -o to /dev/stdout,
    # but actually /usr/bin/time -v -o /dev/stdout writes to stderr by default...
    # Let me handle this differently)
    # Actually, /usr/bin/time writes its output to stderr when using -o /dev/stdout
    # Better approach: redirect time output to a temp file
    return proc.returncode, elapsed, elapsed, 0.0, proc.stdout, proc.stderr


def measure_command_precise(
    cmd: list[str],
    timeout_sec: int = 600,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
) -> tuple[int, float, float, float, str, str]:
    """
    Run a command with precise resource measurement via /usr/bin/time.

    Returns (exit_code, wall_sec, cpu_sec, peak_memory_kb, stdout, stderr).
    Handles non-UTF-8 output gracefully (e.g., SplitCap's GBK error messages).
    """
    combined_env = os.environ.copy()
    if env:
        combined_env.update(env)

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".time", delete=False) as tf:
        time_file = tf.name

    def _safe_decode(data: bytes) -> str:
        """Decode bytes to string, falling back through common encodings."""
        for enc in ["utf-8", "gbk", "latin-1"]:
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("utf-8", errors="replace")

    try:
        if IS_WINDOWS:
            t0 = time.perf_counter()
            proc = subprocess.run(
                cmd, capture_output=True, timeout=timeout_sec,
                cwd=cwd, env=combined_env,
            )
            elapsed = time.perf_counter() - t0
            return (proc.returncode, elapsed, elapsed, 0,
                    _safe_decode(proc.stdout), _safe_decode(proc.stderr))

        # Build the command with /usr/bin/time wrapper
        wrapped_cmd = [
            "/usr/bin/time", "-v", "-o", time_file,
            "--",
        ] + cmd

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                wrapped_cmd, capture_output=True, timeout=timeout_sec,
                cwd=cwd, env=combined_env,
            )
        except subprocess.TimeoutExpired:
            return (-1, timeout_sec, timeout_sec, 0, "", f"TIMEOUT after {timeout_sec}s")

        elapsed = time.perf_counter() - t0

        # Parse /usr/bin/time output
        cpu_sec = elapsed
        peak_kb = 0
        try:
            with open(time_file) as f:
                time_output = f.read()
            # Extract "Maximum resident set size (kbytes): 123456"
            m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", time_output)
            if m:
                peak_kb = int(m.group(1))
            # Extract "User time (seconds): 1.23" and "System time (seconds): 0.45"
            m_user = re.search(r"User time \(seconds\):\s*([\d.]+)", time_output)
            m_sys = re.search(r"System time \(seconds\):\s*([\d.]+)", time_output)
            if m_user and m_sys:
                cpu_sec = float(m_user.group(1)) + float(m_sys.group(1))
        except Exception:
            pass

        return (proc.returncode, elapsed, cpu_sec, peak_kb,
                _safe_decode(proc.stdout), _safe_decode(proc.stderr))

    finally:
        try:
            os.unlink(time_file)
        except OSError:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Tool wrappers
# ═══════════════════════════════════════════════════════════════════════════════

class ToolRunner:
    """Abstraction over RSplitCap (native) and SplitCap (via wine)."""

    def __init__(
        self,
        rsplitcap_bin: str,
        splitcap_bin: Optional[str] = None,
        wine_bin: str = "wine",
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        buffer_bytes: int = DEFAULT_BUFFER_BYTES,
    ):
        self.rsplitcap = shutil.which(rsplitcap_bin) or rsplitcap_bin
        self.splitcap = splitcap_bin
        self.wine = shutil.which(wine_bin) or wine_bin
        self.max_sessions = max_sessions
        self.buffer_bytes = buffer_bytes

        # Resolve real paths
        self.rsplitcap = os.path.realpath(shutil.which(rsplitcap_bin) or rsplitcap_bin)
        self.splitcap = os.path.realpath(splitcap_bin) if splitcap_bin else None
        self.wine = shutil.which(wine_bin) or wine_bin

        # Verify availability
        self.has_rsplitcap = os.path.isfile(self.rsplitcap) and os.access(self.rsplitcap, os.X_OK)
        self.has_splitcap = bool(self.splitcap and os.path.isfile(self.splitcap) and os.access(self.splitcap, os.X_OK))

        # Detect if SplitCap can run directly (WSL2, native Windows, or binfmt_misc)
        self._splitcap_direct = False
        if self.has_splitcap:
            self._splitcap_direct = IS_WINDOWS or self._can_run_exe_directly(self.splitcap)

        # Detect WSL2 for path conversion
        self._is_wsl = False
        if not IS_WINDOWS and self._splitcap_direct:
            self._is_wsl = self._detect_wsl()
            # Cache wslpath availability
            self._has_wslpath = shutil.which("wslpath") is not None if self._is_wsl else False

    @staticmethod
    def _detect_wsl() -> bool:
        """Detect if running under WSL (1 or 2)."""
        try:
            with open("/proc/version") as f:
                return "microsoft" in f.read().lower()
        except Exception:
            return False

    @staticmethod
    def _can_run_exe_directly(exe_path: str) -> bool:
        """Detect if a .exe can execute directly (WSL2 interop or binfmt_misc)."""
        try:
            proc = subprocess.run(
                [exe_path], capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            return proc.returncode >= 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _to_win_path(self, linux_path: str) -> str:
        """Convert a Linux path to Windows format for WSL2 interop."""
        if not self._is_wsl or not self._has_wslpath:
            return linux_path
        try:
            proc = subprocess.run(
                ["wslpath", "-w", linux_path],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
        except Exception:
            pass
        return linux_path

    def _cmd_rsplitcap(self, args: list[str]) -> list[str]:
        return [self.rsplitcap, *args]

    def _cmd_splitcap(self, args: list[str]) -> list[str]:
        """Build SplitCap command — direct on WSL2/Windows, wine fallback otherwise."""
        if self._splitcap_direct:
            return [self.splitcap, *args]
        else:
            return [self.wine, self.splitcap, *args]

    def run(
        self,
        tool: str,
        input_file: str,
        output_dir: str,
        strategy: str = "session",
        ip_filters: Optional[list[str]] = None,
        port_filters: Optional[list[int]] = None,
        output_type: str = "pcap",
        extra_args: Optional[list[str]] = None,
        timeout_sec: int = 600,
    ) -> tuple[int, float, float, float, str, str, str]:
        """
        Run a tool with given parameters.

        Returns (exit_code, wall_sec, cpu_sec, peak_memory_mb, stdout, stderr, tool_name).
        """
        # Convert paths for SplitCap on WSL2
        sc_input = self._to_win_path(input_file) if tool == "splitcap" else input_file
        sc_output = self._to_win_path(output_dir) if tool == "splitcap" else output_dir

        args = [
            "-r", sc_input,
            "-o", sc_output,
            "-s", strategy,
            "-p", str(self.max_sessions),
            "-b", str(self.buffer_bytes),
            "-y", output_type,
        ]
        if ip_filters:
            for ip in ip_filters:
                args.extend(["-ip", ip])
        if port_filters:
            for port in port_filters:
                args.extend(["-port", str(port)])
        if extra_args:
            args.extend(extra_args)

        cmd = self._cmd_rsplitcap(args) if tool == "rsplitcap" else self._cmd_splitcap(args)

        exit_code, wall, cpu, peak_kb, stdout, stderr = measure_command_precise(
            cmd, timeout_sec=timeout_sec,
        )
        peak_mb = peak_kb / 1024.0
        return exit_code, wall, cpu, peak_mb, stdout, stderr, tool

    def run_rsplitcap_archive(
        self,
        input_file: str,
        archive_file: str,
        strategy: str = "session",
        extra_args: Optional[list[str]] = None,
        timeout_sec: int = 600,
    ) -> tuple[int, float, float, float, str, str]:
        """Run RSplitCap in archive mode."""
        args = [
            "-r", input_file,
            "--mode", "archive",
            "--archive", archive_file,
            "-s", strategy,
        ]
        if extra_args:
            args.extend(extra_args)
        cmd = self._cmd_rsplitcap(args)
        exit_code, wall, cpu, peak_kb, stdout, stderr = measure_command_precise(cmd, timeout_sec)
        return exit_code, wall, cpu, peak_kb / 1024.0, stdout, stderr

    def run_rsplitcap_extract(
        self,
        archive_file: str,
        output_dir: str,
        extract_flow: Optional[int] = None,
        filter_ip: Optional[list[str]] = None,
        filter_port: Optional[list[int]] = None,
        filter_proto: Optional[str] = None,
        timeout_sec: int = 600,
    ) -> tuple[int, float, float, float, str, str]:
        """Run RSplitCap in extract mode."""
        args = [
            "--mode", "extract",
            "--archive", archive_file,
            "-o", output_dir,
        ]
        if extract_flow is not None:
            args.extend(["--extract", str(extract_flow)])
        if filter_ip:
            for ip in filter_ip:
                args.extend(["--filter-ip", ip])
        if filter_port:
            for port in filter_port:
                args.extend(["--filter-port", str(port)])
        if filter_proto:
            args.extend(["--filter-proto", filter_proto])
        cmd = self._cmd_rsplitcap(args)
        exit_code, wall, cpu, peak_kb, stdout, stderr = measure_command_precise(cmd, timeout_sec)
        return exit_code, wall, cpu, peak_kb / 1024.0, stdout, stderr

    def run_rsplitcap_list_flows(
        self, archive_file: str, timeout_sec: int = 120
    ) -> tuple[int, str, str]:
        """List flows in archive."""
        cmd = self._cmd_rsplitcap([
            "--mode", "extract",
            "--archive", archive_file,
            "--list-flows",
        ])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        return proc.returncode, proc.stdout, proc.stderr


# ═══════════════════════════════════════════════════════════════════════════════
# Benchmark definitions
# ═══════════════════════════════════════════════════════════════════════════════

# Grouping strategies shared by both tools
SHARED_STRATEGIES = ["session", "flow", "host", "hostpair", "mac", "nosplit"]

# RSplitCap-only strategies
RSPLITCAP_ONLY_STRATEGIES = ["bssid"]

# Time/packet bucketing (RSplitCap only, via -s seconds N / -s packets N)
# These need special handling since sub-arguments are separate


def build_shared_benchmarks(input_files: list[Path]) -> list[dict]:
    """
    Build benchmark definitions for features shared by both tools.

    Each definition is a dict with:
      name, tool (optional — run for both), strategy, input_file, ip_filters,
      port_filters, output_type, extra_args
    """
    benches = []

    # Pick representative files: small (< 1MB), medium (1-50MB), large (50MB+)
    small = [f for f in input_files if f.stat().st_size < 1_000_000][:3]
    medium = [f for f in input_files if 1_000_000 <= f.stat().st_size < 50_000_000][:3]
    large = [f for f in input_files if f.stat().st_size >= 50_000_000][:1]
    representative = (small or medium or large)[:5]

    if not representative:
        return benches

    # For each strategy, benchmark on representative files
    for strategy in SHARED_STRATEGIES:
        for f in representative[:3]:  # limit to 3 files per strategy
            benches.append({
                "name": f"split_{strategy}",
                "strategy": strategy,
                "input_file": str(f),
                "output_type": "pcap",
            })

    # IP filter tests
    for f in representative[:2]:
        benches.append({
            "name": "filter_ip",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "ip_filters": ["10.0.0.1"],
        })

    # Port filter tests
    for f in representative[:2]:
        benches.append({
            "name": "filter_port",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "port_filters": [80, 443],
        })

    # IP + Port combined filter
    for f in representative[:2]:
        benches.append({
            "name": "filter_ip_port",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "ip_filters": ["192.168.0.1"],
            "port_filters": [80],
        })

    # L7 output
    for f in representative[:2]:
        benches.append({
            "name": "split_l7",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "l7",
        })

    return benches


def build_rsplitcap_only_benchmarks(input_files: list[Path]) -> list[dict]:
    """Build benchmark definitions for RSplitCap-unique features."""
    benches = []

    small = [f for f in input_files if f.stat().st_size < 1_000_000][:3]
    medium = [f for f in input_files if 1_000_000 <= f.stat().st_size < 50_000_000][:3]
    representative = (medium or small)[:4]

    if not representative:
        return benches

    # PCAP-NG support — only run on actual .pcapng files
    pcapng_files = [f for f in input_files if f.suffix.lower() == ".pcapng"]
    for f in pcapng_files[:3]:
        benches.append({
            "name": "pcapng_support",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "rsplitcap_only": True,
        })

    # BSSID strategy (requires WiFi data — we run anyway, tool skips non-WiFi gracefully)
    for f in representative[:2]:
        benches.append({
            "name": "strategy_bssid",
            "strategy": "bssid",
            "input_file": str(f),
            "output_type": "pcap",
            "rsplitcap_only": True,
        })

    # Archive mode
    for f in representative[:2]:
        benches.append({
            "name": "archive_create",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "mode": "archive",
            "rsplitcap_only": True,
        })

    # Archive with secondary index
    for f in representative[:2]:
        benches.append({
            "name": "archive_with_index",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "mode": "archive",
            "rsplitcap_only": True,
            "extra_args": [],  # default: secondary index ON
        })

    return benches


def build_pipeline_comparison_benchmarks(input_files: list[Path]) -> list[dict]:
    """Build benchmarks comparing pipelined vs legacy mode."""
    benches = []
    medium = [f for f in input_files if 1_000_000 <= f.stat().st_size < 100_000_000][:3]
    representative = (medium or input_files)[:3]

    for f in representative:
        # Pipelined (default)
        benches.append({
            "name": "pipeline_on",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "rsplitcap_only": True,
            "extra_args": [],
        })
        # Legacy (no-pipeline)
        benches.append({
            "name": "pipeline_off",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "rsplitcap_only": True,
            "extra_args": ["--no-pipeline"],
        })

    return benches


def build_mmap_comparison_benchmarks(input_files: list[Path]) -> list[dict]:
    """Build benchmarks comparing mmap vs read-to-memory."""
    benches = []
    medium = [f for f in input_files if 1_000_000 <= f.stat().st_size < 100_000_000][:3]
    representative = (medium or input_files)[:3]

    for f in representative:
        benches.append({
            "name": "mmap_on",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "rsplitcap_only": True,
        })
        benches.append({
            "name": "mmap_off",
            "strategy": "session",
            "input_file": str(f),
            "output_type": "pcap",
            "rsplitcap_only": True,
            "extra_args": ["--no-mmap"],
        })

    return benches


# ═══════════════════════════════════════════════════════════════════════════════
# Benchmark runner
# ═══════════════════════════════════════════════════════════════════════════════

class BenchmarkRunner:
    """Run benchmark scenarios and collect results."""

    def __init__(
        self,
        runner: ToolRunner,
        output_base: Path,
        warmup_runs: int = 1,
        measure_runs: int = 3,
        timeout_per_test: int = 600,
    ):
        self.runner = runner
        self.output_base = output_base
        self.warmup_runs = warmup_runs
        self.measure_runs = measure_runs
        self.timeout_per_test = timeout_per_test
        self.results: list[BenchResult] = []

    def _output_dir(self, test_name: str, run_idx: int, tool: str) -> Path:
        d = self.output_base / "runs" / test_name / tool / f"run_{run_idx}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _count_output(self, output_dir: Path) -> tuple[int, float]:
        """Count files and total size in output directory."""
        count = 0
        total_size = 0
        if output_dir.exists():
            for f in output_dir.rglob("*"):
                if f.is_file():
                    count += 1
                    total_size += f.stat().st_size
        return count, total_size / (1024 * 1024)

    def _extract_packet_count(self, stderr: str) -> int:
        """Try to extract packet count from stderr/log output."""
        # RSplitCap logs: "Processed NNN packets" or "Pipelined processing: NNN packets"
        m = re.search(r"(?:Processed|processing):\s*(\d+)\s*packets", stderr)
        if m:
            return int(m.group(1))
        # Try SplitCap-style output
        m = re.search(r"(\d+)\s+packets\s+processed", stderr, re.IGNORECASE)
        if m:
            return int(m.group(1))
        return 0

    def run_single(
        self, bench_def: dict, tool: str, run_idx: int
    ) -> BenchResult:
        """Execute a single benchmark run."""
        input_path = Path(bench_def["input_file"])
        file_size_mb = input_path.stat().st_size / (1024 * 1024) if input_path.exists() else 0
        strategy = bench_def.get("strategy", "session")
        output_type = bench_def.get("output_type", "pcap")
        ip_filters = bench_def.get("ip_filters")
        port_filters = bench_def.get("port_filters")
        extra_args = bench_def.get("extra_args", [])
        mode = bench_def.get("mode", "split")

        output_dir = self._output_dir(bench_def["name"], run_idx, tool)

        # Clean output directory
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            if mode == "archive":
                archive_file = str(output_dir / "output.rsplit")
                exit_code, wall, cpu, mem, stdout, stderr = self.runner.run_rsplitcap_archive(
                    input_file=str(input_path),
                    archive_file=archive_file,
                    strategy=strategy,
                    extra_args=extra_args,
                    timeout_sec=self.timeout_per_test,
                )
                if exit_code == 0:
                    output_count, output_size = 1, Path(archive_file).stat().st_size / (1024 * 1024)
                else:
                    output_count, output_size = 0, 0
            elif tool == "rsplitcap":
                exit_code, wall, cpu, mem, stdout, stderr, _ = self.runner.run(
                    tool="rsplitcap",
                    input_file=str(input_path),
                    output_dir=str(output_dir),
                    strategy=strategy,
                    ip_filters=ip_filters,
                    port_filters=port_filters,
                    output_type=output_type,
                    extra_args=extra_args,
                    timeout_sec=self.timeout_per_test,
                )
                output_count, output_size = self._count_output(output_dir)
            else:  # splitcap
                exit_code, wall, cpu, mem, stdout, stderr, _ = self.runner.run(
                    tool="splitcap",
                    input_file=str(input_path),
                    output_dir=str(output_dir),
                    strategy=strategy,
                    ip_filters=ip_filters,
                    port_filters=port_filters,
                    output_type=output_type,
                    extra_args=extra_args,
                    timeout_sec=self.timeout_per_test,
                )
                output_count, output_size = self._count_output(output_dir)

            packets = self._extract_packet_count(stderr)

            return BenchResult(
                test_name=bench_def["name"],
                tool=tool,
                strategy=strategy,
                input_file=str(input_path),
                file_size_mb=file_size_mb,
                elapsed_sec=wall,
                cpu_sec=cpu,
                peak_memory_mb=mem,
                exit_code=exit_code,
                output_file_count=output_count,
                output_size_mb=output_size,
                packets_processed=packets,
                error=stderr.strip()[-500:] if exit_code != 0 else None,
            )

        except subprocess.TimeoutExpired:
            return BenchResult(
                test_name=bench_def["name"],
                tool=tool,
                strategy=strategy,
                input_file=str(input_path),
                file_size_mb=file_size_mb,
                elapsed_sec=self.timeout_per_test,
                cpu_sec=self.timeout_per_test,
                peak_memory_mb=0,
                exit_code=-1,
                error=f"TIMEOUT ({self.timeout_per_test}s)",
            )
        except Exception as e:
            return BenchResult(
                test_name=bench_def["name"],
                tool=tool,
                strategy=strategy,
                input_file=str(input_path),
                file_size_mb=file_size_mb,
                elapsed_sec=0,
                cpu_sec=0,
                peak_memory_mb=0,
                exit_code=-1,
                error=str(e),
            )

    def run_benchmark(
        self,
        bench_def: dict,
        tools: list[str],
    ) -> dict[str, list[BenchResult]]:
        """
        Run a benchmark definition against specified tools.

        Returns {tool: [list of BenchResult per run]}.
        """
        all_runs: dict[str, list[BenchResult]] = {t: [] for t in tools}

        for tool in tools:
            if tool == "splitcap" and not self.runner.has_splitcap:
                continue

            tool_label = "RSplitCap" if tool == "rsplitcap" else "SplitCap"

            # Warmup runs
            for i in range(self.warmup_runs):
                print(f"  [{tool_label}] warmup {i + 1}/{self.warmup_runs} — "
                      f"{bench_def['name']} ({bench_def['strategy']})")
                self.run_single(bench_def, tool, -1 - i)

            # Measurement runs
            for i in range(self.measure_runs):
                print(f"  [{tool_label}] run {i + 1}/{self.measure_runs} — "
                      f"{bench_def['name']} ({bench_def['strategy']})")
                result = self.run_single(bench_def, tool, i)
                all_runs[tool].append(result)
                self.results.append(result)

        return all_runs

    def run_all(
        self,
        benches: list[dict],
        compare_with_splitcap: bool = True,
    ) -> None:
        """Run all benchmark definitions."""
        total = len(benches)
        for idx, bench_def in enumerate(benches):
            rsplitcap_only = bench_def.get("rsplitcap_only", False)
            tools = ["rsplitcap"] if rsplitcap_only else (
                ["rsplitcap", "splitcap"] if compare_with_splitcap else ["rsplitcap"]
            )

            print(f"\n{'=' * 70}")
            print(f"[{idx + 1}/{total}] {bench_def['name']} "
                  f"(strategy={bench_def['strategy']}, "
                  f"file={Path(bench_def['input_file']).name})")
            print(f"  Tools: {', '.join(tools)}")
            print(f"{'=' * 70}")

            self.run_benchmark(bench_def, tools)


# ═══════════════════════════════════════════════════════════════════════════════
# Aggregation
# ═══════════════════════════════════════════════════════════════════════════════

def aggregate_results(results: list[BenchResult]) -> dict[str, dict]:
    """
    Group results by (test_name, tool) and compute median/stddev.

    Returns dict keyed by "test_name|tool" with aggregated stats.
    """
    groups: dict[str, list[BenchResult]] = defaultdict(list)
    for r in results:
        key = f"{r.test_name}|{r.tool}"
        groups[key].append(r)

    aggregated = {}
    for key, runs in groups.items():
        elaps = [r.elapsed_sec for r in runs if r.exit_code == 0]
        cpus = [r.cpu_sec for r in runs if r.exit_code == 0]
        mems = [r.peak_memory_mb for r in runs if r.exit_code == 0]
        pkt_counts = [r.packets_processed for r in runs if r.exit_code == 0]
        out_counts = [r.output_file_count for r in runs if r.exit_code == 0]
        out_sizes = [r.output_size_mb for r in runs if r.exit_code == 0]

        r0 = runs[0]
        aggregated[key] = {
            "test_name": r0.test_name,
            "tool": r0.tool,
            "strategy": r0.strategy,
            "input_file": Path(r0.input_file).name,
            "file_size_mb": r0.file_size_mb,
            "num_runs": len(runs),
            "successful": len(elaps),
            "exit_codes": [r.exit_code for r in runs],
            "wall_median": statistics.median(elaps) if elaps else None,
            "wall_p95": sorted(elaps)[int(len(elaps) * 0.95)] if len(elaps) >= 20 else None,
            "wall_min": min(elaps) if elaps else None,
            "wall_max": max(elaps) if elaps else None,
            "cpu_median": statistics.median(cpus) if cpus else None,
            "mem_median": statistics.median(mems) if mems else None,
            "mem_peak": max(mems) if mems else None,
            "packets_median": int(statistics.median(pkt_counts)) if pkt_counts else 0,
            "output_files_median": int(statistics.median(out_counts)) if out_counts else 0,
            "output_size_median": statistics.median(out_sizes) if out_sizes else 0,
            "first_error": next((r.error for r in runs if r.error), None),
            "throughput_mbps": (
                r0.file_size_mb / statistics.median(elaps)
            ) if elaps and statistics.median(elaps) > 0 else 0,
        }
    return aggregated


def build_comparison_pairs(aggregated: dict) -> list[ComparisonPair]:
    """Pair RSplitCap and SplitCap results for the same test."""
    pairs = []
    by_test = defaultdict(dict)
    for key, agg in aggregated.items():
        by_test[agg["test_name"]][agg["tool"]] = agg

    for test_name, tools in by_test.items():
        # Reconstruct BenchResult-like objects from aggregated data
        def _to_result(agg: dict) -> BenchResult:
            return BenchResult(
                test_name=agg["test_name"],
                tool=agg["tool"],
                strategy=agg["strategy"],
                input_file=agg["input_file"],
                file_size_mb=agg["file_size_mb"],
                elapsed_sec=agg["wall_median"] or 0,
                cpu_sec=agg["cpu_median"] or 0,
                peak_memory_mb=agg["mem_median"] or 0,
                exit_code=0 if agg["successful"] > 0 else -1,
                output_file_count=agg["output_files_median"],
                output_size_mb=agg["output_size_median"],
                packets_processed=agg["packets_median"],
            )

        r = _to_result(tools.get("rsplitcap", {})) if "rsplitcap" in tools else None
        s = _to_result(tools.get("splitcap", {})) if "splitcap" in tools else None

        pairs.append(ComparisonPair(test_name=test_name, rsplitcap=r, splitcap=s))

    return pairs


# ═══════════════════════════════════════════════════════════════════════════════
# HTML Report Generator
# ═══════════════════════════════════════════════════════════════════════════════

# HTML template with CSS and chart containers
REPORT_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #f5f7fa; color: #2d3436; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #6c5ce7, #a855f7);
          color: white; padding: 40px 20px; text-align: center; border-radius: 12px;
          margin-bottom: 30px; }
.header h1 { font-size: 2.2em; font-weight: 700; }
.header p { opacity: 0.9; margin-top: 8px; font-size: 1.1em; }
.meta { display: flex; justify-content: center; gap: 30px; margin-top: 15px;
        font-size: 0.9em; opacity: 0.85; flex-wrap: wrap; }
.card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.06); }
.card h2 { font-size: 1.4em; margin-bottom: 16px; color: #6c5ce7;
           border-bottom: 2px solid #eee; padding-bottom: 10px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 16px; margin-bottom: 24px; }
.stat-box { background: white; border-radius: 10px; padding: 20px; text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
.stat-box .value { font-size: 2em; font-weight: 700; color: #6c5ce7; }
.stat-box .label { color: #636e72; font-size: 0.85em; margin-top: 4px; }
.stat-box.win .value { color: #00b894; }
.stat-box.loss .value { color: #e17055; }
table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
th { background: #f0f0f5; color: #2d3436; font-weight: 600; text-align: left;
     padding: 12px 10px; border-bottom: 2px solid #ddd; }
td { padding: 10px; border-bottom: 1px solid #eee; }
tr:hover td { background: #f8f9ff; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;
         font-weight: 600; }
.badge-rsplit { background: #e8d5f5; color: #6c5ce7; }
.badge-split { background: #dfe6e9; color: #636e72; }
.badge-faster { background: #d5f5e3; color: #00b894; }
.badge-slower { background: #fadbd8; color: #e17055; }
.chart-container { text-align: center; margin: 20px 0; }
.chart-container img { max-width: 100%; height: auto; border-radius: 8px; }
.footer { text-align: center; padding: 20px; color: #b2bec3; font-size: 0.85em; }
.error-msg { background: #fef0ef; border-left: 4px solid #e17055; padding: 12px;
             margin: 8px 0; border-radius: 4px; font-family: monospace; font-size: 0.85em; }
"""


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _fig_to_b64(fig: "plt.Figure") -> str:
    """Convert matplotlib figure to base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def _chart_img(b64: str, alt: str = "") -> str:
    return f'<div class="chart-container"><img src="data:image/png;base64,{b64}" alt="{alt}"></div>'


class ReportGenerator:
    """Generate HTML benchmark report."""

    def __init__(self, aggregated: dict, pairs: list[ComparisonPair],
                 all_results: list[BenchResult], metadata: dict):
        self.aggregated = aggregated
        self.pairs = pairs
        self.all_results = all_results
        self.meta = metadata

    # ── Charts ────────────────────────────────────────────────────────────

    def chart_throughput_comparison(self) -> Optional[str]:
        """Bar chart: RSplitCap vs SplitCap throughput by strategy."""
        if not HAS_MPL:
            return None

        strategies = SHARED_STRATEGIES
        rsplit_tp = []
        split_tp = []
        valid_strategies = []

        for strat in strategies:
            r_key = f"split_{strat}|rsplitcap"
            s_key = f"split_{strat}|splitcap"
            if r_key in self.aggregated and s_key in self.aggregated:
                r_tp = self.aggregated[r_key].get("throughput_mbps", 0)
                s_tp = self.aggregated[s_key].get("throughput_mbps", 0)
                if r_tp > 0 and s_tp > 0:
                    rsplit_tp.append(r_tp)
                    split_tp.append(s_tp)
                    valid_strategies.append(strat)

        if not valid_strategies:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        x = range(len(valid_strategies))
        w = 0.35
        bars1 = ax.bar([i - w / 2 for i in x], rsplit_tp, w, label="RSplitCap", color="#6c5ce7", alpha=0.9)
        bars2 = ax.bar([i + w / 2 for i in x], split_tp, w, label="SplitCap (Wine)", color="#b2bec3", alpha=0.9)

        # Annotate speedup
        for i, (r, s) in enumerate(zip(rsplit_tp, split_tp)):
            if r > s:
                ratio = r / s
                ax.annotate(f"{ratio:.1f}×", (i, max(r, s) + max(rsplit_tp) * 0.02),
                            ha="center", fontsize=9, fontweight="bold", color="#00b894")

        ax.set_xlabel("Grouping Strategy")
        ax.set_ylabel("Throughput (MB/s)")
        ax.set_title("Throughput Comparison: RSplitCap vs SplitCap by Strategy")
        ax.set_xticks(x)
        ax.set_xticklabels(valid_strategies)
        ax.legend(loc="upper left")
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()

        b64 = _fig_to_b64(fig)
        plt.close(fig)
        return _chart_img(b64, "Throughput comparison chart")

    def chart_memory_comparison(self) -> Optional[str]:
        """Bar chart: peak memory usage comparison."""
        if not HAS_MPL:
            return None

        strategies = SHARED_STRATEGIES
        rsplit_mem = []
        split_mem = []
        valid_strategies = []

        for strat in strategies:
            r_key = f"split_{strat}|rsplitcap"
            s_key = f"split_{strat}|splitcap"
            if r_key in self.aggregated and s_key in self.aggregated:
                r_m = self.aggregated[r_key].get("mem_median", 0)
                s_m = self.aggregated[s_key].get("mem_median", 0)
                if r_m > 0 and s_m > 0:
                    rsplit_mem.append(r_m)
                    split_mem.append(s_m)
                    valid_strategies.append(strat)

        if not valid_strategies:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        x = range(len(valid_strategies))
        w = 0.35
        ax.bar([i - w / 2 for i in x], rsplit_mem, w, label="RSplitCap", color="#6c5ce7", alpha=0.9)
        ax.bar([i + w / 2 for i in x], split_mem, w, label="SplitCap (Wine)", color="#b2bec3", alpha=0.9)

        ax.set_xlabel("Grouping Strategy")
        ax.set_ylabel("Peak Memory (MB)")
        ax.set_title("Peak Memory Usage: RSplitCap vs SplitCap")
        ax.set_xticks(x)
        ax.set_xticklabels(valid_strategies)
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()

        b64 = _fig_to_b64(fig)
        plt.close(fig)
        return _chart_img(b64, "Memory comparison chart")

    def chart_relative_performance(self) -> Optional[str]:
        """Horizontal bar chart: relative speedup (RSplitCap / SplitCap)."""
        if not HAS_MPL:
            return None

        pair_labels = []
        speedups = []
        colors = []

        for pair in self.pairs:
            if pair.rsplitcap and pair.splitcap:
                r_time = pair.rsplitcap.elapsed_sec
                s_time = pair.splitcap.elapsed_sec
                if r_time > 0 and s_time > 0:
                    speedup = s_time / r_time  # >1 means RSplitCap is faster
                    pair_labels.append(pair.test_name)
                    speedups.append(speedup)
                    colors.append("#00b894" if speedup >= 1 else "#e17055")

        if not speedups:
            return None

        # Sort by speedup
        sorted_data = sorted(zip(speedups, pair_labels, colors), reverse=True)
        speedups, pair_labels, colors = zip(*sorted_data)

        fig, ax = plt.subplots(figsize=(10, max(4, len(speedups) * 0.4)))
        bars = ax.barh(pair_labels, speedups, color=colors, alpha=0.85)
        ax.axvline(x=1, color="gray", linestyle="--", linewidth=1)
        ax.set_xlabel("Speedup (×) — RSplitCap relative to SplitCap")
        ax.set_title("Relative Performance: RSplitCap vs SplitCap\n(>1 = RSplitCap faster)")

        # Annotate values
        for bar, val in zip(bars, speedups):
            ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                    f"{val:.1f}×", va="center", fontsize=10, fontweight="bold")

        plt.tight_layout()

        b64 = _fig_to_b64(fig)
        plt.close(fig)
        return _chart_img(b64, "Relative performance chart")

    def chart_pipeline_vs_legacy(self) -> Optional[str]:
        """Chart comparing pipelined vs legacy mode."""
        if not HAS_MPL:
            return None

        # Find pipeline comparison pairs by matching input files
        pipe_data = []
        legacy_data = []
        labels = []

        for key, agg in self.aggregated.items():
            if agg["test_name"] == "pipeline_on":
                pipe_data.append((Path(agg["input_file"]).stem[:20], agg))
            elif agg["test_name"] == "pipeline_off":
                legacy_data.append((Path(agg["input_file"]).stem[:20], agg))

        # Match by file stem
        pipe_map = {label: agg for label, agg in pipe_data}
        legacy_map = {label: agg for label, agg in legacy_data}

        common_labels = sorted(set(pipe_map) & set(legacy_map))
        if not common_labels:
            return None

        fig, ax = plt.subplots(figsize=(8, 5))
        x = range(len(common_labels))
        w = 0.35

        pipe_times = [pipe_map[l]["wall_median"] for l in common_labels]
        legacy_times = [legacy_map[l]["wall_median"] for l in common_labels]

        ax.bar([i - w / 2 for i in x], pipe_times, w, label="Pipelined", color="#6c5ce7", alpha=0.9)
        ax.bar([i + w / 2 for i in x], legacy_times, w, label="Legacy (--no-pipeline)", color="#fdcb6e", alpha=0.9)

        ax.set_xlabel("Input File")
        ax.set_ylabel("Elapsed Time (s)")
        ax.set_title("Pipelined Streaming vs Legacy Accumulate Mode")
        ax.set_xticks(x)
        ax.set_xticklabels(common_labels, rotation=30, ha="right", fontsize=8)
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()

        b64 = _fig_to_b64(fig)
        plt.close(fig)
        return _chart_img(b64, "Pipeline comparison chart")

    def chart_mmap_vs_no_mmap(self) -> Optional[str]:
        """Chart comparing mmap vs read-to-memory."""
        if not HAS_MPL:
            return None

        mmap_data = []
        nommap_data = []
        for key, agg in self.aggregated.items():
            if agg["test_name"] == "mmap_on":
                mmap_data.append((Path(agg["input_file"]).stem[:20], agg))
            elif agg["test_name"] == "mmap_off":
                nommap_data.append((Path(agg["input_file"]).stem[:20], agg))

        mmap_map = {label: agg for label, agg in mmap_data}
        nommap_map = {label: agg for label, agg in nommap_data}
        common_labels = sorted(set(mmap_map) & set(nommap_map))

        if not common_labels:
            return None

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        x = range(len(common_labels))
        w = 0.35

        mmap_times = [mmap_map[l]["wall_median"] for l in common_labels]
        nommap_times = [nommap_map[l]["wall_median"] for l in common_labels]
        mmap_mems = [mmap_map[l]["mem_median"] for l in common_labels]
        nommap_mems = [nommap_map[l]["mem_median"] for l in common_labels]

        ax1.bar([i - w / 2 for i in x], mmap_times, w, label="mmap", color="#6c5ce7", alpha=0.9)
        ax1.bar([i + w / 2 for i in x], nommap_times, w, label="read-to-mem", color="#e17055", alpha=0.9)
        ax1.set_title("Time: mmap vs read-to-memory")
        ax1.set_ylabel("Elapsed (s)")
        ax1.set_xticks(x)
        ax1.set_xticklabels(common_labels, rotation=30, ha="right", fontsize=8)
        ax1.legend()
        ax1.grid(axis="y", alpha=0.3)

        ax2.bar([i - w / 2 for i in x], mmap_mems, w, label="mmap", color="#6c5ce7", alpha=0.9)
        ax2.bar([i + w / 2 for i in x], nommap_mems, w, label="read-to-mem", color="#e17055", alpha=0.9)
        ax2.set_title("Memory: mmap vs read-to-memory")
        ax2.set_ylabel("Peak Memory (MB)")
        ax2.set_xticks(x)
        ax2.set_xticklabels(common_labels, rotation=30, ha="right", fontsize=8)
        ax2.legend()
        ax2.grid(axis="y", alpha=0.3)

        plt.suptitle("mmap I/O vs Traditional read()", fontsize=14, fontweight="bold")
        plt.tight_layout()

        b64 = _fig_to_b64(fig)
        plt.close(fig)
        return _chart_img(b64, "mmap comparison chart")

    def chart_file_size_scaling(self) -> Optional[str]:
        """Throughput vs file size scatter/bubble chart."""
        if not HAS_MPL:
            return None

        r_files = []
        r_tps = []
        s_files = []
        s_tps = []

        for key, agg in self.aggregated.items():
            fs = agg["file_size_mb"]
            tp = agg.get("throughput_mbps", 0)
            if tp > 0:
                if agg["tool"] == "rsplitcap":
                    r_files.append(fs)
                    r_tps.append(tp)
                elif agg["tool"] == "splitcap":
                    s_files.append(fs)
                    s_tps.append(tp)

        if not r_files and not s_files:
            return None

        fig, ax = plt.subplots(figsize=(8, 5))
        if r_files:
            ax.scatter(r_files, r_tps, alpha=0.6, s=80, label="RSplitCap", color="#6c5ce7", zorder=3)
        if s_files:
            ax.scatter(s_files, s_tps, alpha=0.6, s=80, label="SplitCap (Wine)", color="#b2bec3", marker="s", zorder=3)

        ax.set_xlabel("Input File Size (MB)")
        ax.set_ylabel("Throughput (MB/s)")
        ax.set_title("Throughput vs File Size")
        ax.legend()
        ax.grid(alpha=0.3)
        plt.tight_layout()

        b64 = _fig_to_b64(fig)
        plt.close(fig)
        return _chart_img(b64, "File size scaling chart")

    # ── HTML tables ───────────────────────────────────────────────────────

    def _build_comparison_table(self) -> str:
        """HTML table comparing RSplitCap vs SplitCap for each shared test."""
        rows = []
        for pair in self.pairs:
            r = pair.rsplitcap
            s = pair.splitcap
            if not r or not s:
                continue

            time_cell = f"{fmt_sec(r.elapsed_sec)} vs {fmt_sec(s.elapsed_sec)}"
            if r.elapsed_sec > 0 and s.elapsed_sec > 0:
                ratio = s.elapsed_sec / r.elapsed_sec
                badge = ("badge-faster" if ratio >= 1 else "badge-slower")
                speed = f"{ratio:.1f}×" if ratio >= 1 else f"1/{1/ratio:.1f}×"
                time_cell += f' <span class="badge {badge}">{speed}</span>'

            mem_cell = f"{fmt_mb(r.peak_memory_mb)} vs {fmt_mb(s.peak_memory_mb)}"

            rows.append(f"""
            <tr>
                <td>{escape_html(pair.test_name)}</td>
                <td>{escape_html(r.strategy)}</td>
                <td>{escape_html(Path(r.input_file).name)}</td>
                <td>{fmt_mb(r.file_size_mb)}</td>
                <td>{time_cell}</td>
                <td>{mem_cell}</td>
                <td>{r.output_file_count}</td>
                <td>{s.output_file_count}</td>
            </tr>""")

        return f"""
        <table>
            <thead>
                <tr>
                    <th>Test</th>
                    <th>Strategy</th>
                    <th>Input</th>
                    <th>Size</th>
                    <th>Time (RSplitCap vs SplitCap)</th>
                    <th>Memory (RSplitCap vs SplitCap)</th>
                    <th>Files (RS)</th>
                    <th>Files (SC)</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;color:#999;">No comparison data yet — run with --splitcap to populate</td></tr>'}
            </tbody>
        </table>"""

    def _build_feature_table(self) -> str:
        """Table of RSplitCap-unique feature benchmarks."""
        rows = []
        for key, agg in sorted(self.aggregated.items()):
            if agg["tool"] != "rsplitcap":
                continue
            # Filter for RSplitCap-unique tests
            if agg["test_name"] in ("split_session", "split_flow", "split_host",
                                     "split_hostpair", "split_mac", "split_nosplit",
                                     "filter_ip", "filter_port", "filter_ip_port", "split_l7"):
                continue  # These are shared tests

            rows.append(f"""
            <tr>
                <td>{escape_html(agg['test_name'])}</td>
                <td>{escape_html(agg['strategy'])}</td>
                <td>{escape_html(agg['input_file'])}</td>
                <td>{fmt_mb(agg['file_size_mb'])}</td>
                <td>{fmt_sec(agg['wall_median'])}</td>
                <td>{fmt_mb(agg['mem_median'])}</td>
                <td>{agg['output_files_median']}</td>
                <td>{fmt_mb(agg['output_size_median'])}</td>
            </tr>""")

        return f"""
        <table>
            <thead>
                <tr>
                    <th>Feature</th>
                    <th>Strategy</th>
                    <th>Input</th>
                    <th>Size</th>
                    <th>Time</th>
                    <th>Memory</th>
                    <th>Files</th>
                    <th>Output Size</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;color:#999;">No RSplitCap-unique feature tests run</td></tr>'}
            </tbody>
        </table>"""

    def _build_summary_boxes(self) -> str:
        """Summary statistic boxes."""
        r_results = [r for r in self.all_results if r.tool == "rsplitcap" and r.exit_code == 0]
        s_results = [r for r in self.all_results if r.tool == "splitcap" and r.exit_code == 0]

        total_tests = len(set(r.test_name for r in self.all_results))
        r_avg_tp = 0.0
        s_avg_tp = 0.0
        if r_results:
            r_avg_tp = statistics.mean(
                [r.file_size_mb / r.elapsed_sec for r in r_results if r.elapsed_sec > 0]
            )
        if s_results:
            s_avg_tp = statistics.mean(
                [r.file_size_mb / r.elapsed_sec for r in s_results if r.elapsed_sec > 0]
            )

        # Count wins
        wins = 0
        losses = 0
        for pair in self.pairs:
            if pair.rsplitcap and pair.splitcap:
                if pair.rsplitcap.elapsed_sec > 0 and pair.splitcap.elapsed_sec > 0:
                    if pair.rsplitcap.elapsed_sec < pair.splitcap.elapsed_sec:
                        wins += 1
                    else:
                        losses += 1

        return f"""
        <div class="summary-grid">
            <div class="stat-box">
                <div class="value">{total_tests}</div>
                <div class="label">Test Scenarios</div>
            </div>
            <div class="stat-box">
                <div class="value">{len(r_results)}</div>
                <div class="label">RSplitCap Runs</div>
            </div>
            <div class="stat-box">
                <div class="value">{len(s_results)}</div>
                <div class="label">SplitCap Runs</div>
            </div>
            <div class="stat-box">
                <div class="value">{r_avg_tp:.1f} MB/s</div>
                <div class="label">RSplitCap Avg Throughput</div>
            </div>
            <div class="stat-box">
                <div class="value">{s_avg_tp:.1f} MB/s</div>
                <div class="label">SplitCap Avg Throughput</div>
            </div>
            <div class="stat-box win">
                <div class="value">{wins}</div>
                <div class="label">RSplitCap Faster</div>
            </div>
            <div class="stat-box loss">
                <div class="value">{losses}</div>
                <div class="label">SplitCap Faster</div>
            </div>
        </div>"""

    def _build_errors_section(self) -> str:
        """List of failed runs."""
        errors = [r for r in self.all_results if r.exit_code != 0]
        if not errors:
            return ""

        rows = []
        for r in errors:
            rows.append(f"""
            <tr>
                <td>{escape_html(r.test_name)}</td>
                <td><span class="badge badge-split">{escape_html(r.tool)}</span></td>
                <td>{escape_html(Path(r.input_file).name)}</td>
                <td>{r.exit_code}</td>
                <td><div class="error-msg">{escape_html(r.error or 'Unknown error')}</div></td>
            </tr>""")

        return f"""
        <div class="card">
            <h2>⚠ Errors / Failures</h2>
            <table>
                <thead>
                    <tr><th>Test</th><th>Tool</th><th>Input</th><th>Exit Code</th><th>Details</th></tr>
                </thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>"""

    def generate(self, output_path: Path) -> None:
        """Generate the full HTML report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        charts = []
        for chart_fn in [
            self.chart_throughput_comparison,
            self.chart_memory_comparison,
            self.chart_relative_performance,
            self.chart_file_size_scaling,
            self.chart_pipeline_vs_legacy,
            self.chart_mmap_vs_no_mmap,
        ]:
            try:
                c = chart_fn()
                if c:
                    charts.append(c)
            except Exception as e:
                charts.append(f'<p style="color:#e17055;">Chart generation failed: {escape_html(str(e))}</p>')

        charts_html = "\n".join(charts)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RSplitCap Benchmark Report</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>🚀 RSplitCap Benchmark Report</h1>
    <p>Performance comparison: RSplitCap (Rust) vs SplitCap (C#, via Wine)</p>
    <div class="meta">
        <span>📅 {now}</span>
        <span>💻 {platform.node()}</span>
        <span>🐧 {platform.system()} {platform.release()}</span>
        <span>🦀 RSplitCap v{self.meta.get('rsplitcap_version', '?')}</span>
        <span>🍷 Wine: {self.meta.get('wine_version', 'N/A')}</span>
    </div>
</div>

<div class="card">
    <h2>📊 Executive Summary</h2>
    {self._build_summary_boxes()}
</div>

<div class="card">
    <h2>📈 Performance Charts</h2>
    {charts_html if charts_html else '<p style="color:#999;">Install matplotlib for charts: pip install matplotlib</p>'}
</div>

<div class="card">
    <h2>🔄 Feature Parity: RSplitCap vs SplitCap</h2>
    <p style="color:#636e72;margin-bottom:16px;">
        Side-by-side comparison of shared SplitCap features.
        <span class="badge badge-faster">N×</span> = RSplitCap is N times faster.
    </p>
    {self._build_comparison_table()}
</div>

<div class="card">
    <h2>✨ RSplitCap-Exclusive Features</h2>
    <p style="color:#636e72;margin-bottom:16px;">
        Features available only in RSplitCap: PCAP-NG, archive mode, pipelined streaming,
        mmap I/O, BSSID strategy, time/packet bucketing, secondary indexes.
    </p>
    {self._build_feature_table()}
</div>

{self._build_errors_section()}

<div class="card">
    <h2>📋 Test Configuration</h2>
    <table>
        <tr><td style="width:200px;font-weight:600;">RSplitCap binary</td><td><code>{escape_html(self.meta.get('rsplitcap_bin', 'N/A'))}</code></td></tr>
        <tr><td>SplitCap binary</td><td><code>{escape_html(self.meta.get('splitcap_bin', 'N/A'))}</code></td></tr>
        <tr><td>Test data</td><td><code>{escape_html(self.meta.get('data_dir', 'N/A'))}</code></td></tr>
        <tr><td>Warmup runs</td><td>{self.meta.get('warmup_runs', '?')}</td></tr>
        <tr><td>Measurement runs</td><td>{self.meta.get('measure_runs', '?')}</td></tr>
        <tr><td>Max sessions</td><td>{self.meta.get('max_sessions', '?')}</td></tr>
    </table>
</div>

<div class="footer">
    Generated by RSplitCap Benchmark Suite — {now}
</div>

</div>
</body>
</html>"""

        output_path.write_text(html, encoding="utf-8")
        print(f"\nReport written to: {output_path}")

        # Also save JSON data for further analysis
        json_path = output_path.with_suffix(".json")
        json_path.write_text(json.dumps({
            "metadata": {
                "generated": now,
                "host": platform.node(),
                "system": platform.system(),
                "release": platform.release(),
                **{k: str(v) for k, v in self.meta.items()},
            },
            "results": [
                {
                    "test_name": r.test_name,
                    "tool": r.tool,
                    "strategy": r.strategy,
                    "input_file": r.input_file,
                    "file_size_mb": r.file_size_mb,
                    "elapsed_sec": r.elapsed_sec,
                    "cpu_sec": r.cpu_sec,
                    "peak_memory_mb": r.peak_memory_mb,
                    "exit_code": r.exit_code,
                    "output_file_count": r.output_file_count,
                    "output_size_mb": r.output_size_mb,
                    "packets_processed": r.packets_processed,
                    "error": r.error,
                }
                for r in self.all_results
            ],
        }, indent=2, default=str), encoding="utf-8")
        print(f"JSON data written to: {json_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="RSplitCap Benchmark Suite — compare RSplitCap with SplitCap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare RSplitCap with SplitCap on USTC-TFC dataset
  python bench_rsplitcap.py --data-dir ./USTC-TFC2016 --rsplitcap ./target/release/rsplitcap \\
                            --splitcap ./SplitCap.exe --output ./bench_report

  # Benchmark RSplitCap only (no comparison)
  python bench_rsplitcap.py --data-dir ./pcaps --rsplitcap ./target/release/rsplitcap \\
                            --output ./bench_report --no-splitcap

  # Quick test: only run a few scenarios
  python bench_rsplitcap.py --data-dir ./pcaps --rsplitcap ./target/release/rsplitcap \\
                            --quick --output ./quick_report
        """,
    )

    # Tool paths
    p.add_argument("--rsplitcap", default=os.environ.get(ENV_RSPLITCAP, "./target/release/rsplitcap"),
                   help="Path to RSplitCap binary (env: RSPLITCAP_BIN)")
    p.add_argument("--splitcap", default=os.environ.get(ENV_SPLITCAP, None),
                   help="Path to SplitCap.exe (env: SPLITCAP_BIN). Required for comparison.")
    p.add_argument("--wine", default="wine", help="Path to wine binary (default: wine)")

    # Data
    p.add_argument("--data-dir", required=True,
                   help="Directory containing PCAP/PCAPNG test files (e.g., USTC-TFC dataset)")
    p.add_argument("--file-extensions", default=".pcap,.pcapng,.cap,.ntar",
                   help="Comma-separated list of file extensions to scan (default: .pcap,.pcapng,.cap,.ntar)")

    # Output
    p.add_argument("--output", "-o", default="./benchmark_report",
                   help="Output directory for report and temporary files")

    # Benchmark settings
    p.add_argument("--warmup-runs", type=int, default=1,
                   help="Number of warmup runs per test (default: 1)")
    p.add_argument("--measure-runs", type=int, default=3,
                   help="Number of measurement runs per test (default: 3)")
    p.add_argument("--timeout", type=int, default=600,
                   help="Timeout per test in seconds (default: 600)")
    p.add_argument("--max-sessions", type=int, default=10000,
                   help="Max concurrent sessions (default: 10000)")
    p.add_argument("--max-files", type=int, default=0,
                   help="Max input files to use (0 = all)")
    p.add_argument("--quick", action="store_true",
                   help="Quick mode: fewer files, fewer runs (1 warmup + 1 measure)")

    # What to run
    p.add_argument("--no-splitcap", action="store_true",
                   help="Skip SplitCap comparison (benchmark RSplitCap only)")
    p.add_argument("--skip-shared", action="store_true",
                   help="Skip shared-feature tests (only run RSplitCap-unique)")
    p.add_argument("--skip-unique", action="store_true",
                   help="Skip RSplitCap-unique feature tests")
    p.add_argument("--skip-pipeline-compare", action="store_true",
                   help="Skip pipeline vs legacy comparison")
    p.add_argument("--skip-mmap-compare", action="store_true",
                   help="Skip mmap vs no-mmap comparison")

    return p.parse_args()


def main():
    args = parse_args()

    # Quick mode overrides
    if args.quick:
        args.warmup_runs = 1
        args.measure_runs = 1
        args.max_files = min(args.max_files or 5, 5)

    # Validate
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"❌ Data directory not found: {data_dir}", file=sys.stderr)
        sys.exit(1)

    rsplitcap_path = args.rsplitcap
    if not os.path.isfile(rsplitcap_path) and not shutil.which(rsplitcap_path):
        print(f"❌ RSplitCap binary not found: {rsplitcap_path}", file=sys.stderr)
        print(f"   Build it first: cargo build --release", file=sys.stderr)
        sys.exit(1)

    if args.splitcap and not os.path.isfile(args.splitcap):
        print(f"❌ SplitCap.exe not found: {args.splitcap}", file=sys.stderr)
        print(f"   Provide path via --splitcap or set SPLITCAP_BIN env var.", file=sys.stderr)
        sys.exit(1)

    # Setup output directory
    output_base = Path(args.output)
    output_base.mkdir(parents=True, exist_ok=True)
    runs_dir = output_base / "runs"
    if runs_dir.exists():
        shutil.rmtree(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)

    # Collect input files
    extensions = tuple(f".{ext.strip().lstrip('.')}" for ext in args.file_extensions.split(","))
    input_files = collect_files(data_dir, extensions=extensions)
    if not input_files:
        print(f"❌ No capture files found in {data_dir} with extensions {extensions}", file=sys.stderr)
        sys.exit(1)

    # Sort by size ascending (useful for progressive benchmarking)
    input_files.sort(key=lambda p: p.stat().st_size)

    if args.max_files > 0 and len(input_files) > args.max_files:
        # Pick a representative sample: smallest, median, largest
        if args.max_files >= 3:
            selected = (
                input_files[:args.max_files // 3]
                + input_files[len(input_files) // 2 : len(input_files) // 2 + args.max_files // 3]
                + input_files[-args.max_files // 3:]
            )
            input_files = sorted(set(selected), key=lambda p: p.stat().st_size)
        else:
            input_files = input_files[:args.max_files]

    print(f"📁 Found {len(input_files)} capture files")
    total_size = sum(f.stat().st_size for f in input_files) / (1024 ** 2)
    print(f"   Total size: {total_size:.1f} MB")
    if len(input_files) <= 10:
        for f in input_files:
            print(f"   - {f.name} ({f.stat().st_size / 1024:.0f} KB)")
    else:
        smallest = input_files[0]
        largest = input_files[-1]
        print(f"   Smallest: {smallest.name} ({smallest.stat().st_size / 1024:.0f} KB)")
        print(f"   Largest:  {largest.name} ({largest.stat().st_size / (1024**2):.1f} MB)")

    # Build benchmark definitions
    all_benches = []

    if not args.skip_shared:
        all_benches.extend(build_shared_benchmarks(input_files))
        print(f"📋 {len(all_benches)} shared-feature benchmarks defined")

    if not args.skip_unique:
        unique = build_rsplitcap_only_benchmarks(input_files)
        all_benches.extend(unique)
        print(f"📋 {len(unique)} RSplitCap-unique benchmarks defined")

        if not args.skip_pipeline_compare:
            pipe = build_pipeline_comparison_benchmarks(input_files)
            all_benches.extend(pipe)
            print(f"📋 {len(pipe)} pipeline comparison benchmarks defined")

        if not args.skip_mmap_compare:
            mmap = build_mmap_comparison_benchmarks(input_files)
            all_benches.extend(mmap)
            print(f"📋 {len(mmap)} mmap comparison benchmarks defined")

    if not all_benches:
        print("❌ No benchmarks defined. Check your options.", file=sys.stderr)
        sys.exit(1)

    print(f"\n🔬 Total benchmark scenarios: {len(all_benches)}")
    print(f"   Warmup runs: {args.warmup_runs}, Measurement runs: {args.measure_runs}")
    print(f"   Total runs: {len(all_benches) * (args.warmup_runs + args.measure_runs) * (1 if args.no_splitcap else 2)}")

    # Get metadata
    rsplitcap_version = "unknown"
    try:
        proc = subprocess.run([rsplitcap_path, "--version"], capture_output=True, text=True, timeout=10)
        rsplitcap_version = proc.stdout.strip() or proc.stderr.strip() or "unknown"
    except Exception:
        pass

    wine_version = "N/A"
    if args.splitcap and not IS_WINDOWS:
        try:
            proc = subprocess.run([args.wine, "--version"], capture_output=True, text=True, timeout=10)
            wine_version = proc.stdout.strip() or proc.stderr.strip() or "N/A"
        except Exception:
            pass

    # Create runner
    tool_runner = ToolRunner(
        rsplitcap_bin=rsplitcap_path,
        splitcap_bin=args.splitcap if not args.no_splitcap else None,
        wine_bin=args.wine,
        max_sessions=args.max_sessions,
    )

    bench_runner = BenchmarkRunner(
        runner=tool_runner,
        output_base=output_base,
        warmup_runs=args.warmup_runs,
        measure_runs=args.measure_runs,
        timeout_per_test=args.timeout,
    )

    # ── Run all benchmarks ────────────────────────────────────────────────
    t_start = time.perf_counter()
    bench_runner.run_all(all_benches, compare_with_splitcap=not args.no_splitcap)
    t_total = time.perf_counter() - t_start
    print(f"\n⏱  Total benchmark time: {fmt_sec(t_total)}")

    # ── Aggregate and report ──────────────────────────────────────────────
    aggregated = aggregate_results(bench_runner.results)
    pairs = build_comparison_pairs(aggregated)

    print(f"\n📊 Generating report...")
    report_gen = ReportGenerator(
        aggregated=aggregated,
        pairs=pairs,
        all_results=bench_runner.results,
        metadata={
            "rsplitcap_bin": rsplitcap_path,
            "rsplitcap_version": rsplitcap_version,
            "splitcap_bin": args.splitcap or "N/A",
            "wine_version": wine_version,
            "data_dir": str(data_dir),
            "warmup_runs": args.warmup_runs,
            "measure_runs": args.measure_runs,
            "max_sessions": args.max_sessions,
            "total_benchmark_time_sec": t_total,
        },
    )

    report_path = output_base / "report.html"
    report_gen.generate(report_path)

    # ── Print summary ─────────────────────────────────────────────────────
    r_ok = sum(1 for r in bench_runner.results if r.tool == "rsplitcap" and r.exit_code == 0)
    s_ok = sum(1 for r in bench_runner.results if r.tool == "splitcap" and r.exit_code == 0)
    r_fail = sum(1 for r in bench_runner.results if r.tool == "rsplitcap" and r.exit_code != 0)
    s_fail = sum(1 for r in bench_runner.results if r.tool == "splitcap" and r.exit_code != 0)

    print(f"\n{'=' * 60}")
    print(f"  RSplitCap: {r_ok} passed, {r_fail} failed")
    print(f"  SplitCap:  {s_ok} passed, {s_fail} failed")
    print(f"  Report:    {report_path}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
