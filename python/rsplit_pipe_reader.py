#!/usr/bin/env python3
"""
Reader for rsplitcap --pipe output.

Usage:
    rsplitcap --mode extract --archive data.rsplit --pipe | python process.py

Each flow is output as: [8B length (u64 LE)] [complete pcap file].
This module reads from stdin and yields each pcap as raw bytes,
which can be fed directly to scapy, dpkt, or written to a file.
"""

import struct
import sys
from typing import Iterator, Optional


def read_one_flow(stream) -> Optional[bytes]:
    """Read one length-prefixed pcap flow from a binary stream.

    Returns the complete pcap bytes, or None on EOF.
    """
    raw = stream.read(8)
    if not raw or len(raw) < 8:
        return None
    length = struct.unpack("<Q", raw)[0]
    return stream.read(length)


def iter_flows(stream) -> Iterator[bytes]:
    """Yield each flow as a complete standard pcap file.

    Example:
        for pcap_bytes in iter_flows(sys.stdin.buffer):
            # pcap_bytes is a valid pcap file, parse with scapy:
            #   from scapy.all import rdpcap
            #   pkts = rdpcap(io.BytesIO(pcap_bytes))
            process(pcap_bytes)
    """
    while True:
        pcap = read_one_flow(stream)
        if pcap is None:
            break
        yield pcap


# ── Example usage ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import io

    count = 0
    for pcap_bytes in iter_flows(sys.stdin.buffer):
        count += 1

        # Parse the pcap global header to get basic info
        if len(pcap_bytes) >= 24:
            magic = struct.unpack_from("<I", pcap_bytes, 0)[0]
            link_type = struct.unpack_from("<I", pcap_bytes, 20)[0]

        # Count frames by scanning the pcap
        n_frames = 0
        pos = 24
        while pos + 16 <= len(pcap_bytes):
            incl_len = struct.unpack_from("<I", pcap_bytes, pos + 8)[0]
            pos += 16 + incl_len
            n_frames += 1

        print(f"Flow {count}: {n_frames} frames, {len(pcap_bytes)} bytes, link_type={link_type}",
              file=sys.stderr)

        # Example: save each flow to a file
        # with open(f"flow_{count}.pcap", "wb") as f:
        #     f.write(pcap_bytes)

    print(f"Total: {count} flows", file=sys.stderr)
