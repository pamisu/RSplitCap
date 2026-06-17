"""
rsplitcap — A fast PCAP/PCAP-NG splitter with archive capabilities.

Native Python bindings via PyO3.

Usage:
    import rsplitcap

    # Open archive
    archive = rsplitcap.Archive.open("data.rsplit")
    print(archive.flow_count)

    for flow in archive.flows():
        print(f"Flow {flow.id}: {flow.proto_name} "
              f"{flow.src_addr}:{flow.src_port} -> {flow.dst_addr}:{flow.dst_port}")
        for pkt in flow.packets():
            print(f"  ts={pkt.ts:.6f}, len={pkt.length}")
            # pkt.data is raw bytes

    # Create archive from pcap
    rsplitcap.create_archive("input.pcap", "output.rsplit")
"""

# The native module is built by maturin as a shared library.
# Import everything from the compiled .so
from .rsplitcap import (
    Archive,
    Flow,
    Packet,
    create_archive,
    read_flows,
    split,
    pipe_archive,
)

__all__ = [
    "Archive",
    "Flow",
    "Packet",
    "create_archive",
    "read_flows",
    "split",
    "pipe_archive",
]
