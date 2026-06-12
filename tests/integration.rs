//! Integration tests — end-to-end round-trip verification.

use std::fs;
use std::process::Command;

/// Helper: build a minimal PCAP file in memory.
fn make_test_pcap() -> Vec<u8> {
    let mut buf = Vec::new();

    // PCAP Global Header
    buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
    buf.extend_from_slice(&2u16.to_le_bytes()); // ver major
    buf.extend_from_slice(&4u16.to_le_bytes()); // ver minor
    buf.extend_from_slice(&0u32.to_le_bytes()); // timezone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    buf.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    /// Helper to make a minimal Ethernet+IPv4+TCP packet.
    fn make_pkt(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16, ts_sec: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0x00u8; 6]); // dst mac
        pkt.extend_from_slice(&[0x11u8; 6]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        // IPv4 header (20 bytes)
        pkt.push(0x45); // version + IHL
        pkt.push(0x00); // DSCP + ECN
        let payload = b"TESTPAYLOAD";
        let ip_total = 20 + 20 + payload.len() as u16; // IP hdr + TCP hdr + payload
        pkt.extend_from_slice(&ip_total.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // ID
        pkt.extend_from_slice(&[0x40, 0x00]); // flags + frag offset
        pkt.push(64); // TTL
        pkt.push(6); // Protocol = TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (zero)
        for octet in src_ip.split('.').map(|s| s.parse::<u8>().unwrap()) {
            pkt.push(octet);
        }
        for octet in dst_ip.split('.').map(|s| s.parse::<u8>().unwrap()) {
            pkt.push(octet);
        }
        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq = 1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        pkt.push(0x50); // data offset (5 * 4 = 20)
        pkt.push(0x10); // flags = ACK
        pkt.extend_from_slice(&[0x7F, 0xFF]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent
        // Payload
        pkt.extend_from_slice(payload);

        // PCAP record header
        let mut record = Vec::new();
        record.extend_from_slice(&ts_sec.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        record.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // incl_len
        record.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // orig_len
        record.extend_from_slice(&pkt);
        record
    }

    buf.extend_from_slice(&make_pkt("10.0.0.1", "10.0.0.2", 1234, 80, 1000));
    buf.extend_from_slice(&make_pkt("10.0.0.2", "10.0.0.1", 80, 1234, 1001));
    buf.extend_from_slice(&make_pkt("192.168.1.1", "192.168.1.2", 5555, 443, 2000));

    buf
}

#[test]
fn test_split_session() {
    let pcap = make_test_pcap();
    let dir = tempfile::TempDir::new().unwrap();
    let pcap_path = dir.path().join("test.pcap");
    fs::write(&pcap_path, &pcap).unwrap();

    let output = dir.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("-r")
        .arg(&pcap_path)
        .arg("-s")
        .arg("session")
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();

    assert!(status.success());

    // Output is in a subdirectory named after the input file stem
    let flow_dir = output.join("test");
    let mut files: Vec<_> = fs::read_dir(&flow_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files.sort();
    assert_eq!(files.len(), 2, "Expected 2 flow files, got: {:?}", files);
    assert!(files[0].ends_with(".pcap"));
    assert!(files[1].ends_with(".pcap"));
}

#[test]
fn test_split_filter() {
    let pcap = make_test_pcap();
    let dir = tempfile::TempDir::new().unwrap();
    let pcap_path = dir.path().join("test.pcap");
    fs::write(&pcap_path, &pcap).unwrap();

    let output = dir.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("-r")
        .arg(&pcap_path)
        .arg("-ip")
        .arg("10.0.0.1")
        .arg("-port")
        .arg("80")
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();

    assert!(status.success());

    let flow_dir = output.join("test");
    let files: Vec<_> = fs::read_dir(&flow_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(files.len(), 1, "Expected 1 filtered flow, got: {:?}", files);
}

#[test]
fn test_l7_output() {
    let pcap = make_test_pcap();
    let dir = tempfile::TempDir::new().unwrap();
    let pcap_path = dir.path().join("test.pcap");
    fs::write(&pcap_path, &pcap).unwrap();

    let output = dir.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("-r")
        .arg(&pcap_path)
        .arg("-y")
        .arg("l7")
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();

    assert!(status.success());

    // Check L7 files have content (files are in subdirectory named after input stem)
    let flow_dir = output.join("test");
    for entry in fs::read_dir(&flow_dir).unwrap() {
        let entry = entry.unwrap();
        let content = fs::read(entry.path()).unwrap();
        assert!(!content.is_empty(), "L7 file should not be empty");
        assert!(
            String::from_utf8_lossy(&content).contains("TESTPAYLOAD"),
            "L7 file should contain payload"
        );
    }
}

#[test]
fn test_archive_roundtrip() {
    let pcap = make_test_pcap();
    let dir = tempfile::TempDir::new().unwrap();
    let pcap_path = dir.path().join("test.pcap");
    fs::write(&pcap_path, &pcap).unwrap();

    let archive_path = dir.path().join("test.rsplit");

    // Archive
    let status = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("-r")
        .arg(&pcap_path)
        .arg("--mode")
        .arg("archive")
        .arg("--archive")
        .arg(&archive_path)
        .arg("-s")
        .arg("session")
        .status()
        .unwrap();
    assert!(status.success());
    assert!(archive_path.exists());

    // Extract a single flow
    let extract_dir = dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("--mode")
        .arg("extract")
        .arg("--archive")
        .arg(&archive_path)
        .arg("--extract")
        .arg("1")
        .arg("-o")
        .arg(&extract_dir)
        .status()
        .unwrap();
    assert!(status.success());

    let files: Vec<_> = fs::read_dir(&extract_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(!files.is_empty(), "Should extract at least one file");
}

#[test]
fn test_pcapng_support() {
    // Build a minimal PCAP-NG file with one EPB
    let mut buf = Vec::new();

    // SHB
    let shb_body = {
        let mut b = Vec::new();
        b.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(-1i64).to_le_bytes());
        b.extend_from_slice(&[0u8; 4]); // endofopt
        b
    };
    let shb_len = 12 + shb_body.len() as u32;
    buf.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    buf.extend_from_slice(&shb_len.to_le_bytes());
    buf.extend_from_slice(&shb_body);
    buf.extend_from_slice(&shb_len.to_le_bytes());

    // IDB
    let idb_body = {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&65535u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 4]); // endofopt
        b
    };
    let idb_len = 12 + idb_body.len() as u32;
    buf.extend_from_slice(&0x00000001u32.to_le_bytes());
    buf.extend_from_slice(&idb_len.to_le_bytes());
    buf.extend_from_slice(&idb_body);
    buf.extend_from_slice(&idb_len.to_le_bytes());

    // EPB with a simple packet
    let eth_pkt = {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x00u8; 12]); // macs
        p.extend_from_slice(&[0x08, 0x00]); // EtherType
        p.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]); // minimal IPv4
        p.extend_from_slice(&[0x00; 16]); // rest of IP header
        p
    };
    let epb_body = {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // interface ID
        b.extend_from_slice(&0u32.to_le_bytes()); // ts high
        b.extend_from_slice(&1000u32.to_le_bytes()); // ts low
        b.extend_from_slice(&(eth_pkt.len() as u32).to_le_bytes()); // cap len
        b.extend_from_slice(&(eth_pkt.len() as u32).to_le_bytes()); // orig len
        b.extend_from_slice(&eth_pkt);
        // 4-byte align + endofopt
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b.extend_from_slice(&[0u8; 4]); // endofopt
        b
    };
    let epb_len = 12 + epb_body.len() as u32;
    buf.extend_from_slice(&0x00000006u32.to_le_bytes());
    buf.extend_from_slice(&epb_len.to_le_bytes());
    buf.extend_from_slice(&epb_body);
    buf.extend_from_slice(&epb_len.to_le_bytes());

    let dir = tempfile::TempDir::new().unwrap();
    let pcapng_path = dir.path().join("test.pcapng");
    fs::write(&pcapng_path, &buf).unwrap();

    let output = dir.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("-r")
        .arg(&pcapng_path)
        .arg("-s")
        .arg("session")
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();

    assert!(status.success());
    // Should have processed at least 1 packet
}

#[test]
fn test_list_flows() {
    let pcap = make_test_pcap();
    let dir = tempfile::TempDir::new().unwrap();
    let pcap_path = dir.path().join("test.pcap");
    fs::write(&pcap_path, &pcap).unwrap();

    let archive_path = dir.path().join("test.rsplit");

    // Create archive
    Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("-r")
        .arg(&pcap_path)
        .arg("--mode")
        .arg("archive")
        .arg("--archive")
        .arg(&archive_path)
        .arg("-s")
        .arg("session")
        .status()
        .unwrap();

    // List flows
    let output = Command::new(env!("CARGO_BIN_EXE_rsplitcap"))
        .arg("--mode")
        .arg("extract")
        .arg("--archive")
        .arg(&archive_path)
        .arg("--list-flows")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TCP"), "List should contain protocol info");
    assert!(stdout.contains("10.0.0.1"), "List should contain IP");
}
