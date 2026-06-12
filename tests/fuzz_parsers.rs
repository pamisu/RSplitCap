//! Robustness tests — feed random/malformed data to parsers, ensure no panics.

/// Generate random bytes of given length (deterministic seed for reproducibility).
fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        buf.push((state >> 32) as u8);
    }
    buf
}

#[test]
fn test_pcap_parser_no_panic_on_random_data() {
    for size in [0, 1, 3, 16, 24, 32, 64, 128, 256, 512, 1024, 4096] {
        for seed in 0..20 {
            let mut data = random_bytes(size, seed);
            // Override first 4 bytes with valid PCAP magic about half the time
            if seed % 2 == 0 && size >= 24 {
                data[0..4].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes());
                // Fill rest of 24-byte header minimally
                if size >= 24 {
                    data[4..8].copy_from_slice(&[2, 0, 4, 0]); // version
                    data[16..20].copy_from_slice(&[0xFF, 0xFF, 0, 0]); // snaplen
                    data[20..24].copy_from_slice(&[1, 0, 0, 0]); // link_type Ethernet
                }
            }
            // This should never panic
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = rsplitcap::parser::open_reader(bytes::Bytes::from(data));
            }));
            assert!(result.is_ok(), "Parser panicked on size={size}, seed={seed}");
        }
    }
}

#[test]
fn test_pcapng_parser_no_panic_on_random_data() {
    for size in [0, 1, 8, 16, 32, 64, 128, 256, 512] {
        for seed in 0..20 {
            let mut data = random_bytes(size, seed + 1000);
            // Half the time: set first 4 bytes to PCAP-NG SHB magic
            if seed % 2 == 0 && size >= 8 {
                data[0..4].copy_from_slice(&0x0A0D0D0Au32.to_le_bytes());
                if size >= 12 {
                    data[4..8].copy_from_slice(&(size as u32).to_le_bytes());
                }
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = rsplitcap::parser::open_reader(bytes::Bytes::from(data));
            }));
            assert!(result.is_ok(), "PCAP-NG parser panicked on size={size}, seed={seed}");
        }
    }
}

#[test]
fn test_packet_parse_no_panic_on_malformed() {
    // Test protocol parsing with various malformed inputs
    let cases: &[&[u8]] = &[
        &[],
        &[0x40],
        &[0x45, 0x00],
        &[0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06], // IPv4 with IHL=5 but header truncated
        &[0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00], // IPv6 with only 8 bytes
        // Ethernet frame with invalid ethertype
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0xFF, 0xFF],
    ];

    for (i, data) in cases.iter().enumerate() {
        let data = bytes::Bytes::from(data.to_vec());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = rsplitcap::packet::Packet::from_pcap_record(0, 0, data.len() as u32, data, 1);
        }));
        assert!(result.is_ok(), "Packet parsing panicked on case {i}");
    }
}

#[test]
fn test_archive_reader_rejects_corrupt_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("corrupt.rsplit");

    for (size, seed) in [(64, 0), (128, 1), (200, 2), (512, 3)] {
        let data = random_bytes(size, seed);
        std::fs::write(&path, &data).unwrap();
        // Should return an error, not panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = rsplitcap::archive::reader::ArchiveReader::open(&path);
        }));
        assert!(result.is_ok(), "ArchiveReader panicked on corrupt file size={size}");
    }
}

#[test]
fn test_leb128_codec_roundtrip() {
    use rsplitcap::archive::{decode_offsets, encode_offsets};

    let test_cases: &[&[u64]] = &[
        &[],
        &[0],
        &[1],
        &[1000],
        &[0, 1, 2, 3, 4, 5],
        &[100, 200, 300],
        &[0, 1000000, 2000000],
    ];

    for (i, offsets) in test_cases.iter().enumerate() {
        let encoded = encode_offsets(offsets);
        let decoded = decode_offsets(&encoded, offsets.len());
        assert_eq!(&decoded, offsets, "LEB128 roundtrip failed for case {i}");
    }
}

#[test]
fn test_wifi_radiotap_parsing() {
    // Build a minimal radiotap + 802.11 data frame
    let radiotap_hdr = {
        let mut b = Vec::new();
        b.push(0x00); // version
        b.push(0x00); // pad
        b.extend_from_slice(&16u16.to_le_bytes()); // length = 16
        b.extend_from_slice(&0u32.to_le_bytes()); // present flags
        b.extend_from_slice(&[0u8; 8]); // padding to reach 16
        b
    };
    assert_eq!(radiotap_hdr.len(), 16);

    // 802.11 Data frame (24 bytes header)
    // Frame Control: Data, ToDS=0, FromDS=0
    let fc: u16 = 0x02 << 2; // type=Data
    let mut frame = Vec::new();
    frame.extend_from_slice(&fc.to_le_bytes()); // Frame Control
    frame.extend_from_slice(&0u16.to_le_bytes()); // Duration
    frame.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // Addr1 (DA)
    frame.extend_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]); // Addr2 (SA)
    frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Addr3 (BSSID)
    frame.extend_from_slice(&0u16.to_le_bytes()); // Seq Control

    let mut data = radiotap_hdr;
    data.extend_from_slice(&frame);

    let pkt = rsplitcap::packet::Packet::from_pcap_record(0, 0, data.len() as u32, bytes::Bytes::from(data), 127);
    assert_eq!(pkt.src_mac, Some([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
    assert_eq!(pkt.dst_mac, Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
    assert_eq!(pkt.bssid, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
}

#[test]
fn test_wifi_management_frame_bssid() {
    // Build a minimal 802.11 Beacon frame (Management, subtype=Beacon)
    // Frame Control: Management, ToDS=0, FromDS=0
    let fc: u16 = (0x00 << 2) | (0x08 << 4); // type=Management, subtype=Beacon
    let mut data = Vec::new();
    data.extend_from_slice(&fc.to_le_bytes()); // Frame Control
    data.extend_from_slice(&0u16.to_le_bytes()); // Duration
    data.extend_from_slice(&[0xFF; 6]); // Addr1 (DA = broadcast)
    data.extend_from_slice(&[0x22, 0x22, 0x22, 0x22, 0x22, 0x22]); // Addr2 (SA = AP MAC)
    data.extend_from_slice(&[0x33, 0x33, 0x33, 0x33, 0x33, 0x33]); // Addr3 (BSSID)
    data.extend_from_slice(&0u16.to_le_bytes()); // Seq Control

    let pkt = rsplitcap::packet::Packet::from_pcap_record(0, 0, data.len() as u32, bytes::Bytes::from(data), 105);
    assert_eq!(pkt.src_mac, Some([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]));
    assert_eq!(pkt.dst_mac, Some([0xFF; 6]));
    assert_eq!(pkt.bssid, Some([0x33, 0x33, 0x33, 0x33, 0x33, 0x33]));
}

#[test]
fn test_wifi_malformed_no_panic() {
    // Malformed/short WiFi frames should not panic
    use bytes::Bytes;
    let cases: Vec<(u32, Vec<u8>)> = vec![
        (105, vec![]),
        (105, vec![0x00; 3]),
        (105, vec![0x00; 15]),
        (127, vec![]),
        (127, vec![0x00, 0x00, 0x04, 0x00]), // radiotap header only (length=4), no frame
        (127, vec![0x00, 0x00, 0x10, 0x00]), // empty radiotap, length=16 but too short
    ];
    for (link_type, data) in cases {
        let data_len = data.len();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = rsplitcap::packet::Packet::from_pcap_record(0, 0, data_len as u32, Bytes::from(data), link_type);
        }));
        assert!(result.is_ok(), "WiFi parsing panicked on link_type={link_type}, data_len={data_len}");
    }
}

#[test]
fn test_ipv6_ext_hdr_via_ethernet() {
    // Ethernet + IPv6 with extension headers → TCP
    let mut pkt = Vec::new();
    // Ethernet header
    pkt.extend_from_slice(&[0x00u8; 6]); // dst mac
    pkt.extend_from_slice(&[0x11u8; 6]); // src mac
    pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType = IPv6

    let ipv6_start = pkt.len();
    // IPv6 fixed header
    pkt.push(0x60); // version=6
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class + flow label
    let payload_len_pos = pkt.len();
    pkt.extend_from_slice(&0u16.to_be_bytes()); // payload length placeholder
    pkt.push(0); // Next Header = Hop-by-Hop Options
    pkt.push(64); // Hop Limit
    pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
    pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst

    // Hop-by-Hop Options (8 bytes)
    pkt.push(43); // Next Header = Routing
    pkt.push(0);  // Ext Len = 0 → 8 bytes
    pkt.extend_from_slice(&[0u8; 6]);

    // Routing Header (8 bytes)
    pkt.push(6);  // Next Header = TCP
    pkt.push(0);  // Ext Len = 0 → 8 bytes
    pkt.push(0);  // Routing Type
    pkt.push(0);  // Segments Left
    pkt.extend_from_slice(&[0u8; 4]);

    // TCP header
    pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&80u16.to_be_bytes());     // dst port
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq=1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack=0
    pkt.push(0x50); // data offset = 5 * 4 = 20
    pkt.push(0x10); // flags = ACK
    pkt.extend_from_slice(&[0x70, 0x00]); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent ptr
    // TCP payload
    pkt.extend_from_slice(b"HELLO");

    // Fix payload length
    let payload_len = (pkt.len() - ipv6_start - 40) as u16;
    pkt[payload_len_pos..payload_len_pos + 2].copy_from_slice(&payload_len.to_be_bytes());

    let packet = rsplitcap::packet::Packet::from_pcap_record(0, 0, pkt.len() as u32, bytes::Bytes::from(pkt), 1);
    let ft = packet.five_tuple.unwrap();
    assert_eq!(ft.protocol, 6, "Should find TCP protocol after extension headers");
    assert_eq!(ft.src_port, 12345);
    assert_eq!(ft.dst_port, 80);
    assert!(packet.l7_offset.is_some());
    assert_eq!(packet.l7_data().unwrap(), b"HELLO");
}

#[test]
fn test_flow_entry_roundtrip() {
    use rsplitcap::archive::FlowEntry;

    let original = FlowEntry {
        flow_id: 42,
        protocol: 6,
        ..Default::default()
    };
    let bytes = original.to_bytes();
    let parsed = FlowEntry::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.flow_id, original.flow_id);
    assert_eq!(parsed.protocol, original.protocol);
}
