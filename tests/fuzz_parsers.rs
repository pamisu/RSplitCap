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
