use pooler_protocol::{ConnectCompression, ConnectDecoder, ConnectError, ConnectLimits};

fn decode_hex(seed: &str) -> Vec<u8> {
    seed.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).expect("valid seed hex"))
        .collect()
}

#[test]
fn committed_connect_seeds_replay_with_fragmented_transport_chunks() {
    let data = decode_hex(include_str!(
        "../../../fuzz/corpus/connect/identity-data.hex"
    ));
    let mut decoder = ConnectDecoder::new(ConnectLimits::default());
    let mut envelopes = Vec::new();
    for byte in data {
        envelopes.extend(decoder.feed(&[byte]).expect("fragmented data frame"));
    }
    decoder.finish().expect("complete data frame");

    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].payload(), b"hello");
    assert!(!envelopes[0].is_end_stream());

    let end = decode_hex(include_str!("../../../fuzz/corpus/connect/end-stream.hex"));
    let mut decoder =
        ConnectDecoder::with_compression(ConnectLimits::default(), ConnectCompression::Identity);
    let envelopes = decoder.feed(&end).expect("end-stream frame");
    decoder.finish().expect("complete end-stream frame");
    assert_eq!(envelopes.len(), 1);
    assert!(envelopes[0].is_end_stream());
}

#[test]
fn invalid_connect_flags_seed_is_rejected() {
    let seed = decode_hex(include_str!(
        "../../../fuzz/corpus/connect/invalid-flags.hex"
    ));
    let mut decoder = ConnectDecoder::new(ConnectLimits::default());

    let error = decoder.feed(&seed).expect_err("reserved flags must fail");

    assert!(matches!(error, ConnectError::InvalidFlags { .. }));
}
