use pooler_http::SseParser;

#[test]
fn committed_sse_seeds_replay_with_fragmented_transport_chunks() {
    let seeds = [
        (
            "basic-fragmented",
            include_bytes!("../../../fuzz/corpus/sse/basic-fragmented.sse").as_slice(),
            2,
            true,
        ),
        (
            "comments-and-multiple-data",
            include_bytes!("../../../fuzz/corpus/sse/comments-and-multiple-data.sse").as_slice(),
            2,
            false,
        ),
        (
            "lf-and-unknown-fields",
            include_bytes!("../../../fuzz/corpus/sse/lf-and-unknown-fields.sse").as_slice(),
            2,
            true,
        ),
    ];

    for (name, seed, expected_count, expected_done) in seeds {
        let mut parser = SseParser::new();
        let mut events = Vec::new();
        for chunk in seed.chunks(3) {
            events.extend(
                parser
                    .feed(chunk)
                    .unwrap_or_else(|error| panic!("{name} should parse when fragmented: {error}")),
            );
        }
        events.extend(
            parser
                .finish()
                .unwrap_or_else(|error| panic!("{name} should finish: {error}")),
        );

        assert_eq!(events.len(), expected_count, "seed {name}");
        assert_eq!(
            events.last().is_some_and(|event| event.is_done()),
            expected_done,
            "seed {name} terminal sentinel"
        );
    }
}

#[test]
fn incomplete_sse_seed_is_rejected_at_eof() {
    let seed = include_bytes!("../../../fuzz/corpus/sse/incomplete.sse");
    let mut parser = SseParser::new();
    parser.feed(seed).expect("field itself is valid");

    let error = parser
        .finish()
        .expect_err("missing record delimiter must fail");

    assert!(error.to_string().contains("incomplete event"));
}
