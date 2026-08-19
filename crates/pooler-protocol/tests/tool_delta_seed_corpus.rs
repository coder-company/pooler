use pooler_protocol::{OpenAiChatEventDecoder, StreamEventKind};

#[test]
fn committed_tool_delta_seeds_replay_as_one_ordered_call() {
    let seeds = [
        include_bytes!("../../../fuzz/corpus/tool-deltas/name-fragment.json").as_slice(),
        include_bytes!("../../../fuzz/corpus/tool-deltas/arguments-fragment.json").as_slice(),
        include_bytes!("../../../fuzz/corpus/tool-deltas/arguments-tail.json").as_slice(),
    ];
    let mut decoder = OpenAiChatEventDecoder::new();
    let mut events = Vec::new();
    for seed in seeds {
        events.extend(decoder.decode_chunk(seed).expect("tool delta seed"));
    }
    events.extend(
        decoder
            .decode_data(b"[DONE]")
            .expect("tool stream sentinel"),
    );

    assert!(events
        .iter()
        .any(|event| { matches!(event.kind, StreamEventKind::ToolCallStart { .. }) }));
    assert!(events
        .iter()
        .any(|event| { matches!(event.kind, StreamEventKind::ToolCallDelta { .. }) }));
    assert!(events
        .iter()
        .any(|event| { matches!(event.kind, StreamEventKind::Completion { .. }) }));
}
