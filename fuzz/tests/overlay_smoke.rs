#[path = "../fuzz_targets/overlay_harness.rs"]
mod overlay_harness;

#[test]
fn sequential_inputs_each_reach_overlay_merge_and_compile() {
    let first = overlay_harness::execute(
        b"upstreams:\n  local:\n    merge: true\n    url: http://127.0.0.1:2\n",
    );
    let second = overlay_harness::execute(
        b"upstreams:\n  local:\n    merge: true\n    url: http://127.0.0.1:3\n",
    );

    assert_eq!(
        first,
        overlay_harness::Execution {
            rendered: true,
            loaded: true,
            compiled: true,
        }
    );
    assert_eq!(
        second,
        overlay_harness::Execution {
            rendered: true,
            loaded: true,
            compiled: true,
        }
    );
}
