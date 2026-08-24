use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use pooler_auth::{CredentialId, MemoryOAuthTokenStore, OAuthTokens};
use pooler_config::compile_yaml;
use pooler_http::{NativeRuntime, SseParser};
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn installed_droid_responses_shape_routes_through_semantic_runtime() {
    let response_id = "resp-droid";
    let message_id = "msg-droid";
    let created = json!({
        "type":"response.created",
        "response":{
            "id":response_id,"object":"response","model":"droid-model",
            "status":"in_progress","output":[],"usage":null
        }
    });
    let item_added = json!({
        "type":"response.output_item.added","output_index":0,
        "item":{"id":message_id,"type":"message","status":"in_progress","role":"assistant","content":[]}
    });
    let part_added = json!({
        "type":"response.content_part.added","item_id":message_id,
        "output_index":0,"content_index":0,
        "part":{"type":"output_text","text":"","annotations":[]}
    });
    let delta = json!({
        "type":"response.output_text.delta","item_id":message_id,
        "output_index":0,"content_index":0,"delta":"DROID_RUNTIME_OK"
    });
    let item_done = json!({
        "type":"response.output_item.done","output_index":0,
        "item":{
            "id":message_id,"type":"message","status":"completed","role":"assistant",
            "content":[{"type":"output_text","text":"DROID_RUNTIME_OK","annotations":[]}]
        }
    });
    let completed = json!({
        "type":"response.completed",
        "response":{
            "id":response_id,"object":"response","model":"droid-model",
            "status":"completed",
            "output":[],
            "usage":{
                "input_tokens":5,"input_tokens_details":{"cached_tokens":0},
                "output_tokens":2,"output_tokens_details":{"reasoning_tokens":0},
                "total_tokens":7
            }
        }
    });
    let upstream_body = [
        ("response.created", created),
        ("response.output_item.added", item_added),
        ("response.content_part.added", part_added),
        ("response.output_text.delta", delta),
        ("response.output_item.done", item_done),
        ("response.completed", completed),
    ]
    .into_iter()
    .map(|(name, value)| format!("event: {name}\ndata: {value}\n\n"))
    .collect::<String>()
    .into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let config = droid_config(upstream_address);
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "model":"droid-model",
        "instructions":"reply briefly",
        "input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],
        "tools":[{
            "type":"function","name":"Read","description":"read",
            "parameters":{"type":"object","properties":{},"additionalProperties":false},
            "strict":false
        }],
        "tool_choice":"auto",
        "parallel_tool_calls":true,
        "reasoning":{"effort":"low","summary":"auto"},
        "include":["reasoning.encrypted_content"],
        "prompt_cache_key":"droid-cache",
        "store":false,
        "stream":true
    }))
    .expect("Droid request JSON");
    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(
        response_status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream Responses SSE");
    events.extend(parser.finish().expect("complete Responses SSE"));
    assert!(events.iter().any(|event| {
        event.event.as_deref() == Some("response.output_text.delta")
            && event.data.contains("DROID_RUNTIME_OK")
    }));
    assert!(events
        .iter()
        .any(|event| event.event.as_deref() == Some("response.completed")));
    assert!(!events.iter().any(|event| event.data == "[DONE]"));

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(&upstream_request, "/v1/responses");
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Responses JSON");
    assert_eq!(forwarded["stream"], true);
    assert_eq!(forwarded["store"], false);
    assert_eq!(forwarded["include"][0], "reasoning.encrypted_content");
    assert_eq!(forwarded["tools"][0]["name"], "Read");
    running.stop().await;
}

#[tokio::test]
async fn same_wire_responses_stream_preserves_provider_events_exactly() {
    let message = json!({
        "id":"msg-exact-stream","type":"message","status":"completed","role":"assistant",
        "content":[{
            "type":"output_text","text":"STREAM_EXACT_OK",
            "annotations":[{
                "type":"url_citation","start_index":0,"end_index":6,
                "url":"https://example.test/stream","title":"Stream citation"
            }]
        }]
    });
    let created_response = json!({
        "id":"resp-exact-stream","object":"response","created_at":1_777_777_781_u64,
        "model":"provider-model","status":"in_progress","output":[],
        "parallel_tool_calls":false,"tool_choice":"none",
        "tools":[{"type":"function","name":"provider_tool"}],
        "reasoning":{"effort":"high","summary":"detailed"},
        "service_tier":"priority","metadata":{"trace_id":"stream-trace"}
    });
    let completed_response = json!({
        "id":"resp-exact-stream","object":"response","created_at":1_777_777_781_u64,
        "model":"provider-model","status":"completed","output":[message.clone()],
        "parallel_tool_calls":false,"tool_choice":"none",
        "tools":[{"type":"function","name":"provider_tool"}],
        "reasoning":{"effort":"high","summary":"detailed"},
        "service_tier":"priority","metadata":{"trace_id":"stream-trace"},
        "usage":{
            "input_tokens":9,"input_tokens_details":{"cached_tokens":2},
            "output_tokens":3,"output_tokens_details":{"reasoning_tokens":1},
            "total_tokens":12
        }
    });
    let events = [
        (
            "response.created",
            json!({
                "type":"response.created","sequence_number":0,
                "response":created_response.clone()
            }),
        ),
        (
            "response.in_progress",
            json!({
                "type":"response.in_progress","sequence_number":1,
                "response":created_response
            }),
        ),
        (
            "response.output_item.added",
            json!({
                "type":"response.output_item.added","sequence_number":2,"output_index":0,
                "item":{"id":"msg-exact-stream","type":"message","status":"in_progress","role":"assistant","content":[]}
            }),
        ),
        (
            "response.content_part.added",
            json!({
                "type":"response.content_part.added","item_id":"msg-exact-stream",
                "sequence_number":3,"output_index":0,"content_index":0,
                "part":{"type":"output_text","text":"","annotations":[]}
            }),
        ),
        (
            "response.output_text.delta",
            json!({
                "type":"response.output_text.delta","item_id":"msg-exact-stream",
                "sequence_number":4,"output_index":0,"content_index":0,
                "delta":"STREAM_EXACT_OK","logprobs":[]
            }),
        ),
        (
            "response.output_text.done",
            json!({
                "type":"response.output_text.done","item_id":"msg-exact-stream",
                "sequence_number":5,"output_index":0,"content_index":0,
                "text":"STREAM_EXACT_OK","logprobs":[]
            }),
        ),
        (
            "response.content_part.done",
            json!({
                "type":"response.content_part.done","item_id":"msg-exact-stream",
                "sequence_number":6,"output_index":0,"content_index":0,
                "part":message["content"][0].clone()
            }),
        ),
        (
            "response.output_item.done",
            json!({
                "type":"response.output_item.done","sequence_number":7,
                "output_index":0,"item":message
            }),
        ),
        (
            "response.completed",
            json!({
                "type":"response.completed","sequence_number":8,
                "response":completed_response
            }),
        ),
    ];
    let upstream_body = events
        .iter()
        .map(|(name, event)| format!("event:{name}\ndata:{event}\n\n"))
        .collect::<String>()
        .into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body.clone()).await;
    let running = start_server(droid_config(upstream_address)).await;
    let request = serde_json::to_vec(&json!({
        "model":"droid-model","input":"hello","stream":true,"store":false
    }))
    .expect("streaming request JSON");

    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(response_status(&response), 200);
    assert_eq!(decoded_response_body(&response), upstream_body);
    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("exact stream upstream timeout")
        .expect("exact stream upstream task");
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded request JSON");
    assert_eq!(forwarded["stream"], true);
    running.stop().await;
}

#[tokio::test]
async fn unary_responses_to_chat_reject_before_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("unused Chat upstream binds");
    let upstream_address = upstream.local_addr().expect("unused Chat upstream address");
    let config = compile_yaml(
        "droid-unary-chat-unsupported.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: droid-unary-chat\n    listen: local\n    match: {{method: POST, path: /v1/responses, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.openai.responses}}\n    target: {{provider: local, path: /v1/chat/completions}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.openai.responses.events}}\n    loss_policy: reject\n"
        ),
    )
    .expect("unsupported unary Chat bridge config");
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "model":"droid-model","input":"hello","stream":false
    }))
    .expect("unary request JSON");

    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(response_status(&response), 400);
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "unsupported unary cross-protocol request reached the upstream"
    );
    running.stop().await;
}

#[tokio::test]
async fn codex_native_unary_responses_force_upstream_streaming_and_return_json() {
    let response_id = "resp-codex-unary";
    let reasoning_id = "rs-codex-unary";
    let function_id = "fc-codex-unary";
    let call_id = "call-codex-unary";
    let message_id = "msg-codex-unary";
    let reasoning_item = json!({
        "id":reasoning_id,"type":"reasoning","status":"completed",
        "summary":[{"type":"summary_text","text":"checked"}],
        "encrypted_content":"encrypted-reasoning"
    });
    let function_item = json!({
        "id":function_id,"type":"function_call","status":"completed",
        "call_id":call_id,"name":"lookup","arguments":"{\"query\":\"status\"}"
    });
    let message_item = json!({
        "id":message_id,"type":"message","status":"completed","role":"assistant",
        "content":[{
            "type":"output_text","text":"CODEX_UNARY_OK",
            "annotations":[{
                "type":"url_citation","start_index":0,"end_index":5,
                "url":"https://example.test/source","title":"Exact source"
            }]
        }]
    });
    let terminal_response = json!({
        "id":response_id,
        "object":"response",
        "created_at":1_777_777_777,
        "status":"completed",
        "background":false,
        "error":null,
        "incomplete_details":null,
        "instructions":"preserve this instruction",
        "max_output_tokens":32,
        "model":"private-luna",
        "output":[],
        "parallel_tool_calls":false,
        "previous_response_id":"resp-previous",
        "reasoning":{"effort":"none","summary":"auto"},
        "service_tier":"priority",
        "store":false,
        "temperature":null,
        "text":{"format":{"type":"text"},"verbosity":"low"},
        "tool_choice":"auto",
        "tools":[{
            "type":"function","name":"lookup","description":"lookup exactly",
            "parameters":{"type":"object","properties":{},"additionalProperties":false},
            "strict":true
        }],
        "top_p":null,
        "truncation":"disabled",
        "usage":{
            "input_tokens":11,"input_tokens_details":{"cached_tokens":3},
            "output_tokens":7,"output_tokens_details":{"reasoning_tokens":2},
            "total_tokens":18,
            "details":{"cost_in_usd_ticks":42}
        },
        "metadata":{"trace_id":"trace-live-shaped","tenant":"test"}
    });
    let events = vec![
        json!({
            "type":"response.created",
            "response":{
                "id":response_id,"object":"response","model":"private-luna",
                "status":"in_progress","output":[]
            }
        }),
        json!({
            "type":"response.output_item.added","output_index":0,
            "item":{
                "id":reasoning_id,"type":"reasoning","status":"in_progress","summary":[]
            }
        }),
        json!({
            "type":"response.reasoning_summary_part.added","item_id":reasoning_id,
            "output_index":0,"summary_index":0,
            "part":{"type":"summary_text","text":""}
        }),
        json!({
            "type":"response.reasoning_summary_text.delta","item_id":reasoning_id,
            "output_index":0,"summary_index":0,"delta":"checked"
        }),
        json!({
            "type":"response.output_item.done","output_index":0,
            "item":reasoning_item.clone()
        }),
        json!({
            "type":"response.output_item.added","output_index":1,
            "item":{
                "id":function_id,"type":"function_call","status":"in_progress",
                "call_id":call_id,"name":"lookup","arguments":""
            }
        }),
        json!({
            "type":"response.function_call_arguments.delta","item_id":function_id,
            "output_index":1,"delta":"{\"query\":\"status\"}"
        }),
        json!({
            "type":"response.function_call_arguments.done","item_id":function_id,
            "output_index":1,"name":"lookup","arguments":"{\"query\":\"status\"}"
        }),
        json!({
            "type":"response.output_item.done","output_index":1,
            "item":function_item.clone()
        }),
        json!({
            "type":"response.output_item.added","output_index":2,
            "item":{
                "id":message_id,"type":"message","status":"in_progress",
                "role":"assistant","content":[]
            }
        }),
        json!({
            "type":"response.content_part.added","item_id":message_id,
            "output_index":2,"content_index":0,
            "part":{"type":"output_text","text":"","annotations":[]}
        }),
        json!({
            "type":"response.output_text.delta","item_id":message_id,
            "output_index":2,"content_index":0,"delta":"CODEX_UNARY_OK"
        }),
        json!({
            "type":"response.output_item.done","output_index":2,
            "item":message_item.clone()
        }),
        json!({
            "type":"response.completed",
            "response":terminal_response.clone()
        }),
    ];
    let upstream_body = events
        .into_iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect::<String>()
        .into_bytes();
    let (upstream_address, upstream_task) =
        spawn_strict_codex_streaming_upstream(upstream_body).await;
    let config = codex_unary_config(upstream_address);
    let token_store = Arc::new(MemoryOAuthTokenStore::new());
    token_store.insert(
        CredentialId::new("codex-account").expect("credential ID"),
        OAuthTokens::bearer("codex-access-token", Some("codex-refresh-token"), None),
    );
    let native = Arc::new(
        NativeRuntime::new(&config, token_store)
            .expect("Codex native runtime")
            .with_account_id("codex-account", "chatgpt-account"),
    );
    let running = start_server_with_native(config, native).await;
    let request = serde_json::to_vec(&json!({
        "model":"public-luna",
        "input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],
        "tools":[{
            "type":"function","name":"lookup","description":"lookup",
            "parameters":{"type":"object","properties":{},"additionalProperties":false}
        }],
        "reasoning":{"effort":"none","summary":"auto"},
        "store":false,
        "stream":false
    }))
    .expect("unary Responses request JSON");

    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(
        response_status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let body: Value = serde_json::from_slice(&decoded_response_body(&response))
        .expect("downstream unary Responses JSON");
    let mut expected = terminal_response;
    expected["output"] = Value::Array(vec![reasoning_item, function_item, message_item]);
    assert_eq!(
        body, expected,
        "unary response must retain raw wire fidelity"
    );
    assert_eq!(body["id"], response_id);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["model"], "private-luna");
    assert!(body.get("type").is_none(), "terminal event wrapper leaked");
    assert_eq!(body["usage"]["input_tokens"], 11);
    assert_eq!(body["usage"]["input_tokens_details"]["cached_tokens"], 3);
    assert_eq!(
        body["usage"]["output_tokens_details"]["reasoning_tokens"],
        2
    );
    let output = body["output"].as_array().expect("Responses output array");
    let reasoning = output
        .iter()
        .find(|item| item["type"] == "reasoning")
        .expect("reasoning output survives");
    assert_eq!(reasoning["summary"][0]["text"], "checked");
    assert_eq!(reasoning["encrypted_content"], "encrypted-reasoning");
    assert_eq!(reasoning["id"], reasoning_id);
    let tool = output
        .iter()
        .find(|item| item["type"] == "function_call")
        .expect("tool output survives");
    assert_eq!(tool["call_id"], call_id);
    assert_eq!(tool["id"], function_id);
    assert_eq!(tool["arguments"], "{\"query\":\"status\"}");
    let message = output
        .iter()
        .find(|item| item["type"] == "message")
        .expect("message output survives");
    assert_eq!(message["content"][0]["text"], "CODEX_UNARY_OK");
    assert_eq!(
        message["content"][0]["annotations"][0]["url"],
        "https://example.test/source"
    );
    assert_eq!(message["id"], message_id);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("strict Codex upstream timeout")
        .expect("strict Codex upstream task");
    assert_request_line(&upstream_request, "/backend-api/codex/responses");
    assert_eq!(
        header_value(&upstream_request, "authorization"),
        Some("Bearer codex-access-token")
    );
    assert_eq!(
        header_value(&upstream_request, "chatgpt-account-id"),
        Some("chatgpt-account")
    );
    let forwarded: Value = serde_json::from_slice(http_body(&upstream_request))
        .expect("forwarded Codex Responses JSON");
    assert_eq!(forwarded["model"], "private-luna");
    assert_eq!(forwarded["stream"], true);
    assert_eq!(forwarded["store"], false);
    assert_eq!(forwarded["reasoning"]["effort"], "none");
    assert_eq!(forwarded["tools"][0]["name"], "lookup");
    running.stop().await;
}

#[tokio::test]
async fn response_headers_may_arrive_after_connect_timeout_within_request_timeout() {
    let header_delay = Duration::from_millis(5_200);
    let (upstream_address, upstream_task) = spawn_delayed_header_upstream(header_delay).await;
    let config = timeout_route_config(&format!("http://{upstream_address}"), "5s", "8s");
    let running = start_server(config).await;

    let started = Instant::now();
    let response = send_request(running.address, "/delayed", br#"{"request":true}"#).await;
    let elapsed = started.elapsed();
    assert_eq!(
        response_status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded_response_body(&response))
            .expect("delayed response JSON"),
        json!({"ok":true})
    );
    assert!(
        elapsed >= header_delay,
        "response returned before header delay"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "response exceeded request timeout: {elapsed:?}"
    );
    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("delayed upstream timeout")
        .expect("delayed upstream task");
    assert_request_line(&upstream_request, "/delayed");
    running.stop().await;
}

#[tokio::test]
async fn stalled_tls_connection_is_bounded_by_connect_timeout() {
    let (upstream_address, upstream_task) = spawn_stalled_tls_upstream().await;
    let config = timeout_route_config(&format!("https://{upstream_address}"), "100ms", "3s");
    let running = start_server(config).await;

    let started = Instant::now();
    let response = send_request(running.address, "/delayed", br#"{"request":true}"#).await;
    let elapsed = started.elapsed();
    assert_eq!(
        response_status(&response),
        504,
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "stalled TLS connect ignored its bound: {elapsed:?}"
    );
    let client_hello = timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("stalled TLS upstream did not observe disconnect")
        .expect("stalled TLS upstream task");
    assert!(
        !client_hello.is_empty(),
        "TLS connection was never attempted"
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_unary_routes_through_semantic_runtime() {
    let upstream_body = serde_json::to_vec(&json!({
        "responseId":"resp-unary",
        "modelVersion":"gemini-test",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"GEMINI_UNARY_OK"}]},
            "finishReason":"STOP"
        }],
        "usageMetadata":{
            "promptTokenCount":3,
            "candidatesTokenCount":2,
            "totalTokenCount":5
        }
    }))
    .expect("Gemini response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_config(
        upstream_address,
        "/v1beta/models/gemini-test:generateContent",
    );
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "contents":[{"role":"user","parts":[{"text":"hello"}]}]
    }))
    .expect("Gemini request JSON");
    let response = send_request(
        running.address,
        "/v1beta/models/gemini-test:generateContent",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let body: Value =
        serde_json::from_slice(&decoded_response_body(&response)).expect("downstream Gemini JSON");
    assert_eq!(
        body["candidates"][0]["content"]["parts"][0]["text"],
        "GEMINI_UNARY_OK"
    );
    assert_eq!(body["candidates"][0]["finishReason"], "STOP");
    assert_eq!(body["usageMetadata"]["totalTokenCount"], 5);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/gemini-test:generateContent",
    );
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Gemini JSON");
    assert_eq!(forwarded["contents"][0]["parts"][0]["text"], "hello");
    running.stop().await;
}

#[tokio::test]
async fn gemini_stream_routes_named_sse_without_openai_done_marker() {
    let first = json!({
        "responseId":"resp-stream",
        "modelVersion":"gemini-test",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"GEMINI_STREAM_OK"}]}
        }]
    });
    let terminal = json!({
        "responseId":"resp-stream",
        "modelVersion":"gemini-test",
        "candidates":[{"index":0,"finishReason":"STOP"}],
        "usageMetadata":{
            "promptTokenCount":4,
            "candidatesTokenCount":3,
            "totalTokenCount":7
        }
    });
    let upstream_body = format!("data: {first}\n\ndata: {terminal}\n\n").into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let config = gemini_config(
        upstream_address,
        "/v1beta/models/gemini-test:streamGenerateContent",
    );
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "contents":[{"role":"user","parts":[{"text":"stream"}]}]
    }))
    .expect("Gemini request JSON");
    let response = send_request(
        running.address,
        "/v1beta/models/gemini-test:streamGenerateContent?alt=sse",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream Gemini SSE");
    events.extend(parser.finish().expect("complete downstream Gemini SSE"));
    assert!(events
        .iter()
        .any(|event| event.data.contains("GEMINI_STREAM_OK")));
    assert!(events
        .iter()
        .any(|event| event.data.contains("finishReason")));
    assert!(!events.iter().any(|event| event.data == "[DONE]"));

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/gemini-test:streamGenerateContent?alt=sse",
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_path_template_rewrites_model_alias_and_normalizes_stream_query() {
    let terminal = json!({
        "responseId":"resp-alias",
        "modelVersion":"private-gemini",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"GEMINI_ALIAS_OK"}]},
            "finishReason":"STOP"
        }],
        "usageMetadata":{
            "promptTokenCount":4,
            "candidatesTokenCount":3,
            "totalTokenCount":7
        }
    });
    let upstream_body = format!("data: {terminal}\n\n").into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let config = gemini_alias_config(upstream_address);
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "systemInstruction":{"parts":[{"text":"Be concise."}]},
        "contents":[{"role":"user","parts":[{"text":"alias"}]}]
    }))
    .expect("Gemini alias request JSON");
    let response = send_request(
        running.address,
        "/v1beta/models/public-gemini:streamGenerateContent?trace=alias&alt=json",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream alias SSE");
    events.extend(parser.finish().expect("complete downstream alias SSE"));
    assert!(events
        .iter()
        .any(|event| event.data.contains("GEMINI_ALIAS_OK")));

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/private-gemini:streamGenerateContent?trace=alias&key=server-key&alt=sse",
    );
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Gemini alias JSON");
    assert!(forwarded.get("model").is_none());
    assert!(forwarded["systemInstruction"].get("role").is_none());
    assert_eq!(
        forwarded["systemInstruction"]["parts"][0]["text"],
        "Be concise."
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_count_tokens_alias_rewrites_path_and_preserves_query_and_body() {
    let upstream_body = br#"{"totalTokens":3}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_same_wire_alias_config(
        upstream_address,
        "POST",
        "/v1beta/models/public-gemini:countTokens",
    );
    let running = start_server(config).await;
    let request = br#"{"contents":[{"parts":[{"text":"count me"}]}]}"#;

    let response = send_request(
        running.address,
        "/v1beta/models/public-gemini:countTokens?trace=count&alt=json",
        request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded_response_body(&response)).expect("count response"),
        json!({"totalTokens":3})
    );

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/private-gemini:countTokens?trace=count&alt=json&key=server-key",
    );
    assert_eq!(http_body(&upstream_request), request);
    running.stop().await;
}

#[tokio::test]
async fn gemini_model_get_alias_rewrites_path_and_preserves_query() {
    let upstream_body = br#"{"name":"models/private-gemini"}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config =
        gemini_same_wire_alias_config(upstream_address, "GET", "/v1beta/models/public-gemini");
    let running = start_server(config).await;

    let response = send_method_request(
        running.address,
        "GET",
        "/v1beta/models/public-gemini?view=full",
        b"",
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_method_request_line(
        &upstream_request,
        "GET",
        "/v1beta/models/private-gemini?view=full&key=server-key",
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_unknown_model_action_is_rejected_before_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let config = gemini_alias_config(upstream_address);
    let running = start_server(config).await;
    let response = send_request(
        running.address,
        "/v1beta/models/not-published:generateContent?trace=unknown",
        br#"{"contents":[{"parts":[{"text":"should not forward"}]}]}"#,
    )
    .await;

    assert_eq!(response_status(&response), 400);
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "unknown Gemini models must not reach the upstream"
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_unknown_interaction_model_is_rejected_before_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let config = gemini_same_wire_alias_config(upstream_address, "POST", "/v1beta/interactions");
    let running = start_server(config).await;
    let response = send_request(
        running.address,
        "/v1beta/interactions?trace=unknown",
        br#"{"model":"models/not-published","input":"should not forward"}"#,
    )
    .await;

    assert_eq!(response_status(&response), 400);
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "unknown Gemini Interaction models must not reach the upstream"
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_returned_interaction_id_keeps_follow_ups_on_the_creating_account() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("affinity upstream binds");
    let upstream_address = listener.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for index in 0..7 {
            let (mut stream, _) = listener.accept().await.expect("upstream accepts");
            let request = read_request(&mut stream).await.expect("upstream request");
            let body = if index == 2 {
                br#"{"id":"int_bound","status":"completed"}"#.as_slice()
            } else {
                br#"{}"#.as_slice()
            };
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .await
                .expect("response headers");
            stream.write_all(body).await.expect("response body");
            requests.push(request);
        }
        requests
    });
    let secrets = tempfile::tempdir().expect("secret directory");
    let first_secret = secrets.path().join("first");
    let second_secret = secrets.path().join("second");
    std::fs::write(&first_secret, "first-token").expect("first secret");
    std::fs::write(&second_secret, "second-token").expect("second secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&first_secret, std::fs::Permissions::from_mode(0o600))
            .expect("first secret permissions");
        std::fs::set_permissions(&second_secret, std::fs::Permissions::from_mode(0o600))
            .expect("second secret permissions");
    }
    let config = compile_yaml(
        "gemini-interaction-affinity-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\naccounts:\n  first: {{provider: local, secret: 'file:{}'}}\n  second: {{provider: local, secret: 'file:{}'}}\naccount_pools: {{pool: {{provider: local, accounts: [first, second]}}}}\nmodels:\n  - id: public-gemini\n    targets:\n      - {{id: public-gemini-target, provider: local, account_pool: pool, priority: 1, upstream_model: private-gemini, capabilities: [text], codecs: [], wire_family: gemini}}\npolicies:\n  interactions:\n    selection:\n      strategy: round_robin\n      affinity: {{key: gemini.interaction_id, ttl: 30m}}\nroutes:\n  - id: create\n    listen: local\n    match: {{method: POST, path: /v1beta/interactions, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local, model_from: request.model, policy: interactions}}\n    response: {{mode: opaque}}\n  - id: resource\n    listen: local\n    match: {{methods: [GET, DELETE], path_template: '/v1beta/interactions/{{interaction}}'}}\n    ingress: {{mode: opaque}}\n    target: {{provider: local, policy: interactions}}\n    response: {{mode: opaque}}\n  - id: cancel\n    listen: local\n    match: {{method: POST, path_template: '/v1beta/interactions/{{interaction}}/cancel'}}\n    ingress: {{mode: opaque}}\n    target: {{provider: local, policy: interactions}}\n    response: {{mode: opaque}}\n",
            first_secret.display(),
            second_secret.display(),
        ),
    )
    .expect("Gemini interaction affinity config");
    let running = start_server(config).await;

    // Advance the independent resource and cancel cursors. Without the
    // returned-ID binding, the later follow-ups would rotate accounts.
    for (method, path) in [
        ("GET", "/v1beta/interactions/int_unbound"),
        ("POST", "/v1beta/interactions/int_unbound/cancel"),
    ] {
        let preflight = send_method_request(running.address, method, path, b"").await;
        assert_eq!(response_status(&preflight), 200);
    }

    let create = send_request(
        running.address,
        "/v1beta/interactions",
        br#"{"model":"public-gemini","input":"hello"}"#,
    )
    .await;
    assert_eq!(response_status(&create), 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded_response_body(&create)).expect("create response"),
        json!({"id":"int_bound","status":"completed"})
    );

    let get = send_method_request(
        running.address,
        "GET",
        "/v1beta/interactions/int_bound",
        b"",
    )
    .await;
    assert_eq!(response_status(&get), 200);
    let delete = send_method_request(
        running.address,
        "DELETE",
        "/v1beta/interactions/int_bound",
        b"",
    )
    .await;
    assert_eq!(response_status(&delete), 200);
    let cancel = send_method_request(
        running.address,
        "POST",
        "/v1beta/interactions/int_bound/cancel",
        b"",
    )
    .await;
    assert_eq!(response_status(&cancel), 200);
    let previous = send_request(
        running.address,
        "/v1beta/interactions",
        br#"{"model":"public-gemini","input":"continue","previous_interaction_id":"int_bound"}"#,
    )
    .await;
    assert_eq!(response_status(&previous), 200);

    let requests = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_eq!(requests.len(), 7);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(
            header_value(request, "authorization"),
            Some("Bearer first-token"),
            "request {index} did not preserve the creating account"
        );
        if request.starts_with(b"POST /v1beta/interactions ") {
            assert_eq!(header_value(request, "accept-encoding"), Some("identity"));
        }
    }
    running.stop().await;
}

#[tokio::test]
async fn gemini_interaction_create_rejects_compressed_responses_before_commitment() {
    std::env::set_var("POOLER_TEST_MODEL_KEY", "server-key");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("compressed upstream binds");
    let upstream_address = listener.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let request = read_request(&mut stream).await.expect("upstream request");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngzip",
            )
            .await
            .expect("compressed response");
        request
    });
    let config = compile_yaml(
        "gemini-compressed-interaction.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\naccounts: {{model-account: {{provider: local, secret: env:POOLER_TEST_MODEL_KEY}}}}\nmodels: [{{id: public-gemini, targets: [{{id: public-gemini-target, provider: local, account: model-account, priority: 1, upstream_model: private-gemini, capabilities: [text], codecs: [], wire_family: gemini}}]}}]\nroutes:\n  - id: create\n    listen: local\n    match: {{method: POST, path: /v1beta/interactions, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local, model_from: request.model}}\n    response: {{mode: opaque}}\n",
        ),
    )
    .expect("compressed interaction config");
    let running = start_server(config).await;
    let response = send_request(
        running.address,
        "/v1beta/interactions",
        br#"{"model":"public-gemini","input":"hello"}"#,
    )
    .await;
    assert_eq!(response_status(&response), 502);
    let request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_eq!(header_value(&request, "accept-encoding"), Some("identity"));
    running.stop().await;
}

#[tokio::test]
async fn gemini_interaction_alias_rewrites_body_and_preserves_query() {
    let upstream_body = br#"{"id":"int_123","status":"completed"}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_same_wire_alias_config(upstream_address, "POST", "/v1beta/interactions");
    let running = start_server(config).await;
    let request = br#"{"model":"models/public-gemini","input":"hello","stream":true}"#;

    let response = send_request(
        running.address,
        "/v1beta/interactions?trace=interaction",
        request,
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/interactions?trace=interaction&key=server-key",
    );
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Interaction JSON");
    assert_eq!(forwarded["model"], "private-gemini");
    assert_eq!(forwarded["input"], "hello");
    assert_eq!(forwarded["stream"], true);
    running.stop().await;
}

#[tokio::test]
async fn gemini_agent_interaction_routes_without_a_model_selection() {
    let upstream_body = br#"{"id":"int_agent","status":"completed"}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_same_wire_alias_config(upstream_address, "POST", "/v1beta/interactions");
    let running = start_server(config).await;
    let request = br#"{"agent":"deep-research","input":"hello"}"#;

    let response = send_request(running.address, "/v1beta/interactions?trace=agent", request).await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/interactions?trace=agent&key=server-key",
    );
    assert_eq!(http_body(&upstream_request), request);
    running.stop().await;
}

fn gemini_config(
    upstream_address: SocketAddr,
    downstream_path: &str,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "gemini-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: gemini\n    listen: local\n    match: {{method: POST, path: '{downstream_path}', content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local}}\n    response: {{mode: semantic, decoder: decode.gemini.generate_content.response, encoder: encode.gemini.generate_content.response}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Gemini runtime config")
}

fn gemini_same_wire_alias_config(
    upstream_address: SocketAddr,
    method: &str,
    downstream_path: &str,
) -> pooler_config::CompiledConfig {
    std::env::set_var("POOLER_TEST_MODEL_KEY", "server-key");
    compile_yaml(
        "gemini-same-wire-alias-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}, query: {{key: server-key}}}}}}\naccounts: {{model-account: {{provider: local, secret: env:POOLER_TEST_MODEL_KEY}}}}\nmodels:\n  - id: public-gemini\n    targets:\n      - {{id: public-gemini-target, provider: local, account: model-account, priority: 1, upstream_model: private-gemini, capabilities: [text, streaming, tools, function_calling], codecs: [decode.gemini.generate_content], wire_family: gemini}}\nroutes:\n  - id: gemini-same-wire-alias\n    listen: local\n    match: {{method: {method}, path: '{downstream_path}'}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local}}\n    response: {{mode: opaque}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Gemini same-wire alias config")
}

fn gemini_alias_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    std::env::set_var("POOLER_TEST_MODEL_KEY", "server-key");
    compile_yaml(
        "gemini-alias-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}, query: {{key: server-key}}}}}}\naccounts: {{model-account: {{provider: local, secret: env:POOLER_TEST_MODEL_KEY}}}}\nmodels:\n  - id: public-gemini\n    targets:\n      - {{id: public-gemini-target, provider: local, account: model-account, priority: 1, upstream_model: private-gemini, capabilities: [text, streaming], codecs: [decode.gemini.generate_content], wire_family: gemini}}\nroutes:\n  - id: gemini-alias\n    listen: local\n    match: {{method: POST, path_template: '/v1beta/models/{{model_action}}', content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local, model_from: request.model}}\n    response: {{mode: semantic, decoder: decode.gemini.generate_content.response, encoder: encode.gemini.generate_content.response}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Gemini alias runtime config")
}

fn droid_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "droid-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: droid-responses\n    listen: local\n    match: {{method: POST, path: /v1/responses, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.openai.responses}}\n    target: {{provider: local, path: /v1/responses}}\n    response: {{mode: semantic, decoder: decode.openai.responses.events, encoder: encode.openai.responses.events}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Droid runtime config")
}

fn codex_unary_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "codex-unary-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  codex:\n    url: http://{upstream_address}\n    native: {{kind: codex}}\naccounts:\n  codex-account: {{provider: codex, auth_kind: oauth}}\naccount_pools:\n  codex-pool: {{provider: codex, accounts: [codex-account]}}\nmodels:\n  - id: public-luna\n    targets:\n      - {{id: public-luna-target, provider: codex, account: codex-account, priority: 1, upstream_model: private-luna, capabilities: [text, streaming, tools, reasoning, function_calling], codecs: [decode.openai.responses], wire_family: openai}}\npolicies:\n  codex-responses:\n    selection: {{strategy: fill_first}}\nroutes:\n  - id: codex-responses\n    listen: local\n    match: {{method: POST, path: /v1/responses, content_types: [application/json]}}\n    limits: {{max_request_body_bytes: 1048576, max_response_body_bytes: 1048576, max_frame_bytes: 1048576, max_event_bytes: 1048576}}\n    ingress: {{mode: semantic, decoder: decode.openai.responses, encoder: encode.openai.responses}}\n    target: {{provider: codex, model_from: request.model, policy: codex-responses}}\n    response: {{mode: semantic, decoder: decode.openai.responses.events, encoder: encode.openai.responses.events}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Codex unary runtime config")
}

fn timeout_route_config(
    upstream_url: &str,
    connect_timeout: &str,
    request_timeout: &str,
) -> pooler_config::CompiledConfig {
    let transport = if upstream_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    compile_yaml(
        "separated-timeout-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  delayed:\n    transport: {{kind: {transport}, base_url: '{upstream_url}', connect_timeout: {connect_timeout}, request_timeout: {request_timeout}}}\nroutes:\n  - id: delayed\n    listen: local\n    match: {{method: POST, path: /delayed}}\n    ingress: {{mode: opaque}}\n    target: {{provider: delayed}}\n    response: {{mode: opaque}}\n"
        ),
    )
    .expect("separated timeout runtime config")
}

struct RunningServer {
    server: HttpProxyServer,
    address: SocketAddr,
    runner: JoinHandle<Result<(), HttpProxyServerError>>,
}

impl RunningServer {
    async fn stop(self) {
        self.server.begin_drain();
        timeout(TEST_TIMEOUT, self.runner)
            .await
            .expect("proxy drain timeout")
            .expect("proxy task")
            .expect("proxy succeeds");
    }
}

async fn start_server(config: pooler_config::CompiledConfig) -> RunningServer {
    let server = HttpProxyServer::bind(config).await.expect("proxy binds");
    let address = server.listener_addresses()[0]
        .address()
        .parse()
        .expect("proxy address");
    let runner_server = server.clone();
    let runner = tokio::spawn(async move { runner_server.run().await });
    RunningServer {
        server,
        address,
        runner,
    }
}

async fn start_server_with_native(
    config: pooler_config::CompiledConfig,
    native: Arc<NativeRuntime>,
) -> RunningServer {
    let server = HttpProxyServer::bind_with_native_runtime(config, native)
        .await
        .expect("native proxy binds");
    let address = server.listener_addresses()[0]
        .address()
        .parse()
        .expect("proxy address");
    let runner_server = server.clone();
    let runner = tokio::spawn(async move { runner_server.run().await });
    RunningServer {
        server,
        address,
        runner,
    }
}

async fn spawn_upstream(
    content_type: &'static str,
    body: Vec<u8>,
) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let request = read_request(&mut stream).await.expect("upstream request");
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("response headers");
        stream.write_all(&body).await.expect("response body");
        request
    });
    (address, task)
}

async fn spawn_strict_codex_streaming_upstream(
    streaming_body: Vec<u8>,
) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("strict Codex upstream binds");
    let address = listener.local_addr().expect("strict Codex address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("strict Codex upstream accepts");
        let request = read_request(&mut stream)
            .await
            .expect("strict Codex upstream request");
        let body = serde_json::from_slice::<Value>(http_body(&request)).ok();
        let is_streaming = body
            .as_ref()
            .and_then(|value| value.get("stream"))
            .and_then(Value::as_bool)
            == Some(true);
        let request_line_ok =
            request.starts_with(b"POST /backend-api/codex/responses HTTP/1.1\r\n");
        let authorization_ok = header_value(&request, "authorization")
            == Some("Bearer codex-access-token")
            && header_value(&request, "chatgpt-account-id") == Some("chatgpt-account");
        let (status, reason, content_type, response_body) = if !is_streaming {
            (
                400,
                "Bad Request",
                "application/json",
                br#"{"error":{"message":"Stream must be set to true"}}"#.to_vec(),
            )
        } else if !request_line_ok {
            (
                401,
                "Unauthorized",
                "application/json",
                br#"{"error":{"message":"strict Codex path rejected request"}}"#.to_vec(),
            )
        } else if !authorization_ok {
            (
                401,
                "Unauthorized",
                "application/json",
                br#"{"error":{"message":"strict Codex auth rejected request"}}"#.to_vec(),
            )
        } else {
            (200, "OK", "text/event-stream", streaming_body)
        };
        let headers = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("strict Codex response headers");
        stream
            .write_all(&response_body)
            .await
            .expect("strict Codex response body");
        request
    });
    (address, task)
}

async fn spawn_delayed_header_upstream(delay: Duration) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("delayed-header upstream binds");
    let address = listener.local_addr().expect("delayed-header address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("delayed-header upstream accepts");
        let request = read_request(&mut stream)
            .await
            .expect("delayed-header upstream request");
        tokio::time::sleep(delay).await;
        let body = br#"{"ok":true}"#;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("delayed response headers");
        stream.write_all(body).await.expect("delayed response body");
        request
    });
    (address, task)
}

async fn spawn_stalled_tls_upstream() -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stalled TLS upstream binds");
    let address = listener.local_addr().expect("stalled TLS address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("stalled TLS upstream accepts");
        let mut client_hello = Vec::new();
        stream
            .read_to_end(&mut client_hello)
            .await
            .expect("stalled TLS client disconnect");
        client_hello
    });
    (address, task)
}

async fn send_request(address: SocketAddr, path: &str, body: &[u8]) -> Vec<u8> {
    send_method_request(address, "POST", path, body).await
}

async fn send_method_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let content_type = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/json\r\n".to_owned()
    };
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: gemini-test\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("request headers");
    stream.write_all(body).await.expect("request body");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("proxy response timeout")
        .expect("proxy response");
    response
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let body_start = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let content_length = header_value(&bytes[..body_start], "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < body_start + content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

fn response_status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .expect("response UTF-8")
        .split_whitespace()
        .nth(1)
        .expect("response status")
        .parse()
        .expect("numeric status")
}

fn response_headers(response: &[u8]) -> String {
    String::from_utf8_lossy(&response[..http_body_start(response)]).into_owned()
}

fn decoded_response_body(response: &[u8]) -> Vec<u8> {
    let body = http_body(response);
    if header_value(response, "transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(body)
    } else {
        body.to_vec()
    }
}

fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&body[..line_end])
                .expect("chunk size UTF-8")
                .split(';')
                .next()
                .expect("chunk size"),
            16,
        )
        .expect("hex chunk size");
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
    decoded
}

fn assert_request_line(request: &[u8], path: &str) {
    assert_method_request_line(request, "POST", path);
}

fn assert_method_request_line(request: &[u8], method: &str, path: &str) {
    let end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("request line");
    assert_eq!(
        std::str::from_utf8(&request[..end]).expect("request line UTF-8"),
        format!("{method} {path} HTTP/1.1")
    );
}

fn header_value<'a>(message: &'a [u8], name: &str) -> Option<&'a str> {
    message[..http_body_start(message)]
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(name.as_bytes())
                .then(|| std::str::from_utf8(&line[colon + 1..]).ok().map(str::trim))
                .flatten()
        })
}

fn http_body(message: &[u8]) -> &[u8] {
    &message[http_body_start(message)..]
}

fn http_body_start(message: &[u8]) -> usize {
    message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("HTTP header delimiter")
}
