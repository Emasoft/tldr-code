use serde_json::{json, Value};
use std::fs;
use tempfile::tempdir;
use tldr_mcp::server::process_request;
use tldr_mcp::tools::ToolRegistry;

fn dispatch_request(frame: Value, registry: &ToolRegistry) -> Value {
    let raw = process_request(&frame.to_string(), registry)
        .expect("request frame must produce a response");
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("response must be valid JSON: {} - raw: {}", e, raw))
}

fn call_tool(registry: &ToolRegistry, name: &str, arguments: Value) -> Value {
    let response = dispatch_request(
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": name,
                "arguments": arguments
            }
        }),
        registry,
    );
    assert!(
        response.get("error").is_none(),
        "tool call must not return JSON-RPC error: {}",
        response
    );
    assert!(
        response["result"].get("isError").is_none(),
        "tool call must not return MCP error: {}",
        response
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result content text missing: {}", response));
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("tool text must be JSON: {} - text: {}", e, text))
}

#[test]
fn calls_response_exposes_calls_v2_honesty_fields() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("main.py"),
        "from worker import run\n\n\ndef main():\n    run()\n    missing()\n",
    )
    .expect("write main.py");
    fs::write(dir.path().join("worker.py"), "def run():\n    pass\n").expect("write worker.py");

    let registry = ToolRegistry::new();
    let payload = call_tool(
        &registry,
        "tldr_calls",
        json!({
            "path": dir.path(),
            "language": "python"
        }),
    );

    assert_eq!(
        payload["schema"], "calls.v2",
        "calls MCP payload: {}",
        payload
    );
    let edge = payload["edges"]
        .as_array()
        .and_then(|edges| edges.iter().find(|edge| edge["dst_func"] == "run"))
        .unwrap_or_else(|| panic!("expected run edge in calls payload: {}", payload));
    assert_eq!(
        edge["confidence"], "T1",
        "edge must expose confidence: {}",
        edge
    );
    assert!(
        edge["provenance"]["rung"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "edge must expose provenance.rung: {}",
        edge
    );
    assert!(
        edge["staleness"]["src_hash"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "edge must expose staleness.src_hash: {}",
        edge
    );
    assert!(
        payload["unresolved"].is_array(),
        "calls.v2 must expose top-level unresolved[]: {}",
        payload
    );
}

#[test]
fn impact_response_separates_and_optionally_merges_approximate_callers() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("main.py"),
        "class Service:\n    def process(self):\n        pass\n\n\ndef caller(obj):\n    obj.process()\n",
    )
    .expect("write main.py");

    let registry = ToolRegistry::new();
    let default_payload = call_tool(
        &registry,
        "tldr_impact",
        json!({
            "path": dir.path(),
            "function": "process",
            "language": "python"
        }),
    );

    assert_eq!(
        default_payload["schema"], "impact.v2",
        "impact MCP payload: {}",
        default_payload
    );
    let target = default_payload["targets"]
        .as_object()
        .and_then(|targets| targets.values().next())
        .unwrap_or_else(|| panic!("expected one impact target: {}", default_payload));
    assert_eq!(
        target["caller_count"], 0,
        "T2 callers must be excluded from default callers: {}",
        target
    );
    assert!(
        target["approximate_callers"]
            .as_array()
            .is_some_and(|callers| callers.iter().any(|caller| caller["function"] == "caller")),
        "T2 caller must be separated into approximate_callers: {}",
        target
    );

    let approximate_payload = call_tool(
        &registry,
        "tldr_impact",
        json!({
            "path": dir.path(),
            "function": "process",
            "language": "python",
            "approximate": true
        }),
    );
    let approximate_target = approximate_payload["targets"]
        .as_object()
        .and_then(|targets| targets.values().next())
        .unwrap_or_else(|| {
            panic!(
                "expected one approximate impact target: {}",
                approximate_payload
            )
        });
    assert!(
        approximate_target["callers"]
            .as_array()
            .is_some_and(|callers| callers.iter().any(|caller| caller["function"] == "caller")),
        "--approximate must merge T2 callers into callers: {}",
        approximate_target
    );
}

#[test]
fn tools_list_exposes_honesty_layer_parameters() {
    let registry = ToolRegistry::new();
    let response = dispatch_request(
        json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }),
        &registry,
    );
    let tools = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must return tools array: {}", response));

    let find_tool = |name: &str| -> &Value {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("missing tool {name} in tools/list: {}", response))
    };

    for name in ["tldr_calls", "tldr_context"] {
        let tool = find_tool(name);
        assert!(
            tool["inputSchema"]["properties"]
                .get("min_confidence")
                .is_some(),
            "{name} must expose optional min_confidence: {}",
            tool
        );
    }

    for name in ["tldr_impact", "tldr_dead"] {
        let tool = find_tool(name);
        assert!(
            tool["inputSchema"]["properties"]
                .get("approximate")
                .is_some(),
            "{name} must expose optional approximate: {}",
            tool
        );
    }
}
