//! Tests for TLDR Daemon
//!
//! Tests the daemon socket path computation, state management, and handler logic.
//! The daemon implementation is in crates/tldr-daemon.

// =============================================================================
// Socket protocol tests
// =============================================================================

mod socket_tests {
    use std::path::PathBuf;
    // why: the previous version of this test re-implemented the MD5 hashing
    // logic inline instead of calling the daemon's own function, so it could
    // never catch a regression in `compute_socket_path`/`compute_tcp_port`
    // itself (a fake/conceptual test — see tldr rule on tests that don't
    // exercise the code they claim to test).
    use tldr_daemon::server::{compute_socket_path, compute_tcp_port};

    #[test]
    fn daemon_socket_path_uses_hash() {
        // The socket path should contain an 8-hex-char hash of the project path.
        // Format: <tmp>/tldr-{hash}-v{version}.sock
        let project_path = PathBuf::from("/tmp/test-project");

        let socket_path = compute_socket_path(&project_path, "1.0");
        let file_name = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("socket path must have a file name");

        assert!(
            file_name.starts_with("tldr-") && file_name.ends_with("-v1.0.sock"),
            "unexpected socket file name: {}",
            file_name
        );
        let hash_prefix = &file_name["tldr-".len()..file_name.len() - "-v1.0.sock".len()];
        assert_eq!(hash_prefix.len(), 8);
        assert!(hash_prefix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn daemon_tcp_port_in_valid_range() {
        // TCP port should be in range [49152, 59152)
        let project_path = PathBuf::from("/tmp/test-project");

        let port = compute_tcp_port(&project_path);

        assert!(port >= 49152);
        assert!(port < 59152);
    }
}

// =============================================================================
// Message format tests
// =============================================================================

mod message_tests {

    #[test]
    fn ping_request_format() {
        // Ping request should be valid JSON
        let request = r#"{"cmd": "ping"}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "ping");
    }

    #[test]
    fn tree_request_format() {
        // Tree request with extensions
        let request = r#"{"cmd": "tree", "extensions": [".py"]}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "tree");
        assert!(parsed["extensions"].is_array());
    }

    #[test]
    fn structure_request_format() {
        // Structure request with language
        let request = r#"{"cmd": "structure", "language": "python", "max_results": 100}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "structure");
        assert_eq!(parsed["language"], "python");
        assert_eq!(parsed["max_results"], 100);
    }

    #[test]
    fn extract_request_format() {
        let request = r#"{"cmd": "extract", "file": "main.py"}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "extract");
        assert_eq!(parsed["file"], "main.py");
    }

    #[test]
    fn calls_request_format() {
        let request = r#"{"cmd": "calls", "language": "python"}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "calls");
    }

    #[test]
    fn impact_request_format() {
        let request = r#"{"cmd": "impact", "func": "process_data", "depth": 3}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "impact");
        assert_eq!(parsed["func"], "process_data");
        assert_eq!(parsed["depth"], 3);
    }

    #[test]
    fn cfg_request_format() {
        let request = r#"{"cmd": "cfg", "file": "main.py", "function": "main"}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "cfg");
        assert_eq!(parsed["file"], "main.py");
        assert_eq!(parsed["function"], "main");
    }

    #[test]
    fn slice_request_format() {
        let request = r#"{"cmd": "slice", "file": "main.py", "function": "main", "line": 10, "direction": "backward"}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "slice");
        assert_eq!(parsed["line"], 10);
        assert_eq!(parsed["direction"], "backward");
    }

    #[test]
    fn search_request_format() {
        let request = r#"{"cmd": "search", "pattern": "def \\w+", "max_results": 50}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "search");
        assert_eq!(parsed["max_results"], 50);
    }

    #[test]
    fn context_request_format() {
        let request = r#"{"cmd": "context", "entry": "main", "depth": 2, "language": "python"}"#;
        let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(parsed["cmd"], "context");
        assert_eq!(parsed["entry"], "main");
        assert_eq!(parsed["depth"], 2);
    }

    #[test]
    fn response_ok_format() {
        // OK response format
        let response = r#"{"status": "ok", "result": "pong"}"#;
        let parsed: serde_json::Value = serde_json::from_str(response).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert!(parsed.get("result").is_some());
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn response_error_format() {
        // Error response format
        let response = r#"{"status": "error", "error": "Unknown command"}"#;
        let parsed: serde_json::Value = serde_json::from_str(response).unwrap();
        assert_eq!(parsed["status"], "error");
        assert!(parsed.get("error").is_some());
    }
}

// =============================================================================
// State management tests (conceptual - actual tests in daemon crate)
// =============================================================================

mod state_tests {

    #[test]
    fn state_structure() {
        // DaemonState should track:
        // - project path
        // - socket path
        // - version
        // - last_activity (atomic timestamp)
        // - idle_timeout
        // - call_graph_cache
        // - bm25_cache
        // - request_count
        // - error_count

        // These are tested in the daemon crate's unit tests
        let _ = ();
    }

    #[test]
    fn idle_timeout_concept() {
        // After idle_timeout (default 5 minutes), daemon should exit
        // This is tested in daemon crate
        let _ = ();
    }

    #[test]
    fn cache_invalidation_concept() {
        // Caches should be invalidated when:
        // - explicitly requested
        // - files are modified (future: file watcher)
        let _ = ();
    }
}

// =============================================================================
// Performance tests
// =============================================================================

mod daemon_performance_tests {

    #[test]
    #[ignore] // Performance test
    fn daemon_handles_concurrent_requests() {
        // This would require starting an actual daemon
        // and sending concurrent requests
        // For now, marked as ignored
    }

    #[test]
    #[ignore] // Performance test
    fn daemon_memory_under_100mb_idle() {
        // Would require starting daemon and measuring memory
        // For now, marked as ignored
    }
}
