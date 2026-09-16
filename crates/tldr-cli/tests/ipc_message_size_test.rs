//! M1 VAL-001 — IPC message-size enforcement (#17 + #25)
//!
//! `IpcStream::recv_raw` must reject oversized messages BEFORE allocating
//! the full payload into memory. Without the fix, a no-newline payload of
//! 100 MB+ either OOMs the daemon or never returns until the OS kills it.
//!
//! RED on HEAD 10f00a9: `oversized_payload_no_newline_rejected_within_5s`
//! either OOMs the test runner or the 5s server-completion timeout fires.
//! GREEN: `recv_raw` returns `Err(InvalidMessage)` in well under 5s; daemon
//! stays alive.

#![cfg(unix)]

use std::time::Duration;

use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::timeout;

use tldr_cli::commands::daemon::ipc::{compute_socket_path, IpcListener, MAX_MESSAGE_SIZE};

async fn start_listener(tmp: &TempDir) -> (IpcListener, std::path::PathBuf) {
    let project = tmp.path();
    let listener = IpcListener::bind(project)
        .await
        .expect("bind should succeed");
    let socket_path = compute_socket_path(project);
    (listener, socket_path)
}

/// RED (#17 + #25): 100 MB no-newline write — server must reject in < 5s without OOM.
///
/// Pre-fix behaviour: `BufReader::read_line` allocates the full 100 MB into a
/// `String` and the post-allocation size check never fires (no newline → keeps
/// reading), so the server task never completes and the 5s `timeout(...)`
/// guard fires `Err(Elapsed)` → `expect("server must complete within 5s ...")`
/// panics. Post-fix: `recv_raw_from` wraps the stream with
/// `AsyncReadExt::take(MAX_MESSAGE_SIZE + 1)` which signals EOF after the
/// limit, and `read_line` returns without finding `\n` → `Err(InvalidMessage)`.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_payload_no_newline_rejected_within_5s() {
    let tmp = TempDir::new().unwrap();
    let (listener, socket_path) = start_listener(&tmp).await;

    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept");
        stream.recv_raw().await
    });

    let client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
        // 100 MB payload, no newline.
        let chunk = vec![b'x'; 100 * 1024 * 1024];
        let _ = stream.write_all(&chunk).await;
    });

    let server_result = timeout(Duration::from_secs(5), server)
        .await
        .expect("server must complete within 5s — if it times out the bug is NOT fixed")
        .expect("server task should not panic");

    assert!(
        server_result.is_err(),
        "recv_raw must reject oversized message; got Ok(_)"
    );
    let err_str = format!("{:?}", server_result.unwrap_err());
    assert!(
        err_str.contains("size") || err_str.contains("large") || err_str.contains("limit"),
        "Error should mention size limit, got: {}",
        err_str
    );

    let _ = client.await;
}

/// Edge: exactly `MAX_MESSAGE_SIZE` bytes followed by `\n` is accepted.
///
/// The implementation uses `take(MAX_MESSAGE_SIZE + 1)` so reading exactly
/// `MAX_MESSAGE_SIZE` payload bytes plus the newline is still within budget.
#[tokio::test(flavor = "multi_thread")]
async fn exact_max_size_with_newline_succeeds() {
    let tmp = TempDir::new().unwrap();
    let (listener, socket_path) = start_listener(&tmp).await;

    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept");
        stream.recv_raw().await
    });

    let client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
        let mut msg = vec![b'x'; MAX_MESSAGE_SIZE];
        msg.push(b'\n');
        stream.write_all(&msg).await.expect("write");
    });

    let result = timeout(Duration::from_secs(15), server)
        .await
        .expect("server must complete within 15s for at-limit message")
        .expect("server task should not panic");

    let payload = result.expect("exactly-limit message should be accepted");
    assert_eq!(payload.len(), MAX_MESSAGE_SIZE);
    let _ = client.await;
}

/// Just over the limit (`MAX_MESSAGE_SIZE + 1` bytes followed by `\n`)
/// must be rejected. With the `take(MAX_MESSAGE_SIZE + 1)` adapter, the
/// limited reader hits EOF before consuming the newline, so `read_line`
/// returns a buffer that does not end in `\n` → `Err(InvalidMessage)`.
#[tokio::test(flavor = "multi_thread")]
async fn over_max_size_with_newline_rejected() {
    let tmp = TempDir::new().unwrap();
    let (listener, socket_path) = start_listener(&tmp).await;

    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept");
        stream.recv_raw().await
    });

    let client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
        let mut msg = vec![b'x'; MAX_MESSAGE_SIZE + 1];
        msg.push(b'\n');
        let _ = stream.write_all(&msg).await;
    });

    let server_result = timeout(Duration::from_secs(15), server)
        .await
        .expect("server must complete within 15s")
        .expect("server task should not panic");

    assert!(
        server_result.is_err(),
        "MAX_MESSAGE_SIZE + 1 with newline must be rejected; got Ok(_)"
    );
    let err_str = format!("{:?}", server_result.unwrap_err());
    assert!(
        err_str.contains("size") || err_str.contains("large") || err_str.contains("limit"),
        "Error should mention size limit, got: {}",
        err_str
    );
    let _ = client.await;
}
