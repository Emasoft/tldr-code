//! PID-identity guard for watchdog kills (issue #55).
//!
//! The bugbot watchdogs signal a child by bare PID after a timeout. A PID is
//! only a name, not an identity: once the child has been reaped (or crashed in
//! a previous run), the kernel may recycle the PID for an unrelated process,
//! and a late-firing watchdog would then SIGKILL that innocent process. The
//! original code also kept sleeping for the FULL timeout after the child had
//! already exited, widening that reuse window to seconds.
//!
//! The guard closes this by verifying PID OWNERSHIP before every kill:
//!
//! 1. Right after spawning, the child's process start-time ("birth time") is
//!    captured — while the child is still OUR unreaped child, so its PID is
//!    held by the kernel and cannot yet be recycled (a zombie keeps its PID
//!    until `wait()` reaps it).
//! 2. When the watchdog fires, the CURRENT occupant of the PID is read and
//!    compared against the recorded birth time. Same birth time = the very
//!    same process we spawned → kill proceeds. Different birth time = the PID
//!    was recycled → the kill is skipped, no matter what. No readable process
//!    behind the PID → nothing to kill.
//! 3. If the platform provides no way to read a start time, the legacy
//!    unverified kill is preserved (Windows): documented residual risk, not a
//!    silent regression. If the reader exists but the baseline could not be
//!    captured, the kill is skipped (fail closed): a watchdog that fails to
//!    enforce a timeout merely lets a hung tool run to completion; a watchdog
//!    that kills an unrelated process destroys user work.
//!
//! The guard only ever signals the SINGLE verified PID — never a process
//! group, never a pid-range.
//!
//! Start-time sources (std + the already-vendored `libc`, no new deps):
//! - macOS: `proc_pidinfo(pid, PROC_PIDTBSDINFO, …)` → `pbi_start_tvsec` /
//!   `pbi_start_tvusec` (identity at microsecond resolution).
//! - Linux: `/proc/<pid>/stat` field 22 (`starttime`, clock ticks since boot),
//!   parsed AFTER the `comm` field which may itself contain spaces/parens.
//! - Anything else: `ProcSnapshot::Unknown`.

/// What the OS currently says lives behind a PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcSnapshot {
    /// A live (or unreaped-zombie) process with this start-time identity.
    Identity(u64),
    /// The reader works on this platform but found no process behind the PID
    /// (it exited / was reaped — or the read failed outright).
    NoProc,
    /// This platform has no start-time reader (e.g. Windows): verification is
    /// impossible, not merely failed.
    #[allow(dead_code)] // constructed only by the fallback reader on other OSes
    Unknown,
}

/// The identity of the child we spawned, captured right after `spawn()`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChildIdentity {
    pub(crate) pid: u32,
    pub(crate) start_time: ProcSnapshot,
}

impl ChildIdentity {
    /// Capture the start-time identity of `pid` (our just-spawned child).
    ///
    /// why immediately after spawn: the child is then still OUR unreaped
    /// child — alive or zombie — so the kernel holds the PID and the snapshot
    /// cannot accidentally belong to a recycled occupant.
    pub(crate) fn capture(pid: u32) -> Self {
        Self {
            pid,
            start_time: snapshot_start_time(pid),
        }
    }
}

/// Verdict of the ownership check performed right before a watchdog kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillDecision {
    /// The PID still carries the recorded identity: it IS our child — kill it.
    Kill,
    /// The PID now belongs to a DIFFERENT process (birth time mismatch): the
    /// PID was recycled — do not signal it.
    SkipReused,
    /// Nothing (readable) lives behind the PID any more — nothing to kill.
    SkipGone,
    /// Ownership cannot be established (no baseline despite a working
    /// reader) — fail closed, do not signal.
    SkipUnverifiable,
}

/// Pure ownership decision: should the watchdog signal the PID it recorded?
///
/// - Matching start times → [`KillDecision::Kill`] (same process generation).
/// - Mismatched start times → [`KillDecision::SkipReused`] (PID recycled).
/// - No current process → [`KillDecision::SkipGone`].
/// - Reader missing on BOTH sides (unsupported platform) → legacy
///   [`KillDecision::Kill`], preserving pre-#55 watchdog behaviour there.
/// - Everything else (half-verifiable) → [`KillDecision::SkipUnverifiable`]
///   (fail closed).
pub(crate) fn decide_kill(recorded: &ProcSnapshot, current: &ProcSnapshot) -> KillDecision {
    match (recorded, current) {
        (ProcSnapshot::Identity(recorded_st), ProcSnapshot::Identity(current_st)) => {
            if recorded_st == current_st {
                KillDecision::Kill
            } else {
                KillDecision::SkipReused
            }
        }
        // Platform cannot verify at all (e.g. Windows): keep the legacy
        // unverified kill rather than silently disabling timeout enforcement.
        (ProcSnapshot::Unknown, ProcSnapshot::Unknown) => KillDecision::Kill,
        (ProcSnapshot::Identity(_), ProcSnapshot::NoProc) => KillDecision::SkipGone,
        // Any other combination is only half-verifiable: refuse to signal.
        _ => KillDecision::SkipUnverifiable,
    }
}

/// Verify the PID still refers to the recorded child and, only then, kill it.
///
/// Returns the decision actually taken (kill performed iff `KillDecision::
/// Kill`). The verdict is meant for diagnostics: the caller's timeout handling
/// reports the timeout regardless of the kill outcome, exactly as before —
/// skipping a stale-PID kill is a safety improvement, not a timeout failure.
pub(crate) fn kill_if_still_child(identity: &ChildIdentity) -> KillDecision {
    let current = snapshot_start_time(identity.pid);
    let decision = decide_kill(&identity.start_time, &current);
    if decision == KillDecision::Kill {
        platform_kill(identity.pid);
    }
    decision
}

/// Read the CURRENT start-time identity behind `pid`.
#[cfg(target_os = "macos")]
pub(crate) fn snapshot_start_time(pid: u32) -> ProcSnapshot {
    use std::mem;

    unsafe {
        let mut info: libc::proc_bsdinfo = mem::zeroed();
        let ret = libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
            mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        );
        if ret <= 0 || (ret as usize) < mem::size_of::<libc::proc_bsdinfo>() {
            // No process behind the PID (or unreadable): nothing verifiable.
            return ProcSnapshot::NoProc;
        }
        // Microsecond-resolution birth time: two distinct processes that
        // started within the same second still carry different identities.
        ProcSnapshot::Identity(
            info.pbi_start_tvsec
                .wrapping_mul(1_000_000)
                .wrapping_add(info.pbi_start_tvusec % 1_000_000),
        )
    }
}

/// Linux: parse `/proc/<pid>/stat` field 22 (`starttime`).
#[cfg(target_os = "linux")]
pub(crate) fn snapshot_start_time(pid: u32) -> ProcSnapshot {
    match std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(stat) => match parse_stat_starttime(&stat) {
            Some(ticks) => ProcSnapshot::Identity(ticks),
            None => ProcSnapshot::NoProc,
        },
        // ESRCH / permissions: nothing verifiable behind the PID.
        Err(_) => ProcSnapshot::NoProc,
    }
}

/// Extract field 22 (`starttime`, clock ticks since boot) from a
/// `/proc/<pid>/stat` line. Field 2 (`comm`) may contain spaces and parens,
/// so everything up to the LAST `)` is skipped; after that, fields start at
/// `state` (field 3) — `starttime` (field 22) is therefore index 19.
#[cfg(target_os = "linux")]
fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse::<u64>().ok())
}

/// Platforms without a start-time reader (e.g. Windows): verification is
/// impossible — the decision falls back to the legacy unverified kill.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn snapshot_start_time(_pid: u32) -> ProcSnapshot {
    ProcSnapshot::Unknown
}

/// Platform kill primitive: SIGKILL on Unix, `TerminateProcess` on Windows.
///
/// Invariant enforced by the caller: this is only ever reached for a PID
/// whose start-time identity matched the recorded child.
fn platform_kill(pid: u32) {
    #[cfg(unix)]
    {
        // SAFETY: `kill(2)` with a valid signal number on a pid_t obtained
        // from `child.id()`; ownership re-verified by `kill_if_still_child`.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        // SAFETY: `OpenProcess`/`TerminateProcess` per WinAPI; handle closed
        // on every path. Ownership re-verified by `kill_if_still_child` where
        // the platform allows it.
        unsafe {
            let handle = windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_TERMINATE,
                0, // bInheritHandle = FALSE
                pid,
            );
            if handle != 0 {
                windows_sys::Win32::System::Threading::TerminateProcess(handle, 1);
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Unsupported platform: no kill primitive. The caller still reports
        // the timeout; the process keeps running.
        let _ = pid;
    }
}

/// How long a test-spawned helper child is given to die after a kill before
/// the test declares the kill ineffective.
#[cfg(test)]
pub(crate) const TEST_KILL_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Decision function — the pure heart of the guard (no OS interaction).
    // ---------------------------------------------------------------------

    /// Issue #55 core decision: recorded birth time ≠ current occupant's
    /// birth time ⇒ the PID was recycled ⇒ NO kill.
    #[test]
    fn mismatched_birth_time_is_skipped() {
        assert_eq!(
            decide_kill(
                &ProcSnapshot::Identity(1_000),
                &ProcSnapshot::Identity(2_000)
            ),
            KillDecision::SkipReused
        );
    }

    /// Same birth time ⇒ the very same process generation ⇒ kill proceeds.
    #[test]
    fn matching_birth_time_kills() {
        assert_eq!(
            decide_kill(&ProcSnapshot::Identity(7), &ProcSnapshot::Identity(7)),
            KillDecision::Kill
        );
    }

    /// No process behind the PID ⇒ nothing to kill.
    #[test]
    fn vanished_pid_is_skipped() {
        assert_eq!(
            decide_kill(&ProcSnapshot::Identity(7), &ProcSnapshot::NoProc),
            KillDecision::SkipGone
        );
    }

    /// Working reader but missing baseline (e.g. the spawn-time read failed)
    /// ⇒ fail closed: never signal a PID we cannot prove is ours.
    #[test]
    fn unverifiable_baseline_fails_closed() {
        assert_eq!(
            decide_kill(&ProcSnapshot::Unknown, &ProcSnapshot::Identity(7)),
            KillDecision::SkipUnverifiable
        );
        assert_eq!(
            decide_kill(&ProcSnapshot::NoProc, &ProcSnapshot::Identity(7)),
            KillDecision::SkipUnverifiable
        );
        assert_eq!(
            decide_kill(&ProcSnapshot::Unknown, &ProcSnapshot::NoProc),
            KillDecision::SkipUnverifiable
        );
    }

    /// Platform with NO reader at all (Windows): legacy unverified kill is
    /// preserved — a documented residual risk, not a silent regression.
    #[test]
    fn unsupported_platform_keeps_legacy_kill() {
        assert_eq!(
            decide_kill(&ProcSnapshot::Unknown, &ProcSnapshot::Unknown),
            KillDecision::Kill
        );
    }

    // ---------------------------------------------------------------------
    // Hazard shape with a LIVE process we control (never killed unless it is
    // our own freshly spawned child): a stale recorded identity pointing at
    // the same PID must NOT authorize a kill, even though a real process is
    // running there right now.
    // ---------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn stale_record_against_live_unrelated_process_is_not_killed() {
        // Stand in for "an unrelated process that now owns the recycled PID":
        // a live child WE spawned and can inspect, but whose recorded
        // identity we forge with a DIFFERENT (stale) birth time.
        let mut unrelated = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep helper");
        let pid = unrelated.id();

        let current = snapshot_start_time(pid);
        let stale_record = match current {
            ProcSnapshot::Identity(t) => ProcSnapshot::Identity(t.wrapping_add(1)),
            other => other,
        };

        let decision = decide_kill(&stale_record, &current);
        assert_eq!(decision, KillDecision::SkipReused);

        // The guard must also REFUSE to perform the kill for this record.
        let identity = ChildIdentity {
            pid,
            start_time: stale_record,
        };
        assert_eq!(kill_if_still_child(&identity), KillDecision::SkipReused);

        // The helper must still be alive — nothing signalled it.
        assert!(unrelated.try_wait().unwrap().is_none());
        // Terminate the helper deterministically (it is ours).
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    }

    // ---------------------------------------------------------------------
    // Fresh child → kill proceeds (end-to-end through the guarded kill).
    // ---------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn fresh_child_identity_matches_and_kill_proceeds() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep helper");
        let pid = child.id();

        // Capture exactly like the watchdog does, right after spawn.
        let identity = ChildIdentity::capture(pid);
        assert_eq!(
            identity.start_time,
            snapshot_start_time(pid),
            "birth time of a live child must be stable between reads"
        );
        assert_eq!(
            decide_kill(&identity.start_time, &snapshot_start_time(pid)),
            KillDecision::Kill,
            "a fresh child must be verified as our own and killed"
        );

        // End-to-end: the guarded kill must actually terminate our child.
        assert_eq!(kill_if_still_child(&identity), KillDecision::Kill);

        let deadline = std::time::Instant::now() + TEST_KILL_WAIT;
        loop {
            match child.try_wait().expect("wait on own child") {
                Some(_status) => break, // killed and reaped
                None => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "guarded kill did not terminate the fresh child"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Platform readers against a process we KNOW exists (this test process
    // itself) — read-only, nothing is signalled.
    // ---------------------------------------------------------------------

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn reader_sees_own_live_process() {
        let me = std::process::id();
        assert_eq!(
            snapshot_start_time(me),
            ChildIdentity::capture(me).start_time,
            "two reads of a live process must yield the same identity"
        );
    }

    /// Linux parser: `comm` with spaces and parentheses must not skew the
    /// field index; field 22 must come out exactly.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stat_parser_survives_weird_comm() {
        // Synthetic /proc/<pid>/stat line: pid (comm-with-spaces-and-parens)
        // followed by 50 fields where field 22 (starttime) = 4242. After the
        // last ')', fields[0] is `state` (field 3), so starttime sits at
        // index 19. Fields: S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 ...
        let stat = "1234 (my (weird) comm) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50";
        assert_eq!(parse_stat_starttime(stat), Some(4242));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stat_parser_rejects_garbage() {
        assert_eq!(parse_stat_starttime("no parens here"), None);
        assert_eq!(parse_stat_starttime("1 (comm) S not-a-number"), None);
    }
}
