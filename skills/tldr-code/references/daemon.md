# Daemon Commands

Daemon commands manage the persistent cache daemon for faster repeated queries.

## daemon

**Purpose:** Daemon management commands.

**Implementation:** `crates/tldr-cli/src/commands/daemon/`

**Subcommands:**

### daemon start

Start the TLDR daemon for caching.

```bash
tldr daemon start

# With custom project
tldr daemon start --project /path/to/project

# Stay in the foreground (no daemonizing)
tldr daemon start --foreground
```

Flags: `-p/--project <PROJECT>` (default: current directory) and `--foreground` (run in the foreground instead of daemonizing). There are no `--tcp`, `--port`, or `--idle-timeout` flags: on Windows (or wherever Unix sockets are unavailable) the daemon automatically falls back to TCP on `127.0.0.1:<port>` with a hash-derived port (`49152 + hash % 10000`), and the idle timeout is fixed (default 300 s), not user-configurable.

**How it works:**
1. Creates a Unix domain socket at `<system-temp-dir>/tldr-{md5-8hex}-v{version}.sock` — the hash is the first 8 hex chars of the MD5 of the canonicalized project path and the version is the binary version (e.g. `/tmp/tldr-1a2b3c4d-v0.4.1.sock`). Override the socket directory with `TLDR_SOCKET_DIR` (`crates/tldr-daemon/src/server.rs:49-71`).
2. Starts HTTP server on socket
3. Background process caches analysis results

### daemon stop

Stop the running daemon.

```bash
tldr daemon stop
```

### daemon status

Check if daemon is running.

```bash
tldr daemon status
```

### daemon query

Send raw query to daemon.

```bash
tldr daemon query '{"cmd":"stats"}'
```

### daemon notify

Notify daemon of file changes (invalidates cache).

```bash
tldr daemon notify src/main.py
tldr daemon notify src/
```

### daemon list

List all running daemons (multi-daemon registry, v0.3.0).

```bash
tldr daemon list
```

### daemon log

Read the daemon's persistent JSONL request log (`.tldr/cache/daemon.log`) with tail/filter options.

```bash
tldr daemon log

# Last 50 entries (after filtering; 0 = all entries; default 100)
tldr daemon log --tail 50

# Only entries of a given event type
# (case-insensitive: request|response|lifecycle|slow|fallback|error)
tldr daemon log --event error

# Only entries for one command (case-insensitive), e.g. extract or ping
tldr daemon log --command extract

# Emit a JSON array even under --format text
tldr daemon log --json
```

`-p/--project <PROJECT>` defaults to the current directory, or to the running daemon's project when exactly one daemon is live.

---

## cache

**Purpose:** Cache management commands.

### cache stats

Show cache statistics.

```bash
tldr cache stats
```

### cache clear

Clear all cache files. Gracefully stops the project's daemon first — the daemon is left stopped; restart it with `tldr daemon start`.

```bash
tldr cache clear
```

---

## warm

**Alias:** `w`

**Purpose:** Pre-warm call graph cache for faster subsequent queries.

**Implementation:** `crates/tldr-cli/src/commands/daemon/warm.rs`

```bash
tldr warm src/

# Background warming
tldr warm src/ -b
```

**How it works:**
1. Builds call graph in background
2. Caches results in daemon memory
3. Subsequent IPC-served queries can reuse the warm index

**Measured reality (re-verified on this checkout, 0.4.1-fork.1):** warming gave **no measurable speedup** — `tldr structure` over the same tree took ~10 s cold and 11–13 s warm, many queries (`structure`, `search`, `semantic`) never route through the daemon, and it did not help `explain` either (the cost there is the graph computation, not a cold cache). The daemon is an index-reuse optimization whose payoff depends on repo size and query volume: it can pay off for repeated IPC-served queries, so **measure before assuming it helps** rather than starting it reflexively. It never hurts correctness — it just may not pay off.

---

## stats

**Purpose:** Show TLDR usage statistics.

```bash
tldr stats
```

Shows:
- Total queries run
- Cache hit rate
- Average query time
- Most used commands
