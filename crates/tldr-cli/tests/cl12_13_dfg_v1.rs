//! cl12_13_dfg_v1 (v0.5.0 CL-12 + CL-13): DFG use-detection fixes (GH #77).
//!
//! Two systemic bugs in the per-function DFG use classifier
//! (`crates/tldr-core/src/dfg/extractor.rs`) and the dead-store detector
//! (`crates/tldr-cli/src/commands/contracts/dead_stores.rs`):
//!
//! CL-12 — non-variable identifiers recorded as variable reads, producing
//!   false `uninitialized` reports in `reaching-defs`. The most concrete
//!   instance owned by this cluster: Solidity treats `from` as a reserved
//!   keyword (`is_keyword`), so every read of a local/parameter named
//!   `from` is silently dropped. `from` is NOT a Solidity keyword — it is
//!   an ordinary identifier (the canonical ERC-20/721 `transferFrom(address
//!   from, ...)` parameter). Dropping its reads both hides real uses (CL-13)
//!   and, where `from` is the receiver of member access, used to misclassify.
//!
//! CL-13 — real uses missed, producing false `dead-stores`:
//!   * op-assign (`x += 1`, Ruby `operator_assignment`) records only an
//!     `Update` and no implicit `Use`, so a prior store `x = 0` looks dead
//!     even though `x += 1` reads it.
//!   * read-then-write `x = f(x)` records the `Use` of `x` on the SAME line
//!     as the new `Definition`; the dead-store "use between two defs" check
//!     used a strict `<` upper boundary, excluding that read and flagging the
//!     prior store dead.
//!
//! These tests are gated on the real corpora under /tmp/tldr_corpora so they
//! exercise the actual reported repos. They FAIL before the fix.

use std::path::Path;
use std::process::Command;

const SOLIDITY_ERC721: &str =
    "/tmp/tldr_corpora/solidity-openzeppelin/contracts/token/ERC721/ERC721.sol";
const RUBY_COMMENT_CONFIG: &str =
    "/tmp/tldr_corpora/ruby-rubocop/lib/rubocop/comment_config.rb";
const LUA_LOG: &str = "/tmp/tldr_corpora/lua-lsp/lua-lsp/log.lua";

fn tldr_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

fn reaching_defs(file: &str, func: &str) -> serde_json::Value {
    let (code, stdout, stderr) =
        run_tldr(&["reaching-defs", file, func, "--format", "json"]);
    assert_eq!(code, 0, "reaching-defs failed: {stdout} {stderr}");
    serde_json::from_str(&stdout).expect("reaching-defs emitted non-JSON")
}

fn dead_stores(file: &str, func: &str) -> serde_json::Value {
    let (code, stdout, stderr) =
        run_tldr(&["dead-stores", file, func, "--format", "json"]);
    assert_eq!(code, 0, "dead-stores failed: {stdout} {stderr}");
    serde_json::from_str(&stdout).expect("dead-stores emitted non-JSON")
}

fn uninit_vars(v: &serde_json::Value) -> Vec<String> {
    v.get("uninitialized")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("var").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// All distinct variable names flagged as dead stores (across both the SSA
/// and live-vars dead-store lists).
fn dead_store_vars(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["dead_stores_ssa", "dead_stores_live_vars"] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            for item in arr {
                if let Some(name) = item.get("variable").and_then(|s| s.as_str()) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

// =============================================================================
// CL-12: Solidity `from` is an identifier, not a keyword.
// =============================================================================

/// `transferFrom(address from, ...)` reads `from` on lines 144-145. After the
/// keyword removal those reads are recorded; the parameter definition reaches
/// them, so `from` must NOT be flagged uninitialized.
#[test]
fn solidity_from_param_not_uninitialized() {
    if !Path::new(SOLIDITY_ERC721).exists() {
        eprintln!("skipping: corpus not present at {SOLIDITY_ERC721}");
        return;
    }
    let v = reaching_defs(SOLIDITY_ERC721, "transferFrom");
    let names = uninit_vars(&v);
    assert!(
        !names.iter().any(|n| n == "from"),
        "Solidity 'from' parameter must not be uninitialized. Got: {names:?}"
    );
    // CL-12: `revert ERC721InvalidReceiver(...)` / `revert
    // ERC721IncorrectOwner(...)` name custom error TYPES, not local
    // variables — the `error` field of `revert_statement` must not be
    // classified as a use, so these must not appear as uninitialized.
    for err_name in ["ERC721InvalidReceiver", "ERC721IncorrectOwner"] {
        assert!(
            !names.iter().any(|n| n == err_name),
            "Solidity revert error name '{err_name}' must not be flagged \
             uninitialized. Got: {names:?}"
        );
    }
}

/// `_update` declares `address from = _ownerOf(tokenId)` and reads `from` on
/// several later lines. With `from` removed from the keyword list those reads
/// are recorded, so the `from` store must NOT be a dead store, and the read of
/// `from` must not be uninitialized.
#[test]
fn solidity_local_from_read_not_dead_and_not_uninit() {
    if !Path::new(SOLIDITY_ERC721).exists() {
        eprintln!("skipping: corpus not present at {SOLIDITY_ERC721}");
        return;
    }
    let rd = reaching_defs(SOLIDITY_ERC721, "_update");
    assert!(
        !uninit_vars(&rd).iter().any(|n| n == "from"),
        "Solidity local 'from' must not be uninitialized. Got: {:?}",
        uninit_vars(&rd)
    );
    let ds = dead_stores(SOLIDITY_ERC721, "_update");
    assert!(
        !dead_store_vars(&ds).iter().any(|n| n == "from"),
        "Solidity local 'from' is read later and must not be a dead store. Got: {:?}",
        dead_store_vars(&ds)
    );
}

// =============================================================================
// CL-13: op-assign implicit read must keep a prior store live.
// =============================================================================

/// Ruby `handle_enable_all`:
///   enabled_cops = 0      # line 233 (store)
///   enabled_cops += 1     # line 238 (reads + writes)
///   ... if enabled_cops.zero?  # line 241 (read)
/// The `+= 1` reads the value stored on line 233, so that store must NOT be a
/// dead store.
#[test]
fn ruby_op_assign_keeps_prior_store_live() {
    if !Path::new(RUBY_COMMENT_CONFIG).exists() {
        eprintln!("skipping: corpus not present at {RUBY_COMMENT_CONFIG}");
        return;
    }
    let ds = dead_stores(RUBY_COMMENT_CONFIG, "handle_enable_all");
    assert!(
        !dead_store_vars(&ds).iter().any(|n| n == "enabled_cops"),
        "Ruby 'enabled_cops = 0' is read by 'enabled_cops += 1' and must not be \
         a dead store. Got: {:?}",
        dead_store_vars(&ds)
    );
}

// =============================================================================
// CL-13: read-then-write x = f(x) must keep the prior store live.
// =============================================================================

/// Lua `log.fmt` contains read-then-write reassignments inside its gsub
/// closure:
///   local depth = input:match(...)   # line 43 (store)
///   depth = tonumber(depth)          # line 44 (reads old depth, writes new)
/// and
///   i, input = input:match(...)      # line 34 (store of i)
///   i = tonumber(i)                  # line 35 (reads old i, writes new)
/// The reads on lines 44/35 keep the stores on 43/34 live, so neither may be a
/// dead store.
#[test]
fn lua_read_then_write_keeps_prior_store_live() {
    if !Path::new(LUA_LOG).exists() {
        eprintln!("skipping: corpus not present at {LUA_LOG}");
        return;
    }
    let ds = dead_stores(LUA_LOG, "fmt");
    let dead = dead_store_vars(&ds);
    assert!(
        !dead.iter().any(|n| n == "depth"),
        "Lua 'local depth = ...' is read by 'depth = tonumber(depth)' and must \
         not be a dead store. Got: {dead:?}"
    );
    // The i store at line 34 (`i, input = input:match(...)`) is read by
    // `i = tonumber(i)` on line 35 — it must not be dead either.
    assert!(
        !ds.get("dead_stores_ssa")
            .and_then(|x| x.as_array())
            .map(|arr| arr.iter().any(|item| {
                item.get("variable").and_then(|s| s.as_str()) == Some("i")
                    && item.get("line").and_then(|l| l.as_u64()) == Some(34)
            }))
            .unwrap_or(false),
        "Lua 'i' store at line 34 is read by 'i = tonumber(i)' on line 35 and \
         must not be a dead store. Got: {ds}"
    );
}
