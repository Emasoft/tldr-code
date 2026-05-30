# Security Policy

This document describes the security posture of `tldr` (the v2 Rust
implementation), the threat model the tool is designed under, the
known issues that have been triaged but not yet code-fixed, and the
process for reporting new vulnerabilities.

## Threat Model

`tldr` is a **single-user, local-only, opt-in** code analysis tool.
The intended deployment is:

1. **Single trust boundary.** The user running `tldr` is the same user
   who owns the source code being analyzed and the same user who owns
   the host machine. There is no multi-tenant mode.
2. **Local-only daemon by default.** The optional `tldr daemon` binds
   to a UNIX domain socket under `$TMPDIR` (Unix) or a loopback TCP
   port in the dynamic range (Windows). It does **not** listen on a
   network interface in any default configuration. Exposing the daemon
   beyond `localhost` is **unsupported**.
3. **Opt-in network access.** The only commands that touch the network
   are the embedding/semantic search features (downloading model
   weights on first use), and they require an explicit feature flag
   and user invocation. There is no auto-telemetry.
4. **No code execution from analyzed sources.** `tldr` parses source
   code with tree-sitter; it never `exec`s, imports, or otherwise
   interprets the code it analyzes. Hostile source code being parsed
   is in scope only insofar as parser bugs are concerned.

What is **out of scope**:

- Defending against an attacker who already has local code execution
  as the user running `tldr`. Such an attacker has already won.
- Defending against a malicious filesystem mounted at `$TMPDIR` where
  the attacker can change the type of a path between `stat` and
  `open` faster than the kernel can serialize the calls. The
  mitigations we apply (`O_NOFOLLOW`, `lstat` + typed errors) close
  the common cases; a determined kernel-race attacker is not in
  scope.
- Network-exposed deployments of `tldr daemon`. See issue #37.

## Known Issues

Issues that have been triaged and either fixed or documented as
out-of-scope. Cross-reference these with the GitHub issue tracker.

### #37 — Daemon `/smells` endpoint path traversal (documentation-only)

**Status:** Mitigation is the default posture; no code fix planned.

The daemon's `/smells?files=<path>` endpoint accepts arbitrary
filesystem paths and will return analysis of files outside the
project root. In a localhost-only deployment this is not a
vulnerability — the daemon is reading files that the same user can
already `cat`. **If you expose the daemon on a network interface,
you have escaped the supported configuration.**

The mitigation is the threat model itself: the daemon is designed
for `localhost`-only operation, and the default configuration
enforces that. If you have a use case that requires network
exposure, please open an issue describing it and we will discuss
adding path-canonicalization-based root-jail enforcement as an
opt-in mode.

### #52 — Daemon PID file symlink-following (fixed in M-115, v0.4.2)

**Status:** Fixed.

The daemon's PID file management (`pid.rs`) opened the PID path
with `std::fs::File::open` / `std::fs::read_to_string`, both of
which silently follow symlinks. An attacker with write access to
`$TMPDIR` (e.g. another user on a shared machine, or any process
running as the same user that could plant a symlink) could
redirect the daemon's truncate+write to an arbitrary
victim-writable file.

**Fix:** open the PID file with `O_NOFOLLOW`, and `lstat` the
path before reading. Symlinked PID paths surface as
`DaemonError::PidSymlink { path }` and refuse to proceed.
Regression covered by
`crates/tldr-cli/tests/m115_security_v1.rs::issue_52_pid_symlink_rejected`.

### #56 — Secrets scanner missed alphanumeric high-entropy strings (fixed in M-115, v0.4.2)

**Status:** Fixed.

`tldr secrets` ran a Shannon-entropy filter on extracted quoted
strings and then ran each high-entropy candidate through a
"likely false positive" filter. One of the filter regexes was
`^[A-Za-z0-9+/]+=*$` — nominally a base64 character-class check,
but with `=*` (zero or more padding chars) it accepted every
pure-alphanumeric string. A 40-char alphanumeric API key with
entropy > 4.5 bits/char was therefore suppressed.

**Fix:** tighten the regex to `^[A-Za-z0-9+/]+=+$` (require at
least one `=` of padding, which is the actual signal that the
string is a base64-encoded asset blob and not a secret).
Hex-only strings of 32+ chars are still suppressed as likely
hashes. Regression covered by
`crates/tldr-cli/tests/m115_security_v1.rs::issue_56_alphanumeric_high_entropy_detected`.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in `tldr`,
please **do not open a public GitHub issue**. Instead:

1. **Preferred:** open a [private security advisory on the
   repository](https://github.com/saqlainmohammed97/tldr-rs/security/advisories/new).
   GitHub's advisory workflow keeps the report off the public issue
   tracker until a fix is ready.
2. **Alternative:** send an email to the project maintainer. Look up
   the maintainer's email via `git log --pretty=format:"%ae" | head -1`
   on the repository.

Please include:

- A description of the vulnerability and the affected commands /
  modules.
- A reproduction (a minimal command line or fixture file is best).
- Your assessment of the severity (CVSS or qualitative).
- Whether you intend to disclose publicly, and on what timeline.

We aim to acknowledge security reports within **7 days** and to
ship a fix within **30 days** for any issue rated MEDIUM or higher
on CVSS. LOW-severity issues are batched into the next quality
release.

## Disclosure Timeline Convention

- Day 0: vulnerability reported.
- Day 7: acknowledgement and initial triage.
- Day 30: fix landed on `main` (target).
- Day 30 + release cycle: fix shipped in a tagged release.
- Day 30 + 14: public disclosure (advisory published).

If a fix is genuinely not feasible within 30 days, we will say so
in the acknowledgement and propose a revised timeline.

## Cryptographic Hygiene

`tldr` does not perform cryptographic operations as part of its
core analysis. The MD5 hashes used in `pid.rs::compute_hash` are
project-identity tokens (used to name PID/socket files
deterministically per project), not security primitives, and are
not collision-attack-sensitive in the supported single-user
threat model.
