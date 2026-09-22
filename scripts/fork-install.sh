#!/bin/sh
# tldr fork installer — installs precompiled tldr / tldr-daemon / tldr-mcp.
#
# This is the committed TEMPLATE. The fork-release workflow
# (.github/workflows/fork-release.yml) bakes the concrete tag into the
# TAG_DEFAULT= line below (single anchored sed) and publishes the result as
# `tldr-cli-installer.sh`, matching the README one-liner:
#   curl --proto '=https' --tlsv1.2 -LsSf \
#     https://github.com/Emasoft/tldr-code/releases/download/<tag>/tldr-cli-installer.sh | sh
#
# Environment overrides (all optional):
#   TLDR_INSTALL_TAG        release tag to install   (default: baked-in release tag)
#   TLDR_INSTALL_URL_BASE   download base URL        (default: .../releases/download/$TAG;
#                           set to file:///path for local testing)
#   TLDR_INSTALL_DIR        install directory        (default: ${CARGO_HOME:-$HOME/.cargo}/bin)
#   TLDR_INSTALL_SKILLS_DIR agent skill install dir  (default: $HOME/.agents/skills — the
#                           universal root the Vercel skills CLI uses, so existing
#                           per-agent symlinks keep working)
#   TLDR_INSTALL_NO_SKILL   set to 1 to skip the agent skill install entirely
#
# The binaries are the primary payload: if the skill bundle cannot be downloaded
# or its checksum does not match, the installer prints a WARNING and finishes
# with the binaries installed (a partial release must not fail the whole
# install). The skill bundle itself (`tldr-skill-<tag>.tar.gz`, sha256-verified)
# extracts to <skills-dir>/tldr-code and <skills-dir>/tldr-scan-workflow.
#
# Platforms: macOS arm64/x86_64, Linux arm64/x86_64.
# Windows is NOT installed by this script: download
# tldr-fork-<tag>-x86_64-pc-windows-msvc.zip from the release page, extract,
# and put the three .exe files on PATH.
set -eu

TAG_DEFAULT="__FORK_RELEASE_TAG__" # ONLY this line is sed-replaced by the release workflow

err() {
    printf 'fork-install: error: %s\n' "$1" >&2
    exit 1
}

info() {
    printf 'fork-install: %s\n' "$1"
}

warn() {
    printf 'fork-install: WARNING: %s\n' "$1" >&2
}

# ---------------------------------------------------------------- tag + base
# Effective tag: explicit TLDR_INSTALL_TAG wins; otherwise the default the
# release workflow bakes in. The workflow seds ONLY the TAG_DEFAULT= line
# (anchored), never the guard literal below — so a user override equal to the
# baked tag remains valid and never trips the guard.
TAG="${TLDR_INSTALL_TAG:-$TAG_DEFAULT}"
if [ "$TAG" = "__FORK_RELEASE_TAG__" ]; then
    err "release tag not baked in and TLDR_INSTALL_TAG not set — this is the template; run the fork-release workflow (or set TLDR_INSTALL_TAG, e.g. TLDR_INSTALL_TAG=v0.4.1-fork.1)"
fi

BASE="${TLDR_INSTALL_URL_BASE:-https://github.com/Emasoft/tldr-code/releases/download/$TAG}"
BASE="${BASE%/}" # tolerate trailing slash

# ------------------------------------------------------------- platform map
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64 | aarch64) TARGET="aarch64-apple-darwin" ;;
            x86_64) TARGET="x86_64-apple-darwin" ;;
            *) err "unsupported macOS architecture: $ARCH (need arm64 or x86_64)" ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            arm64 | aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            x86_64 | amd64) TARGET="x86_64-unknown-linux-gnu" ;;
            *) err "unsupported Linux architecture: $ARCH (need arm64 or x86_64)" ;;
        esac
        ;;
    MINGW* | MSYS* | CYGWIN*)
        err "this shell installer does not support Windows ($OS). Download tldr-fork-$TAG-x86_64-pc-windows-msvc.zip from https://github.com/Emasoft/tldr-code/releases/tag/$TAG , extract it, and put tldr.exe / tldr-daemon.exe / tldr-mcp.exe on your PATH."
        ;;
    *)
        err "unsupported operating system: $OS (supported: Darwin, Linux)"
        ;;
esac

TARBALL="tldr-fork-$TAG-$TARGET.tar.gz"
INSTALL_DIR="${TLDR_INSTALL_DIR:-${CARGO_HOME:-$HOME/.cargo}/bin}"

info "tag:      $TAG"
info "target:   $TARGET"
info "install:  $INSTALL_DIR"

# ---------------------------------------------------------------- downloader
fetch() {
    # fetch <url> <dest-file> — https-pinned for network URLs; file:// allowed
    # (TLS pinning is meaningless there) so TLDR_INSTALL_URL_BASE=file://... works.
    if command -v curl >/dev/null 2>&1; then
        case "$1" in
            file://*) curl -fSL -o "$2" "$1" || err "download failed: $1" ;;
            *) curl --proto '=https' --tlsv1.2 -fSL -o "$2" "$1" || err "download failed: $1" ;;
        esac
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1" || err "download failed: $1"
    else
        err "neither curl nor wget found — install one and retry"
    fi
}

# fetch_soft <url> <dest-file> — like fetch but RETURNS non-zero instead of
# exiting. Used for the optional skill bundle: a missing/partial release must
# not abort an install whose binaries already came through.
fetch_soft() {
    if command -v curl >/dev/null 2>&1; then
        case "$1" in
            file://*) curl -fSL -o "$2" "$1" ;;
            *) curl --proto '=https' --tlsv1.2 -fSL -o "$2" "$1" ;;
        esac
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        return 1
    fi
}

TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT INT TERM

fetch "$BASE/$TARBALL" "$TMPDIR_DL/$TARBALL"
fetch "$BASE/$TARBALL.sha256" "$TMPDIR_DL/$TARBALL.sha256"

# ------------------------------------------------------------ sha256 verify
cd "$TMPDIR_DL"
if command -v sha256sum >/dev/null 2>&1; then
    SUM="sha256sum"
else
    SUM="shasum -a 256"
fi
if ! $SUM -c "$TARBALL.sha256" >/dev/null 2>&1; then
    $SUM -c "$TARBALL.sha256" || true # show the failing line(s)
    err "sha256 checksum mismatch for $TARBALL — download is corrupted or tampered with (expected hash from $TARBALL.sha256)"
fi
info "checksum OK: $TARBALL"

# ------------------------------------------------------------- install bins
tar -xzf "$TARBALL"
mkdir -p "$INSTALL_DIR"
for bin in tldr tldr-daemon tldr-mcp; do
    [ -f "$bin" ] || err "archive did not contain expected binary: $bin"
    install -m 0755 "$bin" "$INSTALL_DIR/$bin"
done

# --------------------------------------------------------------- verify run
info "running $INSTALL_DIR/tldr --version"
"$INSTALL_DIR/tldr" --version || err "installed binary failed to execute"

info "installed tldr, tldr-daemon, tldr-mcp to: $INSTALL_DIR"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        info "NOTE: $INSTALL_DIR is not on your PATH. Add it with:"
        info "      export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac

# ---------------------------------------------------------------- agent skill
# Installs the tldr-code + tldr-scan-workflow agent skills from the same
# release. Optional on every axis: TLDR_INSTALL_NO_SKILL=1 skips it, a failed
# download or a checksum mismatch is a WARNING (never a failed install — the
# binaries above are the primary payload and are already in place).
SKILLS_DIR="${TLDR_INSTALL_SKILLS_DIR:-$HOME/.agents/skills}"
SKILL_BUNDLE="tldr-skill-$TAG.tar.gz"

if [ "${TLDR_INSTALL_NO_SKILL:-0}" = "1" ]; then
    info "TLDR_INSTALL_NO_SKILL=1 — skipping agent skill install"
elif fetch_soft "$BASE/$SKILL_BUNDLE" "$TMPDIR_DL/$SKILL_BUNDLE" &&
    fetch_soft "$BASE/$SKILL_BUNDLE.sha256" "$TMPDIR_DL/$SKILL_BUNDLE.sha256"; then
    if (cd "$TMPDIR_DL" && $SUM -c "$SKILL_BUNDLE.sha256" >/dev/null 2>&1); then
        mkdir -p "$SKILLS_DIR"
        if tar -xzf "$TMPDIR_DL/$SKILL_BUNDLE" -C "$SKILLS_DIR" &&
            [ -f "$SKILLS_DIR/tldr-code/SKILL.md" ] &&
            [ -f "$SKILLS_DIR/tldr-scan-workflow/SKILL.md" ]; then
            info "checksum OK: $SKILL_BUNDLE"
            info "installed agent skills (tldr-code, tldr-scan-workflow) to: $SKILLS_DIR"
            info "NOTE: per-agent symlinks for the skills can be managed with: npx skills add -g -y --all"
        else
            warn "skill bundle did not extract the expected skill directories into $SKILLS_DIR — skipping (binaries are unaffected)"
        fi
    else
        (cd "$TMPDIR_DL" && $SUM -c "$SKILL_BUNDLE.sha256") || true # show the failing line(s)
        warn "sha256 checksum mismatch for $SKILL_BUNDLE — skipping skill install (binaries are unaffected; expected hash from $SKILL_BUNDLE.sha256)"
    fi
else
    warn "could not download $SKILL_BUNDLE from $BASE — skipping skill install (binaries are the primary payload and are already installed)"
fi

info "done"
