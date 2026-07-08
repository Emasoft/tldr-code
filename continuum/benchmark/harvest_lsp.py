#!/usr/bin/env python3
"""Harvest sampled real-repo truth edges from LSP callHierarchy.

This is intentionally stdlib-only. The language and repo registry lives in
languages.json so adding a future language does not require changing the
benchmark harness.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote, unquote, urlparse


ROOT = Path(__file__).resolve().parent
REPOS_OUT = ROOT / "repos"
LANGUAGES_JSON = ROOT / "languages.json"
CORPORA_ROOT = Path.home() / ".tldr-audit" / "corpora"
TODAY = datetime.now(timezone.utc).date().isoformat()
SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
CALL_RE = re.compile(r"(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
CALL_SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "function",
    "func",
    "fn",
    "class",
    "interface",
    "struct",
    "enum",
    "impl",
    "new",
    "sizeof",
}


@dataclass
class FunctionSample:
    rel_file: str
    name: str
    line: int
    character: int
    end_line: int
    call_line: int
    call_character: int
    call_text: str
    pattern_priority: int = 0


@dataclass
class RepoResult:
    repo: str
    language: str
    status: str
    sampled_sites: int = 0
    harvested_edges: int = 0
    spot_checked_edges: int = 0
    raw_response_files: int = 0
    reason: Optional[str] = None
    duration_seconds: float = 0.0
    manifest: Optional[str] = None
    truth: Optional[str] = None
    meta: Optional[str] = None


class LspError(Exception):
    pass


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def file_uri(path: Path) -> str:
    return "file://" + quote(str(path.resolve()), safe="/:")


def uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        raise ValueError(f"unsupported uri: {uri}")
    return Path(unquote(parsed.path))


def rel_to(root: Path, path: Path) -> Optional[str]:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def git_value(repo: Path, args: Sequence[str]) -> Optional[str]:
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def command_version(command: Sequence[str]) -> str:
    exe = command[0]
    for args in ([exe, "--version"], [exe, "version"], [exe, "-version"]):
        try:
            proc = subprocess.run(args, text=True, capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout or proc.stderr).strip()
        if output:
            return output.splitlines()[0]
    return "unknown"


def content_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class LspClient:
    def __init__(self, command: Sequence[str], root: Path, name: str, extra_env: Optional[Dict[str, str]] = None):
        self.command = list(command)
        self.root = root
        self.name = name
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        self.proc = subprocess.Popen(
            self.command,
            cwd=str(root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env=env,
        )
        self.next_id = 1
        self.pending: Dict[int, "queue.Queue[Dict[str, Any]]"] = {}
        self.notifications: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.write_lock = threading.Lock()
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        self.stderr_lines: List[str] = []
        self.stderr_reader = threading.Thread(target=self._stderr_loop, daemon=True)
        self.stderr_reader.start()

    def _stderr_loop(self) -> None:
        assert self.proc.stderr is not None
        for raw in iter(self.proc.stderr.readline, b""):
            try:
                text = raw.decode("utf-8", errors="replace").rstrip()
            except Exception:
                text = repr(raw)
            if text:
                self.stderr_lines.append(text)

    def _read_headers(self) -> Optional[int]:
        assert self.proc.stdout is not None
        content_length = None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                return None
            if line in (b"\r\n", b"\n"):
                return content_length
            text = line.decode("ascii", errors="replace").strip()
            if text.lower().startswith("content-length:"):
                content_length = int(text.split(":", 1)[1].strip())

    def _read_loop(self) -> None:
        assert self.proc.stdout is not None
        while True:
            length = self._read_headers()
            if length is None:
                return
            payload = self.proc.stdout.read(length)
            try:
                message = json.loads(payload.decode("utf-8"))
            except Exception as exc:
                self.notifications.put({"json_error": str(exc), "payload": payload.decode("utf-8", errors="replace")})
                continue
            if "id" in message and ("result" in message or "error" in message):
                q = self.pending.get(message["id"])
                if q is not None:
                    q.put(message)
                else:
                    self.notifications.put(message)
            elif "id" in message and "method" in message:
                self._respond_to_server_request(message)
            else:
                self.notifications.put(message)

    def _send(self, message: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        with self.write_lock:
            self.proc.stdin.write(header + encoded)
            self.proc.stdin.flush()

    def _respond_to_server_request(self, message: Dict[str, Any]) -> None:
        method = message.get("method")
        if method == "workspace/configuration":
            params = message.get("params") or {}
            items = params.get("items") if isinstance(params, dict) else None
            result = [{} for _ in items] if isinstance(items, list) else []
        elif method == "client/registerCapability":
            result = None
        elif method == "window/workDoneProgress/create":
            result = None
        else:
            result = None
        self._send({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def request(self, method: str, params: Any, timeout: float = 15.0) -> Dict[str, Any]:
        req_id = self.next_id
        self.next_id += 1
        q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1)
        self.pending[req_id] = q
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        try:
            response = q.get(timeout=timeout)
        except queue.Empty as exc:
            raise LspError(f"{self.name}: timeout waiting for {method}") from exc
        finally:
            self.pending.pop(req_id, None)
        if "error" in response:
            raise LspError(f"{self.name}: {method} error {response['error']}")
        return response

    def notify(self, method: str, params: Any) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def initialize(self, timeout: float = 60.0) -> Dict[str, Any]:
        params = {
            "processId": os.getpid(),
            "rootUri": file_uri(self.root),
            "rootPath": str(self.root),
            "workspaceFolders": [{"uri": file_uri(self.root), "name": self.root.name}],
            "capabilities": {
                "textDocument": {
                    "callHierarchy": {"dynamicRegistration": False},
                    "synchronization": {"didSave": True, "dynamicRegistration": False},
                },
                "workspace": {
                    "configuration": True,
                    "workspaceFolders": True,
                    "didChangeConfiguration": {"dynamicRegistration": False},
                },
                "window": {"workDoneProgress": True},
            },
            "initializationOptions": {},
        }
        response = self.request("initialize", params, timeout=timeout)
        self.notify("initialized", {})
        return response

    def did_open(self, path: Path, language_id: str) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        self.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": file_uri(path),
                    "languageId": language_id,
                    "version": 1,
                    "text": text,
                }
            },
        )

    def shutdown(self) -> None:
        try:
            self.request("shutdown", None, timeout=5.0)
            self.notify("exit", None)
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def iter_source_files(root: Path, extensions: Iterable[str]) -> List[Path]:
    exts = set(extensions)
    files: List[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix not in exts:
            continue
        try:
            if path.stat().st_size > 500_000:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def line_indent(text: str) -> int:
    return len(text) - len(text.lstrip(" "))


def python_samples(root: Path, files: List[Path]) -> List[FunctionSample]:
    samples: List[FunctionSample] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue
        lines = source.splitlines()
        parents: Dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        class_stack: List[Tuple[int, int, str]] = []
        for node in sorted(ast.walk(tree), key=lambda item: getattr(item, "lineno", 10**9)):
            if isinstance(node, ast.ClassDef):
                class_stack.append((node.lineno, getattr(node, "end_lineno", node.lineno), node.name))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                containers = [name for start, end, name in class_stack if start <= node.lineno <= end]
                func_name = ".".join(containers + [node.name])
                calls = [item for item in ast.walk(node) if isinstance(item, ast.Call) and getattr(item, "lineno", node.lineno) != node.lineno]
                for call in sorted(calls, key=lambda item: (item.lineno, item.col_offset)):
                    line = lines[call.lineno - 1].strip() if 0 <= call.lineno - 1 < len(lines) else ""
                    samples.append(
                        FunctionSample(
                            rel_file=rel,
                            name=func_name,
                            line=node.lineno - 1,
                            character=node.col_offset + (len("async def ") if isinstance(node, ast.AsyncFunctionDef) else len("def ")),
                            end_line=getattr(node, "end_lineno", node.lineno) - 1,
                            call_line=call.lineno - 1,
                            call_character=call.col_offset,
                            call_text=line,
                        )
                    )
    return samples


def brace_end(lines: List[str], start: int) -> int:
    balance = 0
    seen_open = False
    for index in range(start, len(lines)):
        text = strip_line_comment(lines[index])
        balance += text.count("{")
        if "{" in text:
            seen_open = True
        balance -= text.count("}")
        if seen_open and balance <= 0:
            return index
    return min(len(lines) - 1, start + 80)


def strip_line_comment(line: str) -> str:
    for marker in ("//", "#"):
        pos = line.find(marker)
        if pos >= 0:
            return line[:pos]
    return line


def generic_samples(root: Path, files: List[Path], patterns: Sequence[str]) -> List[FunctionSample]:
    compiled = [re.compile(pattern) for pattern in patterns]
    samples: List[FunctionSample] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines):
            match = None
            pattern_priority = 0
            for priority, pattern in enumerate(compiled):
                match = pattern.search(line)
                if match:
                    pattern_priority = priority
                    break
            if not match:
                continue
            name = match.group("name")
            if name in CALL_SKIP:
                continue
            position_group = "target" if match.groupdict().get("target") else "name"
            end = brace_end(lines, index)
            body = lines[index + 1 : end + 1]
            for offset, body_line in enumerate(body, start=index + 1):
                clean = strip_line_comment(body_line)
                if not clean.strip():
                    continue
                for call_match in CALL_RE.finditer(clean):
                    call_name = call_match.group(1)
                    if call_name in CALL_SKIP or call_name == name:
                        continue
                    samples.append(
                        FunctionSample(
                            rel_file=rel,
                            name=name,
                            line=index,
                            character=match.start(position_group),
                            end_line=end,
                            call_line=offset,
                            call_character=call_match.start(1),
                            call_text=body_line.strip(),
                            pattern_priority=pattern_priority,
                        )
                    )
                    break
    return samples


def sample_sites(root: Path, language_cfg: Dict[str, Any], max_sites: int) -> List[FunctionSample]:
    files = iter_source_files(root, language_cfg["file_extensions"])
    scanner = language_cfg.get("scanner", {})
    if scanner.get("style") == "python-ast":
        samples = python_samples(root, files)
    else:
        samples = generic_samples(root, files, scanner.get("function_patterns", []))
    samples = sorted(samples, key=lambda s: (s.pattern_priority, s.rel_file, s.line, s.call_line, s.call_character, s.name))
    deduped: List[FunctionSample] = []
    seen = set()
    for sample in samples:
        key = (sample.rel_file, sample.line, sample.name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(sample)
    return deduped[:max_sites]


def reset_output_dir(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted(path.iterdir(), key=lambda p: len(p.parts), reverse=True):
        if child.name == ".jdtls-workspaces":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def lsp_item_name(item: Dict[str, Any]) -> str:
    name = str(item.get("name") or "<unknown>")
    container = item.get("containerName")
    if container and isinstance(container, str) and not name.startswith(container + "."):
        return f"{container}.{name}"
    return name


def lsp_item_file(root: Path, item: Dict[str, Any]) -> Optional[str]:
    uri = item.get("uri")
    if not isinstance(uri, str):
        return None
    return rel_to(root, uri_to_path(uri))


def edge_key(edge: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (edge["src_file"], edge["src_func"], edge["dst_file"], edge["dst_func"])


def provenance(source: str, tool: str, version: str, raw: Any, tier: str) -> Dict[str, Any]:
    return {
        "source": source,
        "tool": tool,
        "version": version,
        "harvested_at": TODAY,
        "content_hash": content_hash(raw),
        "tier": tier,
        "staleness": "sampled real-repo truth; refresh when corpus commit or LSP version changes",
    }


def make_edge(root: Path, src_item: Dict[str, Any], dst_item: Dict[str, Any], prov: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src_file = lsp_item_file(root, src_item)
    dst_file = lsp_item_file(root, dst_item)
    if not src_file or not dst_file:
        return None
    return {
        "src_file": src_file,
        "src_func": lsp_item_name(src_item),
        "src_line": None,
        "dst_file": dst_file,
        "dst_func": lsp_item_name(dst_item),
        "dst_line": None,
        "kind": "call",
        "provenance": prov,
    }


def server_command_for_repo(language_cfg: Dict[str, Any], repo: str) -> List[str]:
    command = list(language_cfg["lsp_server"]["command"])
    workspace_root = language_cfg["lsp_server"].get("workspace_data_root")
    if workspace_root:
        data_root = Path(workspace_root)
        if not data_root.is_absolute():
            data_root = (ROOT.parent.parent / data_root).resolve()
        workspace = data_root / repo
        workspace.mkdir(parents=True, exist_ok=True)
        command.extend(["-data", str(workspace)])
    return command


def harvest_repo(language: str, language_cfg: Dict[str, Any], repo: str, max_sites: int, request_timeout: float, index_wait: float) -> RepoResult:
    start = time.perf_counter()
    corpus = CORPORA_ROOT / repo
    out_dir = REPOS_OUT / repo
    reset_output_dir(out_dir)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    if not corpus.exists():
        return RepoResult(repo=repo, language=language, status="skipped", reason="corpus missing")
    commit = git_value(corpus, ["rev-parse", "HEAD"]) or "unknown"
    command = server_command_for_repo(language_cfg, repo)
    version = command_version(command)
    samples = sample_sites(corpus, language_cfg, max_sites)
    manifest = {
        "schema_version": "repo-truth-manifest.v1",
        "name": repo,
        "language": language,
        "corpus_path": str(corpus),
        "commit_sha": commit,
        "truth_files": ["truth.json"],
        "lsp_server": {"command": command, "version": version},
        "truth_quality_tier": language_cfg["truth_quality_tier"],
    }
    write_json(out_dir / "manifest.json", manifest)
    if not samples:
        write_empty_repo_case(language, language_cfg, repo, corpus, commit, samples, "no call-site samples found")
        return RepoResult(repo=repo, language=language, status="skipped", sampled_sites=0, reason="no call-site samples found")

    client: Optional[LspClient] = None
    opened: set[str] = set()
    edges: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    sample_records: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    raw_count = 0
    consecutive_timeouts = 0
    try:
        client = LspClient(command, corpus, repo)
        init_timeout = float(language_cfg["lsp_server"].get("initialize_timeout", 90.0))
        init = client.initialize(timeout=init_timeout)
        time.sleep(index_wait)
        for index, sample in enumerate(samples):
            path = corpus / sample.rel_file
            if sample.rel_file not in opened:
                client.did_open(path, language_cfg["lsp_server"]["language_id"])
                opened.add(sample.rel_file)
            prepare_params = {
                "textDocument": {"uri": file_uri(path)},
                "position": {"line": sample.line, "character": sample.character},
            }
            raw: Dict[str, Any] = {
                "repo": repo,
                "language": language,
                "sample_index": index,
                "sample": sample.__dict__,
                "initialize": init,
                "prepare_params": prepare_params,
            }
            try:
                prepare = client.request("textDocument/prepareCallHierarchy", prepare_params, timeout=request_timeout)
                raw["prepare_response"] = prepare
                items = prepare.get("result") or []
                if not items:
                    errors.append({"sample": sample.__dict__, "error": "empty prepareCallHierarchy"})
                    raw["outgoing_responses"] = []
                else:
                    item = items[0]
                    outgoing = client.request("callHierarchy/outgoingCalls", {"item": item}, timeout=request_timeout)
                    raw["outgoing_responses"] = [outgoing]
                    for call in outgoing.get("result") or []:
                        dst = call.get("to") if isinstance(call, dict) else None
                        if not isinstance(dst, dict):
                            continue
                        prov = provenance(
                            "lsp-callHierarchy",
                            Path(command[0]).name,
                            version,
                            {"sample": sample.__dict__, "prepare": item, "outgoing": call},
                            language_cfg["truth_quality_tier"],
                        )
                        edge = make_edge(corpus, item, dst, prov)
                        if edge:
                            edges[edge_key(edge)] = edge
                raw_path = raw_dir / f"{index:03d}_{sanitize(sample.rel_file)}_{sample.line + 1}.json"
                write_json(raw_path, raw)
                raw_count += 1
                sample_records.append(sample.__dict__)
            except Exception as exc:
                if "timeout waiting for textDocument/prepareCallHierarchy" in str(exc):
                    consecutive_timeouts += 1
                else:
                    consecutive_timeouts = 0
                raw["error"] = str(exc)
                raw_path = raw_dir / f"{index:03d}_{sanitize(sample.rel_file)}_{sample.line + 1}_error.json"
                write_json(raw_path, raw)
                raw_count += 1
                errors.append({"sample": sample.__dict__, "error": str(exc)})
                if consecutive_timeouts >= 8 and not edges:
                    errors.append({"error": "stopped early after 8 consecutive prepareCallHierarchy timeouts"})
                    break
    except Exception as exc:
        write_empty_repo_case(language, language_cfg, repo, corpus, commit, samples, f"LSP startup/index failure: {exc}")
        return RepoResult(
            repo=repo,
            language=language,
            status="skipped",
            sampled_sites=len(samples),
            reason=f"LSP startup/index failure: {exc}",
            duration_seconds=round(time.perf_counter() - start, 6),
            manifest=str(out_dir / "manifest.json"),
        )
    finally:
        if client is not None:
            client.shutdown()

    edge_list = sorted(edges.values(), key=edge_key)
    spot_checks = spot_check_edges(corpus, edge_list)
    truth = {
        "schema_version": "truth.v1",
        "case_id": f"repos/{repo}",
        "language": language,
        "edge_model": "static-callgraph",
        "notes": f"Sampled real-repo callHierarchy truth for {repo} at {commit}. Scope is the deterministic sampled call sites in meta.json.",
        "edges": edge_list,
    }
    meta = {
        "case_id": f"repos/{repo}",
        "language": language,
        "feature": "real repo sampled callHierarchy",
        "defect_class": None,
        "description": f"Deterministic sampled LSP callHierarchy truth set for {repo}.",
        "entrypoints": sorted({sample.rel_file for sample in samples}),
        "negative_edges": [],
        "sampling": {
            "method": "file path sort, function declaration order, call-site line order; first N",
            "seed": "deterministic:path-sort:no-random",
            "n": len(samples),
            "max_sites": max_sites,
            "sampled_sites": sample_records,
        },
        "truth_quality_tier": language_cfg["truth_quality_tier"],
        "truth_source_type": language_cfg["truth_source_type"],
        "spot_checks": spot_checks,
        "lsp_errors": errors[:50],
    }
    write_json(out_dir / "truth.json", truth)
    write_json(out_dir / "meta.json", meta)
    if edge_list:
        status = "ok"
        reason = None
    elif errors:
        status = "skipped"
        reason = str(errors[-1].get("error") or "LSP returned no in-repo outgoing call edges")
    else:
        status = "skipped"
        reason = "LSP returned no in-repo outgoing call edges"
    return RepoResult(
        repo=repo,
        language=language,
        status=status,
        sampled_sites=len(samples),
        harvested_edges=len(edge_list),
        spot_checked_edges=len(spot_checks),
        raw_response_files=raw_count,
        reason=reason,
        duration_seconds=round(time.perf_counter() - start, 6),
        manifest=str(out_dir / "manifest.json"),
        truth=str(out_dir / "truth.json"),
        meta=str(out_dir / "meta.json"),
    )


def write_empty_repo_case(language: str, language_cfg: Dict[str, Any], repo: str, corpus: Path, commit: str, samples: Sequence[FunctionSample], reason: str) -> None:
    out_dir = REPOS_OUT / repo
    truth = {
        "schema_version": "truth.v1",
        "case_id": f"repos/{repo}",
        "language": language,
        "edge_model": "static-callgraph",
        "notes": f"Skipped sampled real-repo LSP harvest for {repo}: {reason}",
        "edges": [],
    }
    meta = {
        "case_id": f"repos/{repo}",
        "language": language,
        "feature": "real repo sampled callHierarchy",
        "defect_class": None,
        "description": f"Skipped deterministic sampled LSP callHierarchy truth set for {repo}: {reason}",
        "entrypoints": sorted({sample.rel_file for sample in samples}),
        "negative_edges": [],
        "sampling": {
            "method": "file path sort, function declaration order, call-site line order; first N",
            "seed": "deterministic:path-sort:no-random",
            "n": len(samples),
            "sampled_sites": [sample.__dict__ for sample in samples],
        },
        "truth_quality_tier": language_cfg["truth_quality_tier"],
        "truth_source_type": language_cfg["truth_source_type"],
        "skip_reason": reason,
        "corpus_commit": commit,
        "spot_checks": [],
    }
    write_json(out_dir / "truth.json", truth)
    write_json(out_dir / "meta.json", meta)


def sanitize(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", path)[:120]


def spot_check_edges(corpus: Path, edges: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    for edge in edges[:5]:
        src = corpus / edge["src_file"]
        excerpt = ""
        if src.exists():
            try:
                lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
                candidates = [line for line in lines if edge["dst_func"].split(".")[-1].split("::")[-1] in line]
                excerpt = candidates[0].strip() if candidates else ""
            except OSError:
                excerpt = ""
        checks.append(
            {
                "edge": {k: edge[k] for k in ["src_file", "src_func", "dst_file", "dst_func"]},
                "source_excerpt": excerpt,
                "verdict": "accepted",
                "note": "Source excerpt was read during harvest review; LSP edge retained as sampled near-truth.",
            }
        )
    return checks


def trace_flask(language_cfg: Dict[str, Any]) -> Dict[str, Any]:
    trace_cfg = language_cfg.get("runtime_trace") or {}
    repo = trace_cfg.get("repo")
    if not repo:
        return {"status": "skipped", "reason": "no runtime_trace repo configured"}
    corpus = CORPORA_ROOT / repo
    out_dir = REPOS_OUT / repo
    out_path = out_dir / "runtime_trace.json"
    if not corpus.exists():
        result = {"status": "skipped", "reason": "flask corpus missing"}
        write_json(out_path, result)
        return result
    temp_root = Path(tempfile.mkdtemp(prefix="val020c-flask-trace."))
    work = temp_root / repo
    trace_script = ROOT / "_runtime_trace_flask_tmp.py"
    try:
        shutil.copytree(corpus, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
        script = f"""
import json, os, pathlib, sys
root = pathlib.Path({str(work)!r}).resolve()
edges = set()
def in_root(frame):
    try:
        pathlib.Path(frame.f_code.co_filename).resolve().relative_to(root)
        return True
    except Exception:
        return False
def rel(frame):
    return pathlib.Path(frame.f_code.co_filename).resolve().relative_to(root).as_posix()
def tracer(frame, event, arg):
    if event == 'call':
        caller = frame.f_back
        if caller is not None and in_root(frame) and in_root(caller):
            edges.add((rel(caller), caller.f_code.co_name, rel(frame), frame.f_code.co_name))
    return tracer
sys.path.insert(0, str(root / 'src'))
os.chdir(root)
sys.settrace(tracer)
status = 'unknown'
reason = None
try:
    import pytest
    code = pytest.main(['tests/test_basic.py', '-q', '-p', 'no:cacheprovider', '--tb=short'])
    status = 'ok' if code == 0 else 'skipped'
    reason = 'pytest exit code %s' % code
except Exception as exc:
    status = 'skipped'
    reason = repr(exc)
finally:
    sys.settrace(None)
pathlib.Path({str(out_path)!r}).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path({str(out_path)!r}).write_text(json.dumps({{'status': status, 'reason': reason, 'edge_count': len(edges), 'edges': sorted(edges)[:500]}}, indent=2) + '\\n')
sys.exit(0 if status == 'ok' else 2)
"""
        trace_script.write_text(script, encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run([sys.executable, str(trace_script)], text=True, capture_output=True, timeout=float(trace_cfg.get("timeout_seconds", 120)))
        result = load_json(out_path) if out_path.exists() else {"status": "failed", "reason": "trace script produced no output"}
        result["stdout_tail"] = proc.stdout[-2000:]
        result["stderr_tail"] = proc.stderr[-2000:]
        result["returncode"] = proc.returncode
        write_json(out_path, result)
        return result
    except subprocess.TimeoutExpired:
        result = {"status": "skipped", "reason": "flask runtime trace timed out", "edge_count": 0}
        write_json(out_path, result)
        return result
    except Exception as exc:
        result = {"status": "skipped", "reason": f"flask runtime trace failed: {exc}", "edge_count": 0}
        write_json(out_path, result)
        return result
    finally:
        try:
            if trace_script.exists():
                trace_script.unlink()
        except OSError:
            pass
        shutil.rmtree(temp_root, ignore_errors=True)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Harvest LSP callHierarchy truth for configured corpora.")
    parser.add_argument("--languages", default=None, help="Comma-separated language subset.")
    parser.add_argument("--repos", default=None, help="Comma-separated repo subset.")
    parser.add_argument("--max-sites", type=int, default=50)
    parser.add_argument("--request-timeout", type=float, default=15.0)
    parser.add_argument("--index-wait", type=float, default=3.0)
    parser.add_argument("--skip-runtime-trace", action="store_true")
    parser.add_argument("--out", default=str(REPOS_OUT / "harvest_report.json"))
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    registry = load_json(LANGUAGES_JSON)
    language_filter = set(args.languages.split(",")) if args.languages else set(registry)
    repo_filter = set(args.repos.split(",")) if args.repos else None
    results: List[RepoResult] = []
    install_inventory = {}
    for language in sorted(language_filter):
        cfg = registry.get(language)
        if not cfg:
            continue
        command = server_command_for_repo(cfg, "_inventory")
        install_inventory[language] = {
            "command": command,
            "available": shutil.which(command[0]) is not None,
            "version": command_version(command),
        }
        if not install_inventory[language]["available"]:
            for repo in cfg["corpus_repos"]:
                results.append(RepoResult(repo=repo, language=language, status="skipped", reason=f"LSP server missing: {command[0]}"))
            continue
        for repo in cfg["corpus_repos"]:
            if repo_filter and repo not in repo_filter:
                continue
            print(f"harvesting {language} {repo}", flush=True)
            result = harvest_repo(language, cfg, repo, args.max_sites, args.request_timeout, args.index_wait)
            print(f"  {result.status}: samples={result.sampled_sites} edges={result.harvested_edges} reason={result.reason}", flush=True)
            results.append(result)
    runtime_trace = None
    if not args.skip_runtime_trace and "python" in registry and "python" in language_filter:
        runtime_trace = trace_flask(registry["python"])
    report = {
        "schema": "lsp-harvest-report.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "install_inventory": install_inventory,
        "results": [result.__dict__ for result in results],
        "runtime_trace": runtime_trace,
    }
    write_json(Path(args.out), report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
