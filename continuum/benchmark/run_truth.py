#!/usr/bin/env python3
"""Run the tldr ground-truth benchmark corpus.

The harness is intentionally stdlib-only so it can run in the repo without
bootstrap steps. It scores `tldr calls` for the full corpus and scores
definition/impact/dead only for micro-suites, where truth is complete enough
for those command semantics.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BINARY = Path.home() / ".cargo" / "bin" / "tldr"
DEFAULT_OUT = SCRIPT_DIR / "report.json"
LANGUAGE_REGISTRY = SCRIPT_DIR / "languages.json"
CALLS_COMMAND = "calls"
MICRO_COMMANDS = ("definition", "impact", "dead")
SOURCE_EXTENSIONS = {
    "python": [".py"],
    "typescript": [".ts"],
    "go": [".go"],
    "rust": [".rs"],
    "java": [".java"],
}
ALLOWED_PROVENANCE = {"manual", "lsp-callHierarchy", "runtime-trace", "vendored-pycg"}
ALLOWED_EDGE_KINDS = {"call", "method", "constructor"}


@dataclass(frozen=True, order=True)
class EdgeKey:
    src_file: str
    src_func: str
    dst_file: str
    dst_func: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "src_file": self.src_file,
            "src_func": self.src_func,
            "dst_file": self.dst_file,
            "dst_func": self.dst_func,
        }


@dataclass(frozen=True, order=True)
class FunctionKey:
    file: str
    func: str

    def as_dict(self) -> Dict[str, str]:
        return {"file": self.file, "func": self.func}


@dataclass(frozen=True)
class SourceFunction:
    key: FunctionKey
    line_start: int
    line_end: int


@dataclass
class SourceIndex:
    lines_by_file: Dict[str, List[str]]
    functions: List[SourceFunction]
    by_key: Dict[FunctionKey, SourceFunction]


@dataclass
class Case:
    case_id: str
    case_dir: Path
    execution_dir: Path
    truth_path: Path
    meta_path: Path
    truth: Dict[str, Any]
    meta: Dict[str, Any]
    language: str
    suite: str
    suite_group: str
    suite_family: str
    defect_class: str
    truth_quality_tier: str


class ValidationError(Exception):
    pass


class Counts:
    def __init__(self) -> None:
        self.cases = 0
        self.scored_cases = 0
        self.skipped_cases = 0
        self.true_positives = 0
        self.false_negatives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.unscored = 0
        self.truth_edges = 0
        self.reported_edges = 0
        self.unique_reported_edges = 0
        self.duration_seconds = 0.0
        self.skipped_by_reason: Dict[str, int] = defaultdict(int)

    def add_case(self, result: Dict[str, Any]) -> None:
        self.cases += 1
        self.duration_seconds += float(result.get("duration_seconds", 0.0) or 0.0)
        if result.get("status") != "ok":
            self.skipped_cases += 1
            self.skipped_by_reason[str(result.get("skip_reason") or result.get("status"))] += 1
            return
        counts = result["counts"]
        self.scored_cases += 1
        self.true_positives += counts["true_positives"]
        self.false_negatives += counts["false_negatives"]
        self.false_positives += counts["false_positives"]
        self.true_negatives += counts["true_negatives"]
        self.unscored += counts["unscored"]
        self.truth_edges += counts["truth_edges"]
        self.reported_edges += counts["reported_edges"]
        self.unique_reported_edges += counts["unique_reported_edges"]

    def to_dict(self) -> Dict[str, Any]:
        return with_metrics(
            {
                "cases": self.cases,
                "scored_cases": self.scored_cases,
                "skipped_cases": self.skipped_cases,
                "true_positives": self.true_positives,
                "false_negatives": self.false_negatives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "unscored": self.unscored,
                "truth_edges": self.truth_edges,
                "reported_edges": self.reported_edges,
                "unique_reported_edges": self.unique_reported_edges,
                "duration_seconds": round(self.duration_seconds, 6),
                "skipped_by_reason": dict(sorted(self.skipped_by_reason.items())),
            }
        )


class RungCounts:
    def __init__(self) -> None:
        self.true_positives = 0
        self.false_positives = 0
        self.samples = 0
        self.cases: Set[str] = set()
        self.languages: Set[str] = set()
        self.examples: List[Dict[str, Any]] = []

    def add_event(self, event: Dict[str, Any]) -> None:
        outcome = event.get("outcome")
        if outcome == "tp":
            self.true_positives += 1
        elif outcome == "fp":
            self.false_positives += 1
        else:
            return
        self.samples += 1
        if isinstance(event.get("case_id"), str):
            self.cases.add(event["case_id"])
        if isinstance(event.get("language"), str):
            self.languages.add(event["language"])
        if len(self.examples) < 12:
            self.examples.append(
                {
                    key: value
                    for key, value in event.items()
                    if key
                    in {
                        "case_id",
                        "command",
                        "language",
                        "outcome",
                        "rung",
                        "target",
                        "caller",
                        "edge",
                        "reason",
                    }
                }
            )

    def to_dict(self) -> Dict[str, Any]:
        precision = None
        if self.samples > 0:
            precision = round(self.true_positives / self.samples, 6)
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "samples": self.samples,
            "precision": precision,
            "case_count": len(self.cases),
            "languages": sorted(self.languages),
            "examples": self.examples,
        }


def load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: expected a JSON object")
    return data


def load_language_registry(root: Path) -> Dict[str, Any]:
    path = root / "languages.json"
    if not path.exists():
        return {}
    return load_json(path)


def require_keys(path: Path, data: Dict[str, Any], required: Iterable[str]) -> None:
    missing = [key for key in required if key not in data]
    if missing:
        raise ValidationError(f"{path}: missing required keys: {', '.join(missing)}")


def reject_extra_keys(path: Path, data: Dict[str, Any], allowed: Iterable[str], context: str) -> None:
    allowed_set = set(allowed)
    extra = sorted(key for key in data if key not in allowed_set)
    if extra:
        raise ValidationError(f"{path}: unexpected {context} keys: {', '.join(extra)}")


def validate_provenance(path: Path, provenance: Any, context: str) -> None:
    if not isinstance(provenance, dict):
        raise ValidationError(f"{path}: {context}.provenance must be an object")
    require_keys(path, provenance, ["source", "harvested_at"])
    reject_extra_keys(
        path,
        provenance,
        [
            "source",
            "tool",
            "version",
            "harvested_at",
            "upstream_url",
            "upstream_commit",
            "content_hash",
            "tier",
            "staleness",
        ],
        f"{context}.provenance",
    )
    if provenance["source"] not in ALLOWED_PROVENANCE:
        raise ValidationError(f"{path}: {context}.provenance.source={provenance['source']!r} is not allowed")
    if not isinstance(provenance["harvested_at"], str):
        raise ValidationError(f"{path}: {context}.provenance.harvested_at must be a string")
    if "tier" in provenance and provenance["tier"] not in {"T0", "T1", "T2"}:
        raise ValidationError(f"{path}: {context}.provenance.tier={provenance['tier']!r} is not allowed")


def validate_edge(path: Path, edge: Any, context: str, allow_reason: bool = False) -> None:
    if not isinstance(edge, dict):
        raise ValidationError(f"{path}: {context} must be an object")
    required = ["src_file", "src_func", "src_line", "dst_file", "dst_func", "dst_line", "kind", "provenance"]
    allowed = required + ["confidence_note", "tier_hint", "staleness"]
    if allow_reason:
        allowed.append("reason")
    require_keys(path, edge, required)
    reject_extra_keys(path, edge, allowed, context)
    for key in ["src_file", "src_func", "dst_file", "dst_func"]:
        if not isinstance(edge[key], str):
            raise ValidationError(f"{path}: {context}.{key} must be a string")
    for key in ["src_line", "dst_line"]:
        if edge[key] is not None and not isinstance(edge[key], int):
            raise ValidationError(f"{path}: {context}.{key} must be integer or null")
    if edge["kind"] not in ALLOWED_EDGE_KINDS:
        raise ValidationError(f"{path}: {context}.kind={edge['kind']!r} is not allowed")
    validate_provenance(path, edge["provenance"], context)
    if allow_reason and "reason" in edge and not isinstance(edge["reason"], str):
        raise ValidationError(f"{path}: {context}.reason must be a string")


def validate_expected_unresolved(path: Path, item: Any, index: int) -> None:
    context = f"expected_unresolved[{index}]"
    if not isinstance(item, dict):
        raise ValidationError(f"{path}: {context} must be an object")
    require_keys(path, item, ["expression", "location", "reason", "missing_edge", "provenance"])
    reject_extra_keys(path, item, ["expression", "location", "reason", "missing_edge", "provenance"], context)
    if not isinstance(item["expression"], str) or not isinstance(item["reason"], str):
        raise ValidationError(f"{path}: {context}.expression and .reason must be strings")
    location = item["location"]
    if not isinstance(location, dict):
        raise ValidationError(f"{path}: {context}.location must be an object")
    require_keys(path, location, ["file", "line"])
    reject_extra_keys(path, location, ["file", "line"], f"{context}.location")
    if not isinstance(location["file"], str) or not isinstance(location["line"], int):
        raise ValidationError(f"{path}: {context}.location has invalid fields")
    validate_edge(path, item["missing_edge"], f"{context}.missing_edge")
    validate_provenance(path, item["provenance"], context)


def validate_truth(path: Path, truth: Dict[str, Any]) -> None:
    require_keys(path, truth, ["schema_version", "case_id", "language", "edge_model", "notes", "edges"])
    reject_extra_keys(path, truth, ["schema_version", "case_id", "language", "edge_model", "notes", "edges", "expected_unresolved"], "truth")
    if truth["schema_version"] != "truth.v1":
        raise ValidationError(f"{path}: schema_version must be truth.v1")
    if truth["edge_model"] != "static-callgraph":
        raise ValidationError(f"{path}: edge_model must be static-callgraph")
    for key in ["case_id", "language", "notes"]:
        if not isinstance(truth[key], str):
            raise ValidationError(f"{path}: {key} must be a string")
    if not isinstance(truth["edges"], list):
        raise ValidationError(f"{path}: edges must be an array")
    for index, item in enumerate(truth["edges"]):
        validate_edge(path, item, f"edges[{index}]")
    if "expected_unresolved" in truth:
        if not isinstance(truth["expected_unresolved"], list):
            raise ValidationError(f"{path}: expected_unresolved must be an array")
        for index, item in enumerate(truth["expected_unresolved"]):
            validate_expected_unresolved(path, item, index)


def validate_meta(path: Path, meta: Dict[str, Any], allow_harvest_fields: bool = False) -> None:
    require_keys(path, meta, ["case_id", "language", "feature", "defect_class", "description", "entrypoints", "negative_edges"])
    allowed = [
        "case_id",
        "language",
        "feature",
        "defect_class",
        "description",
        "entrypoints",
        "entry_points",
        "negative_edges",
        "expected_unresolved",
    ]
    if allow_harvest_fields:
        allowed += [
            "corpus_commit",
            "lsp_errors",
            "lsp_readiness",
            "pytest_reason",
            "pytest_returncode",
            "sampling",
            "skip_reason",
            "spot_checks",
            "truth_quality_tier",
            "truth_source_type",
        ]
    reject_extra_keys(path, meta, allowed, "meta")
    for key in ["case_id", "language", "feature", "description"]:
        if not isinstance(meta[key], str):
            raise ValidationError(f"{path}: {key} must be a string")
    if meta["defect_class"] is not None and not isinstance(meta["defect_class"], str):
        raise ValidationError(f"{path}: defect_class must be string or null")
    if not isinstance(meta["entrypoints"], list) or not all(isinstance(item, str) for item in meta["entrypoints"]):
        raise ValidationError(f"{path}: entrypoints must be a string array")
    if "entry_points" in meta:
        if not isinstance(meta["entry_points"], list) or not all(isinstance(item, str) for item in meta["entry_points"]):
            raise ValidationError(f"{path}: entry_points must be a string array")
    if not isinstance(meta["negative_edges"], list):
        raise ValidationError(f"{path}: negative_edges must be an array")
    for index, item in enumerate(meta["negative_edges"]):
        validate_edge(path, item, f"negative_edges[{index}]", allow_reason=True)
        if not item.get("reason"):
            raise ValidationError(f"{path}: negative_edges[{index}] must include a reason")
    if "expected_unresolved" in meta:
        if not isinstance(meta["expected_unresolved"], list):
            raise ValidationError(f"{path}: expected_unresolved must be an array")
        for index, item in enumerate(meta["expected_unresolved"]):
            validate_expected_unresolved(path, item, index)


def discover_cases(root: Path, filter_text: Optional[str]) -> List[Case]:
    registry = load_language_registry(root)
    truth_paths: List[Path] = []
    suites_root = root / "suites"
    vendored_root = root / "vendored"
    repos_root = root / "repos"
    if suites_root.exists():
        truth_paths.extend(sorted(suites_root.glob("*/*/*/truth.json")))
    if vendored_root.exists():
        truth_paths.extend(sorted(vendored_root.glob("*/cases/*/*/truth.json")))
    if repos_root.exists():
        for manifest_path in sorted(repos_root.glob("*/manifest.json")):
            manifest = load_json(manifest_path)
            truth_files = manifest.get("truth_files")
            if not isinstance(truth_files, list):
                continue
            for item in truth_files:
                if isinstance(item, str):
                    truth_paths.append(manifest_path.parent / item)

    cases: List[Case] = []
    for truth_path in truth_paths:
        case_dir = truth_path.parent
        meta_path = case_dir / "meta.json"
        if truth_path.name == "runtime_trace_truth.json":
            meta_path = case_dir / "runtime_trace_meta.json"
        if not meta_path.exists():
            raise ValidationError(f"{case_dir}: missing meta.json")
        truth = load_json(truth_path)
        meta = load_json(meta_path)
        validate_truth(truth_path, truth)
        rel = case_dir.relative_to(root)
        is_repo_case = rel.parts[0] == "repos"
        validate_meta(meta_path, meta, allow_harvest_fields=is_repo_case)
        if truth["case_id"] != meta["case_id"]:
            raise ValidationError(f"{case_dir}: truth/meta case_id mismatch")
        if truth["language"] != meta["language"]:
            raise ValidationError(f"{case_dir}: truth/meta language mismatch")
        truth_quality_tier = str(
            meta.get("truth_quality_tier")
            or registry.get(truth["language"], {}).get("truth_quality_tier")
            or "unregistered"
        )

        if rel.parts[0] == "suites":
            suite = "suites"
            suite_group = f"{rel.parts[1]}-suite"
            suite_family = "/".join(rel.parts[:3])
            execution_dir = case_dir
        elif rel.parts[0] == "vendored":
            suite = f"vendored/{rel.parts[1]}"
            suite_group = f"{rel.parts[1]}-vendored"
            suite_family = "/".join(rel.parts[:4])
            execution_dir = case_dir
        elif rel.parts[0] == "repos":
            manifest = load_json(case_dir / "manifest.json")
            corpus_path = manifest.get("corpus_path")
            if not isinstance(corpus_path, str):
                raise ValidationError(f"{case_dir}: manifest missing corpus_path")
            execution_dir = Path(corpus_path)
            suite = "repos"
            suite_group = f"{truth['language']}-repo"
            suite_family = f"repos/{rel.parts[1]}"
        else:
            raise ValidationError(f"{case_dir}: unsupported case location")

        case_id = truth["case_id"]
        searchable = f"{case_id} {rel.as_posix()} {meta.get('feature', '')} {meta.get('defect_class', '')}"
        if filter_text and filter_text not in searchable:
            continue
        cases.append(
            Case(
                case_id=case_id,
                case_dir=case_dir,
                execution_dir=execution_dir,
                truth_path=truth_path,
                meta_path=meta_path,
                truth=truth,
                meta=meta,
                language=truth["language"],
                suite=suite,
                suite_group=suite_group,
                suite_family=suite_family,
                defect_class=meta.get("defect_class") or "none",
                truth_quality_tier=truth_quality_tier,
            )
        )
    return sorted(cases, key=lambda item: item.case_id)


def posix_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def module_name_for_file(file_name: str) -> str:
    file_name = posix_path(file_name)
    if file_name.startswith("<"):
        return file_name
    if file_name.endswith(".py"):
        file_name = file_name[:-3]
    parts = [part for part in file_name.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def normalize_func(func_name: str, file_name: str) -> str:
    value = func_name.strip()
    if ":" in value:
        left, right = value.split(":", 1)
        if left.endswith(".py"):
            value = right
    module = module_name_for_file(file_name)
    if module and value.startswith(module + "."):
        return value[len(module) + 1 :]
    return value


def edge_key(edge: Dict[str, Any]) -> EdgeKey:
    src_file = posix_path(str(edge["src_file"]))
    dst_file = posix_path(str(edge["dst_file"]))
    return EdgeKey(
        src_file=src_file,
        src_func=normalize_func(str(edge["src_func"]), src_file),
        dst_file=dst_file,
        dst_func=normalize_func(str(edge["dst_func"]), dst_file),
    )


def report_edge_key(edge: Dict[str, Any]) -> Optional[EdgeKey]:
    for key in ["src_file", "src_func", "dst_file", "dst_func"]:
        if key not in edge:
            return None
    return edge_key(edge)


def ownerless_name(func_name: str) -> str:
    if "." not in func_name:
        return func_name
    return func_name.rsplit(".", 1)[-1]


def edge_dict_from_key(key: EdgeKey, reason: Optional[str] = None) -> Dict[str, Any]:
    data = key.as_dict()
    if reason:
        data["reason"] = reason
    data["rung"] = None
    return data


def edge_dict_with_rung(key: EdgeKey, rung: Optional[str], reason: Optional[str] = None) -> Dict[str, Any]:
    data = edge_dict_from_key(key, reason)
    data["rung"] = rung
    return data


def unique_edge_keys(edges: Sequence[Dict[str, Any]]) -> Set[EdgeKey]:
    return {edge_key(edge) for edge in edges}


def forbidden_edges(case: Case) -> Set[EdgeKey]:
    keys = set()
    for edge in case.meta.get("negative_edges", []):
        keys.add(edge_key(edge))
    for item in case.truth.get("expected_unresolved", []):
        keys.add(edge_key(item["missing_edge"]))
    for item in case.meta.get("expected_unresolved", []):
        keys.add(edge_key(item["missing_edge"]))
    return keys


def function_key(file_name: str, func_name: str) -> FunctionKey:
    file_name = posix_path(file_name)
    return FunctionKey(file=file_name, func=normalize_func(func_name, file_name))


def strip_arity(func_name: str) -> str:
    return re.sub(r"\([^)]*\)$", "", func_name)


def source_paths(case: Case) -> List[Path]:
    extensions = SOURCE_EXTENSIONS.get(case.language, [])
    if not extensions:
        return []
    paths: List[Path] = []
    for ext in extensions:
        paths.extend(case.case_dir.rglob(f"*{ext}"))
    ignored_parts = {"raw", ".jdtls-workspaces", "__pycache__", "node_modules", "target", "dist", "build"}
    return sorted(path for path in paths if not any(part in ignored_parts for part in path.relative_to(case.case_dir).parts))


def add_source_function(functions: List[SourceFunction], rel_file: str, func_name: str, line_start: int, line_end: int) -> None:
    key = function_key(rel_file, func_name)
    if line_end < line_start:
        line_end = line_start
    functions.append(SourceFunction(key=key, line_start=line_start, line_end=line_end))


def parse_python_functions(rel_file: str, text: str, functions: List[SourceFunction]) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    lambda_counter = 0

    def visit_body(nodes: List[ast.stmt], stack: List[str]) -> None:
        nonlocal lambda_counter
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = ".".join(stack + [node.name])
                add_source_function(functions, rel_file, name, node.lineno, getattr(node, "end_lineno", node.lineno))
                visit_body(list(node.body), stack + [node.name])
                for decorator in node.decorator_list:
                    visit_expr(decorator, stack)
            elif isinstance(node, ast.ClassDef):
                visit_body(list(node.body), stack + [node.name])
                for decorator in node.decorator_list:
                    visit_expr(decorator, stack)
            else:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.expr):
                        visit_expr(child, stack)

    def visit_expr(node: ast.AST, stack: List[str]) -> None:
        nonlocal lambda_counter
        if isinstance(node, ast.Lambda):
            lambda_counter += 1
            name = ".".join(stack + [f"<lambda{lambda_counter}>"])
            add_source_function(functions, rel_file, name, node.lineno, getattr(node, "end_lineno", node.lineno))
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                visit_expr(child, stack)
            elif isinstance(child, ast.stmt):
                visit_body([child], stack)

    visit_body(list(tree.body), [])


def block_end_line(lines: List[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_line - 1, len(lines)):
        line = lines[index]
        depth += line.count("{")
        if "{" in line:
            seen_open = True
        depth -= line.count("}")
        if seen_open and depth <= 0:
            return index + 1
    return start_line


def parse_go_functions(rel_file: str, lines: List[str], functions: List[SourceFunction]) -> None:
    receiver_re = re.compile(r"^\s*func\s*\((?P<recv>[^)]*)\)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    func_re = re.compile(r"^\s*func\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for line_no, line in enumerate(lines, 1):
        match = receiver_re.search(line)
        if match:
            receiver_parts = match.group("recv").replace("*", " ").split()
            receiver_type = receiver_parts[-1] if receiver_parts else ""
            name = f"{receiver_type}.{match.group('name')}"
            add_source_function(functions, rel_file, name, line_no, block_end_line(lines, line_no))
            continue
        match = func_re.search(line)
        if match:
            add_source_function(functions, rel_file, match.group("name"), line_no, block_end_line(lines, line_no))


def parse_typescript_functions(rel_file: str, lines: List[str], functions: List[SourceFunction]) -> None:
    function_re = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]+>)?\s*\(")
    class_re = re.compile(r"\bclass\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b")
    method_re = re.compile(r"^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*|constructor)\s*(?:<[^>]+>)?\s*\(")
    current_class: Optional[str] = None
    class_depth = 0
    depth = 0
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        class_match = class_re.search(line)
        if class_match:
            current_class = class_match.group("name")
            class_depth = depth + max(1, line.count("{"))
        elif current_class and depth >= class_depth:
            method_match = method_re.search(line)
            if method_match and not stripped.startswith(("if", "for", "while", "switch", "catch")):
                method = method_match.group("name")
                name = f"{current_class}.constructor" if method == "constructor" else f"{current_class}.{method}"
                add_source_function(functions, rel_file, name, line_no, block_end_line(lines, line_no))
        func_match = function_re.search(line)
        if func_match:
            add_source_function(functions, rel_file, func_match.group("name"), line_no, block_end_line(lines, line_no))
        depth += line.count("{") - line.count("}")
        if current_class and depth < class_depth:
            current_class = None
            class_depth = 0


def java_param_signature(params: str) -> str:
    params = params.strip()
    if not params:
        return ""
    parts = []
    for raw in params.split(","):
        tokens = [token for token in raw.strip().split() if token not in {"final"}]
        if tokens:
            parts.append(tokens[0].replace("...", "[]"))
    return ",".join(parts)


def parse_java_functions(rel_file: str, lines: List[str], functions: List[SourceFunction]) -> None:
    class_re = re.compile(r"\b(?:class|interface)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
    method_re = re.compile(
        r"^\s*(?:public|private|protected|static|final|abstract|synchronized|\s)*"
        r"(?:(?:[A-Za-z_][A-Za-z0-9_<>\[\].?,\s]+)\s+)?"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)"
    )
    current_class: Optional[str] = None
    class_depth = 0
    depth = 0
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        class_match = class_re.search(line)
        if class_match:
            current_class = class_match.group("name")
            class_depth = depth + max(1, line.count("{"))
        elif current_class and depth >= class_depth:
            method_match = method_re.search(line)
            if method_match and "{" in line and not stripped.startswith(("if", "for", "while", "switch", "catch")):
                method = method_match.group("name")
                params = java_param_signature(method_match.group("params"))
                if method == current_class:
                    name = f"{current_class}.{current_class}"
                elif params:
                    name = f"{current_class}.{method}({params})"
                else:
                    name = f"{current_class}.{method}"
                add_source_function(functions, rel_file, name, line_no, block_end_line(lines, line_no))
        depth += line.count("{") - line.count("}")
        if current_class and depth < class_depth:
            current_class = None
            class_depth = 0


def parse_rust_functions(rel_file: str, lines: List[str], functions: List[SourceFunction]) -> None:
    impl_re = re.compile(r"^\s*impl(?:\s+[A-Za-z_][A-Za-z0-9_:<>]*)?(?:\s+for)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_:<>]*)\s*\{")
    trait_re = re.compile(r"^\s*(?:pub\s+)?trait\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
    fn_re = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    current_owner: Optional[str] = None
    owner_depth = 0
    depth = 0
    for line_no, line in enumerate(lines, 1):
        impl_match = impl_re.search(line)
        trait_match = trait_re.search(line)
        if impl_match:
            current_owner = impl_match.group("name").split("::")[-1]
            owner_depth = depth + max(1, line.count("{"))
        elif trait_match:
            current_owner = trait_match.group("name")
            owner_depth = depth + max(1, line.count("{"))
        fn_match = fn_re.search(line)
        if fn_match:
            fn_name = fn_match.group("name")
            name = f"{current_owner}.{fn_name}" if current_owner and depth >= owner_depth else fn_name
            add_source_function(functions, rel_file, name, line_no, block_end_line(lines, line_no))
        depth += line.count("{") - line.count("}")
        if current_owner and depth < owner_depth:
            current_owner = None
            owner_depth = 0


def build_source_index(case: Case) -> SourceIndex:
    lines_by_file: Dict[str, List[str]] = {}
    functions: List[SourceFunction] = []
    for path in source_paths(case):
        rel_file = path.relative_to(case.case_dir).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        lines_by_file[rel_file] = lines
        if case.language == "python":
            parse_python_functions(rel_file, text, functions)
        elif case.language == "go":
            parse_go_functions(rel_file, lines, functions)
        elif case.language == "typescript":
            parse_typescript_functions(rel_file, lines, functions)
        elif case.language == "java":
            parse_java_functions(rel_file, lines, functions)
        elif case.language == "rust":
            parse_rust_functions(rel_file, lines, functions)
    by_key: Dict[FunctionKey, SourceFunction] = {}
    for function in functions:
        by_key.setdefault(function.key, function)
    return SourceIndex(lines_by_file=lines_by_file, functions=functions, by_key=by_key)


def command_output_to_edges(output: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    warnings: List[str] = []
    raw_edges = output.get("edges", [])
    if not isinstance(raw_edges, list):
        raise ValueError("tldr JSON field edges is not an array")
    edges: List[Dict[str, Any]] = []
    for index, edge in enumerate(raw_edges):
        if not isinstance(edge, dict):
            warnings.append(f"reported edge {index} is not an object")
            continue
        key = report_edge_key(edge)
        if key is None:
            warnings.append(f"reported edge {index} is missing required fields")
            continue
        normalized = key.as_dict()
        normalized["call_type"] = edge.get("call_type")
        provenance = edge.get("provenance")
        normalized["rung"] = provenance.get("rung") if isinstance(provenance, dict) else None
        edges.append(normalized)
    return edges, warnings


def run_tldr_args(binary: Path, args: Sequence[str], timeout_seconds: float) -> Tuple[str, Dict[str, Any], str, float]:
    env = os.environ.copy()
    env["TLDR_NO_DAEMON"] = "1"
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [str(binary)] + list(args),
            cwd=str(SCRIPT_DIR.parent.parent),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - started
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return "timeout", {}, stderr, duration
    except OSError as exc:
        duration = time.perf_counter() - started
        return "execution_error", {}, str(exc), duration
    duration = time.perf_counter() - started
    if proc.returncode != 0:
        return "nonzero_exit", {"returncode": proc.returncode, "stdout": proc.stdout}, proc.stderr, duration
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return "parse_error", {"stdout": proc.stdout}, f"invalid JSON: {exc}; stderr={proc.stderr}", duration
    if not isinstance(parsed, dict):
        return "parse_error", {"stdout": proc.stdout}, "top-level JSON was not an object", duration
    return "ok", parsed, proc.stderr, duration


def run_tldr_calls(binary: Path, case_dir: Path, timeout_seconds: float) -> Tuple[str, Dict[str, Any], str, float]:
    return run_tldr_args(binary, [CALLS_COMMAND, str(case_dir), "--format", "json"], timeout_seconds)


def base_result(case: Case, command: str, timeout_seconds: float, duration: float) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "path": case.case_dir.relative_to(SCRIPT_DIR).as_posix(),
        "truth_path": case.truth_path.relative_to(SCRIPT_DIR).as_posix(),
        "execution_path": str(case.execution_dir),
        "language": case.language,
        "suite": case.suite,
        "suite_group": case.suite_group,
        "suite_family": case.suite_family,
        "feature": case.meta.get("feature"),
        "defect_class": case.defect_class,
        "command": command,
        "truth_quality_tier": case.truth_quality_tier,
        "duration_seconds": round(duration, 6),
        "timeout_seconds": timeout_seconds,
        "rung_supported": False,
    }


def score_calls_case(case: Case, binary: Path, timeout_seconds: float) -> Dict[str, Any]:
    status, output, stderr, duration = run_tldr_calls(binary, case.execution_dir, timeout_seconds)
    base = base_result(case, CALLS_COMMAND, timeout_seconds, duration)
    if status != "ok":
        base.update(
            {
                "status": "skipped",
                "skip_reason": status,
                "stderr": stderr,
                "tldr": output,
                "counts": empty_counts(),
                "metrics": metrics(0, 0, 0),
            }
        )
        return base

    try:
        reported_edges, warnings = command_output_to_edges(output)
    except ValueError as exc:
        base.update(
            {
                "status": "skipped",
                "skip_reason": "parse_error",
                "stderr": str(exc),
                "tldr": summarize_tldr(output),
                "counts": empty_counts(),
                "metrics": metrics(0, 0, 0),
            }
        )
        return base

    truth_keys = unique_edge_keys(case.truth.get("edges", []))
    forbidden_keys = forbidden_edges(case)
    rung_by_key: Dict[EdgeKey, Optional[str]] = {}
    for edge in reported_edges:
        key = report_edge_key(edge)
        if key is not None:
            rung_by_key.setdefault(key, edge.get("rung") if isinstance(edge.get("rung"), str) else None)
    reported_keys = {report_edge_key(edge) for edge in reported_edges}
    reported_keys = {key for key in reported_keys if key is not None}

    matched = truth_keys & reported_keys
    missed = truth_keys - reported_keys
    forbidden_reported = forbidden_keys & reported_keys

    truth_call_index: Dict[Tuple[str, str, str], Set[EdgeKey]] = defaultdict(set)
    for key in truth_keys:
        truth_call_index[(key.src_file, key.src_func, ownerless_name(key.dst_func))].add(key)

    wrong_owner: Set[EdgeKey] = set()
    unscored: Set[EdgeKey] = set()
    for key in sorted(reported_keys):
        if key in matched or key in forbidden_reported:
            continue
        call_key = (key.src_file, key.src_func, ownerless_name(key.dst_func))
        if call_key in truth_call_index:
            wrong_owner.add(key)
        else:
            unscored.add(key)

    false_positive_keys = forbidden_reported | wrong_owner
    true_negative_keys = forbidden_keys - reported_keys
    rung_events = []
    for key in sorted(matched):
        rung_events.append(
            {
                "command": CALLS_COMMAND,
                "language": case.language,
                "case_id": case.case_id,
                "outcome": "tp",
                "rung": rung_by_key.get(key),
                "edge": edge_dict_with_rung(key, rung_by_key.get(key)),
            }
        )
    for key in sorted(false_positive_keys):
        reason = "matched negative edge" if key in forbidden_reported else "wrong-owner contradiction"
        rung_events.append(
            {
                "command": CALLS_COMMAND,
                "language": case.language,
                "case_id": case.case_id,
                "outcome": "fp",
                "rung": rung_by_key.get(key),
                "reason": reason,
                "edge": edge_dict_with_rung(key, rung_by_key.get(key), reason),
            }
        )
    counts = {
        "truth_edges": len(truth_keys),
        "reported_edges": len(reported_edges),
        "unique_reported_edges": len(reported_keys),
        "true_positives": len(matched),
        "false_negatives": len(missed),
        "false_positives": len(false_positive_keys),
        "true_negatives": len(true_negative_keys),
        "unscored": len(unscored),
        "forbidden_edges": len(forbidden_keys),
        "wrong_owner_false_positives": len(wrong_owner),
        "negative_edge_false_positives": len(forbidden_reported),
    }
    base.update(
        {
            "status": "ok",
            "stderr": stderr,
            "warnings": warnings,
            "rung_supported": True,
            "rung_events": rung_events,
            "tldr": summarize_tldr(output),
            "counts": counts,
            "metrics": metrics(counts["true_positives"], counts["false_positives"], counts["false_negatives"]),
            "matched_edges": [edge_dict_with_rung(key, rung_by_key.get(key)) for key in sorted(matched)],
            "missed_truth_edges": [edge_dict_from_key(key) for key in sorted(missed)],
            "false_positive_edges": [
                edge_dict_with_rung(
                    key,
                    rung_by_key.get(key),
                    "matched negative edge" if key in forbidden_reported else "wrong-owner contradiction",
                )
                for key in sorted(false_positive_keys)
            ],
            "true_negative_edges": [edge_dict_from_key(key) for key in sorted(true_negative_keys)],
            "unscored_reported_edges": [edge_dict_from_key(key) for key in sorted(unscored)],
        }
    )
    return base


def is_micro_case(case: Case) -> bool:
    return case.suite != "repos"


def relative_to_case(path_value: str, case: Case) -> str:
    path_value = posix_path(path_value)
    if path_value.startswith("<"):
        return path_value
    path = Path(path_value)
    if path.is_absolute():
        try:
            return path.relative_to(case.execution_dir).as_posix()
        except ValueError:
            try:
                return path.relative_to(case.case_dir).as_posix()
            except ValueError:
                return path.name
    case_prefix = case.case_dir.as_posix().rstrip("/") + "/"
    execution_prefix = case.execution_dir.as_posix().rstrip("/") + "/"
    if path_value.startswith(case_prefix):
        return path_value[len(case_prefix) :]
    if path_value.startswith(execution_prefix):
        return path_value[len(execution_prefix) :]
    return path_value


def candidate_tokens_for_edge(edge: Dict[str, Any]) -> List[str]:
    dst_file = posix_path(str(edge["dst_file"]))
    dst_func = normalize_func(str(edge["dst_func"]), dst_file)
    raw_parts = [part for part in strip_arity(dst_func).split(".") if part]
    leaf = strip_arity(ownerless_name(dst_func))
    tokens: List[str] = []
    if leaf in {"__init__", "constructor"} and len(raw_parts) >= 2:
        tokens.append(raw_parts[-2])
    if leaf:
        tokens.append(leaf)
    if leaf == "new" and len(raw_parts) >= 2:
        tokens.append("new")
    if leaf.startswith("<lambda"):
        tokens.append("lambda")
    cleaned: List[str] = []
    for token in tokens:
        token = token.strip("<>")
        if token and token not in cleaned:
            cleaned.append(token)
    return cleaned


def identifier_boundary(line: str, start: int, end: int) -> bool:
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    before_ok = not (before.isalnum() or before in "_$")
    after_ok = not (after.isalnum() or after in "_$")
    return before_ok and after_ok


def occurrence_score(line: str, start: int, token: str) -> int:
    end = start + len(token)
    suffix = line[end:].lstrip()
    prefix = line[:start].rstrip()
    score = 0
    if suffix.startswith(("(", "<", "::")):
        score += 4
    if prefix.endswith((".", "::")):
        score += 2
    if line.lstrip().startswith(("@", "return", "await", "let ", "const ", "var ")):
        score += 1
    return score


def source_span_for_edge(case: Case, index: SourceIndex, edge: Dict[str, Any]) -> Tuple[int, int]:
    src_file = posix_path(str(edge["src_file"]))
    lines = index.lines_by_file.get(src_file, [])
    if not lines:
        return (1, 0)
    src_key = function_key(src_file, str(edge["src_func"]))
    source_function = index.by_key.get(src_key)
    if source_function:
        return (source_function.line_start, source_function.line_end)
    src_func = normalize_func(str(edge["src_func"]), src_file)
    module = module_name_for_file(src_file)
    if case.language == "python" and src_func in {module, "main", "<module>"}:
        return (1, len(lines))
    return (1, len(lines))


def locate_call_position(case: Case, index: SourceIndex, edge: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    src_file = posix_path(str(edge["src_file"]))
    if src_file.startswith("<"):
        return None, "source file is synthetic"
    lines = index.lines_by_file.get(src_file)
    if not lines:
        return None, f"source file not indexed: {src_file}"
    tokens = candidate_tokens_for_edge(edge)
    if not tokens:
        return None, "no callee token candidate"
    start_line, end_line = source_span_for_edge(case, index, edge)
    if end_line <= 0:
        return None, f"empty source span for {src_file}"
    best: Optional[Tuple[int, int, int, str]] = None
    for line_no in range(max(1, start_line), min(len(lines), end_line) + 1):
        line = lines[line_no - 1]
        for token in tokens:
            offset = 0
            while True:
                found = line.find(token, offset)
                if found < 0:
                    break
                end = found + len(token)
                if identifier_boundary(line, found, end):
                    score = occurrence_score(line, found, token)
                    candidate = (score, -line_no, -found, token)
                    if best is None or candidate > best:
                        best = candidate
                offset = found + len(token)
    if best is None:
        return None, f"callee token not found in {src_file}:{start_line}-{end_line}: {tokens}"
    _, negative_line, negative_col, token = best
    line_no = -negative_line
    column = -negative_col
    return {
        "file": src_file,
        "line": line_no,
        "column": column,
        "token": token,
        "src_span": [start_line, end_line],
    }, None


def definition_output_location(output: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    declined = output.get("declined")
    if isinstance(declined, list) and declined:
        return None
    definition = output.get("definition")
    if isinstance(definition, dict):
        return definition
    symbol = output.get("symbol")
    if isinstance(symbol, dict) and isinstance(symbol.get("location"), dict):
        return symbol["location"]
    return None


def definition_matches(case: Case, edge: Dict[str, Any], output: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    expected = edge_key(edge)
    symbol = output.get("symbol") if isinstance(output.get("symbol"), dict) else {}
    if expected.dst_file == "<builtin>":
        if symbol.get("is_builtin") is True:
            return True, {"file": "<builtin>", "func": symbol.get("name", "")}, "builtin match"
        return False, None, "expected builtin but output was not builtin"
    location = definition_output_location(output)
    if not location:
        if symbol.get("is_builtin") is True:
            return False, {"file": "<builtin>", "func": symbol.get("name", "")}, "returned builtin without source definition"
        return False, None, "no definition location returned"
    file_value = location.get("file")
    line_value = location.get("line")
    if not isinstance(file_value, str):
        return False, None, "definition location missing file"
    actual_file = relative_to_case(file_value, case)
    actual = {"file": actual_file, "line": line_value, "column": location.get("column")}
    if actual_file != expected.dst_file:
        return False, actual, "definition file mismatch"
    expected_line = edge.get("dst_line")
    if expected_line is not None and line_value != expected_line:
        return False, actual, "definition line mismatch"
    return True, actual, "matched"


def score_definition_case(case: Case, binary: Path, timeout_seconds: float, index: SourceIndex) -> Dict[str, Any]:
    total_duration = 0.0
    stderr_parts: List[str] = []
    warnings: List[str] = []
    matched: List[Dict[str, Any]] = []
    missed: List[Dict[str, Any]] = []
    false_positive: List[Dict[str, Any]] = []
    reported_locations: Set[Tuple[str, Optional[int]]] = set()
    truth_edges = case.truth.get("edges", [])
    for edge in truth_edges:
        query, reason = locate_call_position(case, index, edge)
        expected = edge_key(edge)
        if query is None:
            missed.append({**edge_dict_from_key(expected, reason), "query": None})
            continue
        status, output, stderr, duration = run_tldr_args(
            binary,
            [
                "definition",
                str(case.case_dir / query["file"]),
                str(query["line"]),
                str(query["column"]),
                "--project",
                str(case.execution_dir),
                "--format",
                "json",
            ],
            timeout_seconds,
        )
        total_duration += duration
        if stderr:
            stderr_parts.append(stderr)
        if status != "ok":
            missed.append({**edge_dict_from_key(expected, status), "query": query})
            warnings.append(f"{expected.src_file}:{query['line']}:{query['column']} definition {status}")
            continue
        ok, actual, match_reason = definition_matches(case, edge, output)
        if actual and "file" in actual:
            reported_locations.add((str(actual["file"]), actual.get("line") if isinstance(actual.get("line"), int) else None))
        detail = {**edge_dict_from_key(expected, match_reason), "query": query, "actual": actual}
        if ok:
            matched.append(detail)
        else:
            missed.append(detail)
            if actual:
                false_positive.append(detail)
    counts = {
        "truth_edges": len(truth_edges),
        "reported_edges": len(reported_locations),
        "unique_reported_edges": len(reported_locations),
        "true_positives": len(matched),
        "false_negatives": len(missed),
        "false_positives": len(false_positive),
        "true_negatives": 0,
        "unscored": 0,
        "forbidden_edges": 0,
        "wrong_owner_false_positives": len(false_positive),
        "negative_edge_false_positives": 0,
    }
    base = base_result(case, "definition", timeout_seconds, total_duration)
    base.update(
        {
            "status": "ok",
            "stderr": "\n".join(stderr_parts),
            "warnings": warnings,
            "derivation": "For each truth edge, locate the destination identifier inside the source function span and query `tldr definition FILE LINE COLUMN --project CASE_DIR`.",
            "counts": counts,
            "metrics": metrics(counts["true_positives"], counts["false_positives"], counts["false_negatives"]),
            "matched_definitions": matched,
            "missed_definitions": missed,
            "false_positive_definitions": false_positive,
        }
    )
    return base


def calls_rung_map(case: Case, binary: Path, timeout_seconds: float) -> Tuple[Dict[EdgeKey, Optional[str]], List[str]]:
    status, output, stderr, _duration = run_tldr_calls(binary, case.execution_dir, timeout_seconds)
    warnings: List[str] = []
    if stderr:
        warnings.append(stderr)
    if status != "ok":
        warnings.append(f"calls rung attribution {status}")
        return {}, warnings
    try:
        reported_edges, parse_warnings = command_output_to_edges(output)
    except ValueError as exc:
        warnings.append(str(exc))
        return {}, warnings
    warnings.extend(parse_warnings)
    rung_by_edge: Dict[EdgeKey, Optional[str]] = {}
    for edge in reported_edges:
        key = report_edge_key(edge)
        if key is not None:
            rung_by_edge.setdefault(key, edge.get("rung") if isinstance(edge.get("rung"), str) else None)
    return rung_by_edge, warnings


def impact_callers_with_rungs(
    output: Dict[str, Any], case: Case, rung_by_edge: Dict[EdgeKey, Optional[str]]
) -> Dict[FunctionKey, Optional[str]]:
    callers: Dict[FunctionKey, Optional[str]] = {}
    targets = output.get("targets")
    if not isinstance(targets, dict):
        return callers
    stack: List[Tuple[FunctionKey, Dict[str, Any]]] = []
    for target in targets.values():
        if not isinstance(target, dict):
            continue
        file_value = target.get("file")
        func_value = target.get("function")
        if not isinstance(file_value, str) or not isinstance(func_value, str):
            continue
        parent = function_key(relative_to_case(file_value, case), func_value)
        if isinstance(target.get("callers"), list):
            stack.extend((parent, item) for item in target["callers"] if isinstance(item, dict))
    while stack:
        parent, item = stack.pop()
        file_value = item.get("file")
        func_value = item.get("function")
        if isinstance(file_value, str) and isinstance(func_value, str):
            caller = function_key(relative_to_case(file_value, case), func_value)
            edge = EdgeKey(
                src_file=caller.file,
                src_func=caller.func,
                dst_file=parent.file,
                dst_func=parent.func,
            )
            callers.setdefault(caller, rung_by_edge.get(edge))
            next_parent = caller
        else:
            next_parent = parent
        nested = item.get("callers")
        if isinstance(nested, list):
            stack.extend((next_parent, child) for child in nested if isinstance(child, dict))
    return callers


def score_impact_case(case: Case, binary: Path, timeout_seconds: float) -> Dict[str, Any]:
    by_destination: Dict[FunctionKey, Set[FunctionKey]] = defaultdict(set)
    for edge in case.truth.get("edges", []):
        key = edge_key(edge)
        by_destination[FunctionKey(key.dst_file, key.dst_func)].add(FunctionKey(key.src_file, key.src_func))

    total_duration = 0.0
    stderr_parts: List[str] = []
    warnings: List[str] = []
    matched: Set[Tuple[FunctionKey, FunctionKey]] = set()
    missed: Set[Tuple[FunctionKey, FunctionKey]] = set()
    false_positive: Set[Tuple[FunctionKey, FunctionKey]] = set()
    rung_by_pair: Dict[Tuple[FunctionKey, FunctionKey], Optional[str]] = {}
    reported_count = 0
    details: List[Dict[str, Any]] = []
    rung_events: List[Dict[str, Any]] = []
    rung_by_edge, rung_warnings = calls_rung_map(case, binary, timeout_seconds)
    warnings.extend(rung_warnings)

    for dst, expected_callers in sorted(by_destination.items()):
        query_func = dst.func
        status, output, stderr, duration = run_tldr_args(
            binary,
            ["impact", query_func, str(case.execution_dir), "--file", dst.file, "--format", "json"],
            timeout_seconds,
        )
        total_duration += duration
        if stderr:
            stderr_parts.append(stderr)
        if status != "ok":
            warnings.append(f"{dst.file}:{dst.func} impact {status}")
            for caller in expected_callers:
                missed.add((dst, caller))
            details.append({"target": dst.as_dict(), "status": status, "expected_callers": [caller.as_dict() for caller in sorted(expected_callers)]})
            continue
        reported_callers_with_rungs = impact_callers_with_rungs(output, case, rung_by_edge)
        reported_callers = set(reported_callers_with_rungs)
        reported_count += len(reported_callers)
        target_matched = expected_callers & reported_callers
        target_missed = expected_callers - reported_callers
        target_false_positive = reported_callers - expected_callers
        for caller in target_matched:
            matched.add((dst, caller))
            rung = reported_callers_with_rungs.get(caller)
            rung_by_pair[(dst, caller)] = rung
            rung_events.append(
                {
                    "command": "impact",
                    "language": case.language,
                    "case_id": case.case_id,
                    "outcome": "tp",
                    "rung": rung,
                    "target": dst.as_dict(),
                    "caller": caller.as_dict(),
                }
            )
        for caller in target_missed:
            missed.add((dst, caller))
        for caller in target_false_positive:
            false_positive.add((dst, caller))
            rung = reported_callers_with_rungs.get(caller)
            rung_by_pair[(dst, caller)] = rung
            rung_events.append(
                {
                    "command": "impact",
                    "language": case.language,
                    "case_id": case.case_id,
                    "outcome": "fp",
                    "rung": rung,
                    "target": dst.as_dict(),
                    "caller": caller.as_dict(),
                    "reason": "caller not in truth caller set",
                }
            )
        details.append(
            {
                "target": dst.as_dict(),
                "status": "ok",
                "expected_callers": [caller.as_dict() for caller in sorted(expected_callers)],
                "reported_callers": [
                    {**caller.as_dict(), "rung": reported_callers_with_rungs.get(caller)}
                    for caller in sorted(reported_callers)
                ],
            }
        )

    counts = {
        "truth_edges": sum(len(callers) for callers in by_destination.values()),
        "reported_edges": reported_count,
        "unique_reported_edges": reported_count,
        "true_positives": len(matched),
        "false_negatives": len(missed),
        "false_positives": len(false_positive),
        "true_negatives": 0,
        "unscored": 0,
        "forbidden_edges": 0,
        "wrong_owner_false_positives": len(false_positive),
        "negative_edge_false_positives": 0,
    }
    base = base_result(case, "impact", timeout_seconds, total_duration)
    base.update(
        {
            "status": "ok",
            "stderr": "\n".join(stderr_parts),
            "warnings": warnings,
            "rung_supported": True,
            "rung_events": rung_events,
            "derivation": "For each unique truth destination, query `tldr impact <dst_func> CASE_DIR --file <dst_file>`; the --file filter disambiguates same-name targets.",
            "counts": counts,
            "metrics": metrics(counts["true_positives"], counts["false_positives"], counts["false_negatives"]),
            "matched_callers": [
                {
                    "target": dst.as_dict(),
                    "caller": caller.as_dict(),
                    "rung": rung_by_pair.get((dst, caller)),
                }
                for dst, caller in sorted(matched)
            ],
            "missed_callers": [{"target": dst.as_dict(), "caller": caller.as_dict()} for dst, caller in sorted(missed)],
            "false_positive_callers": [
                {
                    "target": dst.as_dict(),
                    "caller": caller.as_dict(),
                    "rung": rung_by_pair.get((dst, caller)),
                }
                for dst, caller in sorted(false_positive)
            ],
            "impact_targets": details,
        }
    )
    return base


def expected_unresolved_edges(case: Case) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    for item in case.truth.get("expected_unresolved", []):
        edges.append(item["missing_edge"])
    for item in case.meta.get("expected_unresolved", []):
        edges.append(item["missing_edge"])
    return edges


def dead_entry_functions(case: Case) -> Set[FunctionKey]:
    explicit = case.meta.get("entry_points")
    roots: Set[FunctionKey] = set()
    if isinstance(explicit, list) and explicit:
        for item in explicit:
            if ":" in item:
                file_name, func_name = item.split(":", 1)
                roots.add(function_key(file_name, func_name))
            else:
                roots.add(FunctionKey("*", item))
        return roots

    dst_keys = {FunctionKey(edge_key(edge).dst_file, edge_key(edge).dst_func) for edge in case.truth.get("edges", [])}
    for edge in list(case.truth.get("edges", [])) + expected_unresolved_edges(case):
        key = edge_key(edge)
        src = FunctionKey(key.src_file, key.src_func)
        if src not in dst_keys:
            roots.add(src)
    if not roots:
        for default_name in ["main", "run", "entry", "Entry", "Main.run"]:
            roots.add(FunctionKey("*", default_name))
    return roots


def is_entry_function(key: FunctionKey, roots: Set[FunctionKey]) -> bool:
    if key in roots:
        return True
    for root in roots:
        if root.file == "*" and (key.func == root.func or ownerless_name(key.func) == root.func):
            return True
    return False


def dead_reported_functions(output: Dict[str, Any], case: Case, index: SourceIndex) -> Tuple[Set[FunctionKey], Set[FunctionKey]]:
    reported: Set[FunctionKey] = set()
    unknown: Set[FunctionKey] = set()
    items: List[Dict[str, Any]] = []
    value = output.get("dead_functions")
    if isinstance(value, list):
        items.extend(item for item in value if isinstance(item, dict))
    for item in items:
        file_value = item.get("file")
        name_value = item.get("name")
        if not isinstance(file_value, str) or not isinstance(name_value, str):
            continue
        raw_key = function_key(relative_to_case(file_value, case), name_value)
        resolved = resolve_function_key(raw_key, index)
        if resolved:
            reported.add(resolved)
        else:
            unknown.add(raw_key)
    return reported, unknown


def resolve_function_key(raw_key: FunctionKey, index: SourceIndex) -> Optional[FunctionKey]:
    if raw_key in index.by_key:
        return raw_key
    raw_no_arity = FunctionKey(raw_key.file, strip_arity(raw_key.func))
    if raw_no_arity in index.by_key:
        return raw_no_arity
    candidates = [
        function.key
        for function in index.functions
        if function.key.file == raw_key.file
        and (
            function.key.func == raw_key.func
            or strip_arity(function.key.func) == strip_arity(raw_key.func)
            or ownerless_name(strip_arity(function.key.func)) == ownerless_name(strip_arity(raw_key.func))
        )
    ]
    unique = sorted(set(candidates))
    if len(unique) == 1:
        return unique[0]
    return None


def score_dead_case(case: Case, binary: Path, timeout_seconds: float, index: SourceIndex) -> Dict[str, Any]:
    all_functions = {function.key for function in index.functions}
    reachable_dst = {FunctionKey(edge_key(edge).dst_file, edge_key(edge).dst_func) for edge in case.truth.get("edges", [])}
    roots = dead_entry_functions(case)
    expected_dead = {
        key for key in all_functions if key not in reachable_dst and not is_entry_function(key, roots)
    }
    entry_points = sorted({root.func for root in roots})
    status, output, stderr, duration = run_tldr_args(
        binary,
        ["dead", str(case.execution_dir), "--entry-points", ",".join(entry_points), "--format", "json"],
        timeout_seconds,
    )
    base = base_result(case, "dead", timeout_seconds, duration)
    if status != "ok":
        counts = {
            **empty_counts(),
            "truth_edges": len(expected_dead),
            "false_negatives": len(expected_dead),
        }
        base.update(
            {
                "status": "ok",
                "stderr": stderr,
                "warnings": [f"dead command {status}; all expected-dead functions counted as missed"],
                "derivation": "Expected-dead is source functions not used as truth destinations and not selected as truth-graph roots.",
                "counts": counts,
                "metrics": metrics(0, 0, len(expected_dead)),
                "expected_dead_functions": [key.as_dict() for key in sorted(expected_dead)],
                "reported_dead_functions": [],
            }
        )
        return base
    reported_dead, unknown_reported = dead_reported_functions(output, case, index)
    matched = expected_dead & reported_dead
    missed = expected_dead - reported_dead
    false_positive = reported_dead - expected_dead
    counts = {
        "truth_edges": len(expected_dead),
        "reported_edges": len(reported_dead) + len(unknown_reported),
        "unique_reported_edges": len(reported_dead) + len(unknown_reported),
        "true_positives": len(matched),
        "false_negatives": len(missed),
        "false_positives": len(false_positive),
        "true_negatives": 0,
        "unscored": len(unknown_reported),
        "forbidden_edges": 0,
        "wrong_owner_false_positives": len(false_positive),
        "negative_edge_false_positives": 0,
    }
    base.update(
        {
            "status": "ok",
            "stderr": stderr,
            "warnings": [],
            "derivation": "Expected-dead is source functions not used as truth destinations and not selected as truth-graph roots; tldr dead is run with truth-derived root names.",
            "dead_entry_points": entry_points,
            "counts": counts,
            "metrics": metrics(counts["true_positives"], counts["false_positives"], counts["false_negatives"]),
            "expected_dead_functions": [key.as_dict() for key in sorted(expected_dead)],
            "matched_dead_functions": [key.as_dict() for key in sorted(matched)],
            "missed_dead_functions": [key.as_dict() for key in sorted(missed)],
            "false_positive_dead_functions": [key.as_dict() for key in sorted(false_positive)],
            "unscored_reported_functions": [key.as_dict() for key in sorted(unknown_reported)],
            "tldr": summarize_tldr(output),
        }
    )
    return base


def score_case_commands(case: Case, binary: Path, timeout_seconds: float) -> List[Dict[str, Any]]:
    results = [score_calls_case(case, binary, timeout_seconds)]
    if not is_micro_case(case):
        return results
    index = build_source_index(case)
    results.append(score_definition_case(case, binary, timeout_seconds, index))
    results.append(score_impact_case(case, binary, timeout_seconds))
    results.append(score_dead_case(case, binary, timeout_seconds, index))
    return results


def empty_counts() -> Dict[str, int]:
    return {
        "truth_edges": 0,
        "reported_edges": 0,
        "unique_reported_edges": 0,
        "true_positives": 0,
        "false_negatives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "unscored": 0,
        "forbidden_edges": 0,
        "wrong_owner_false_positives": 0,
        "negative_edge_false_positives": 0,
    }


def summarize_tldr(output: Dict[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for key in ["root", "language", "truncated", "total_edges", "shown_edges", "returncode"]:
        if key in output:
            summary[key] = output[key]
    if "nodes" in output and isinstance(output["nodes"], list):
        summary["node_count"] = len(output["nodes"])
    if "edges" in output and isinstance(output["edges"], list):
        summary["edge_count"] = len(output["edges"])
    return summary


def safe_ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator == 0:
        return None
    return numerator / denominator


def metrics(tp: int, fp: int, fn: int) -> Dict[str, Optional[float]]:
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        f1 = None
    else:
        f1 = (2 * precision * recall) / (precision + recall)
    return {
        "precision": round(precision, 6) if precision is not None else None,
        "recall": round(recall, 6) if recall is not None else None,
        "f1": round(f1, 6) if f1 is not None else None,
    }


def with_metrics(data: Dict[str, Any]) -> Dict[str, Any]:
    data["metrics"] = metrics(data["true_positives"], data["false_positives"], data["false_negatives"])
    return data


def aggregate(results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = Counts()
    by_language: Dict[str, Counts] = defaultdict(Counts)
    by_suite_group: Dict[str, Counts] = defaultdict(Counts)
    by_suite_family: Dict[str, Counts] = defaultdict(Counts)
    by_defect_class: Dict[str, Counts] = defaultdict(Counts)
    by_command: Dict[str, Counts] = defaultdict(Counts)
    by_command_language: Dict[str, Counts] = defaultdict(Counts)
    rung_totals: Dict[str, RungCounts] = defaultdict(RungCounts)
    rung_by_command: Dict[str, Dict[str, RungCounts]] = defaultdict(lambda: defaultdict(RungCounts))
    rung_by_command_language: Dict[str, RungCounts] = defaultdict(RungCounts)
    for result in results:
        total.add_case(result)
        by_language[result["language"]].add_case(result)
        by_suite_group[result["suite_group"]].add_case(result)
        by_suite_family[result["suite_family"]].add_case(result)
        by_defect_class[result["defect_class"]].add_case(result)
        by_command[result["command"]].add_case(result)
        by_command_language[f"{result['command']}:{result['language']}"].add_case(result)
        for event in result.get("rung_events", []):
            if not isinstance(event, dict):
                continue
            rung = event.get("rung") if isinstance(event.get("rung"), str) else "<missing>"
            command = event.get("command") if isinstance(event.get("command"), str) else result["command"]
            language = event.get("language") if isinstance(event.get("language"), str) else result["language"]
            rung_totals[rung].add_event(event)
            rung_by_command[command][rung].add_event(event)
            rung_by_command_language[f"{command}:{language}:{rung}"].add_event(event)
    return {
        "totals": total.to_dict(),
        "by_language": counts_map(by_language),
        "by_suite_group": counts_map(by_suite_group),
        "by_suite_family": counts_map(by_suite_family),
        "by_defect_class": counts_map(by_defect_class),
        "by_command": counts_map(by_command),
        "by_command_language": counts_map(by_command_language),
        "by_rung": {
            "totals": rung_counts_map(rung_totals),
            "by_command": {
                command: rung_counts_map(rungs) for command, rungs in sorted(rung_by_command.items())
            },
            "by_command_language": rung_counts_map(rung_by_command_language),
        },
        "command_scope": {
            "calls": "all discovered cases, including real-repo truth sets",
            "definition": "micro-suites only; real-repo truth is sampled/incomplete for per-call-site definition recall",
            "impact": "micro-suites only; real-repo truth is sampled/incomplete for caller-set recall",
            "dead": "micro-suites only; real-repo truth is sampled/incomplete for reachability/dead-code recall",
        },
    }


def counts_map(groups: Dict[str, Counts]) -> Dict[str, Any]:
    return {key: groups[key].to_dict() for key in sorted(groups)}


def rung_counts_map(groups: Dict[str, RungCounts]) -> Dict[str, Any]:
    return {key: groups[key].to_dict() for key in sorted(groups)}


def sha256_file(path: Path) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def git_value(args: Sequence[str]) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git"] + list(args),
            cwd=str(SCRIPT_DIR.parent.parent),
            text=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def build_report(
    *,
    binary: Path,
    cases: Sequence[Case],
    results: Sequence[Dict[str, Any]],
    filter_text: Optional[str],
    timeout_seconds: float,
    runtime_seconds: float,
) -> Dict[str, Any]:
    binary_sha = sha256_file(binary)
    return {
        "schema": "harness.v2",
        "schema_note": "harness.v2 is backward-compatible with harness.v1 per-case count/metric fields and adds command-scoped results for definition, impact, and dead.",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": str(SCRIPT_DIR),
        "binary_sha": binary_sha,
        "binary": {
            "path": str(binary),
            "sha256": binary_sha,
        },
        "corpus_commit": git_value(["rev-parse", "HEAD"]),
        "invocation": {
            "command": "calls+micro-definition-impact-dead",
            "filter": filter_text,
            "timeout_seconds": timeout_seconds,
            "case_count": len(cases),
            "micro_case_count": sum(1 for case in cases if is_micro_case(case)),
            "result_count": len(results),
            "runtime_seconds": round(runtime_seconds, 6),
        },
        "rung_supported": True,
        "scoring": {
            "schema": "scoring.v2",
            "edge_key": ["src_file", "src_func", "dst_file", "dst_func"],
            "line_numbers": "ignored",
            "normalization": [
                "Path separators are normalized to slash.",
                "A Python module prefix derived from the edge file is removed from src_func and dst_func.",
                "Reported edges are deduplicated for scoring; raw reported edge count is retained.",
            ],
            "true_positive": "A reported normalized edge exactly matches a truth edge.",
            "false_negative": "A truth edge is absent from reported normalized edges.",
            "false_positive": "Only a reported normalized edge that matches a negative edge or contradicts a covered call by same source and destination leaf name with the wrong owner is a false positive.",
            "unscored": "Reported edges outside truth coverage and outside negative/wrong-owner rules are counted separately and excluded from precision.",
            "expected_unresolved": "Expected-unresolved missing_edge values are treated as forbidden edges; reporting them is a false positive and not reporting them is a true negative.",
            "rung_attribution": "calls.v2 provenance.rung is preserved for calls scoring; impact attribution joins each emitted caller edge back to calls.v2 edge provenance.",
            "definition": "Micro-suite only. For each truth edge, the harness locates the destination identifier inside the source function span and runs `tldr definition FILE LINE COLUMN --project CASE_DIR`; wrong returned source locations count as both FP and FN.",
            "impact": "Micro-suite only. For each unique truth destination, the harness runs `tldr impact <dst_func> CASE_DIR --file <dst_file>` and scores the returned caller set against truth callers.",
            "dead": "Micro-suite only. Expected-dead functions are source definitions that are not truth destinations and are not truth-graph roots; reported reachable functions are false positives.",
            "real_repo_command_scope": "Real-repo truth sets remain calls-only because sampled LSP/runtime truth is incomplete for definition, impact, and dead recall.",
        },
        "per_case": list(results),
        "aggregates": aggregate(results),
    }


def metric_text(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{value:.3f}"


def print_table(report: Dict[str, Any]) -> None:
    rows: List[Tuple[str, Dict[str, Any]]] = [("total", report["aggregates"]["totals"])]
    for name, data in report["aggregates"]["by_command_language"].items():
        rows.append((name, data))
    print("command:language          cases skip  TP   FN   FP  unscored  P      R      F1")
    print("------------------------  ----- ---- ---- ---- ---- --------- ------ ------ ------")
    for name, data in rows:
        m = data["metrics"]
        print(
            f"{name[:24]:24}  "
            f"{data['cases']:5d} "
            f"{data['skipped_cases']:4d} "
            f"{data['true_positives']:4d} "
            f"{data['false_negatives']:4d} "
            f"{data['false_positives']:4d} "
            f"{data['unscored']:9d} "
            f"{metric_text(m['precision']):>6} "
            f"{metric_text(m['recall']):>6} "
            f"{metric_text(m['f1']):>6}"
        )
    runtime = report["invocation"]["runtime_seconds"]
    skipped = report["aggregates"]["totals"]["skipped_by_reason"]
    skipped_text = ", ".join(f"{key}={value}" for key, value in skipped.items()) if skipped else "none"
    print(f"\nruntime_seconds={runtime:.3f} skipped={skipped_text} out={report.get('out_path', '-')}")
    offenders = []
    for rung, data in report["aggregates"].get("by_rung", {}).get("totals", {}).items():
        if data["samples"] >= 5 and data["false_positives"] > 0:
            precision = data["precision"] if data["precision"] is not None else 0.0
            offenders.append((precision, -data["false_positives"], rung, data))
    if offenders:
        print("\nby_rung top offenders       samples  TP   FP   P")
        print("--------------------------  ------- ---- ---- ------")
        for precision, _neg_fp, rung, data in sorted(offenders)[:10]:
            print(
                f"{rung[:26]:26}  "
                f"{data['samples']:7d} "
                f"{data['true_positives']:4d} "
                f"{data['false_positives']:4d} "
                f"{precision:6.3f}"
            )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the tldr benchmark truth harness.")
    parser.add_argument("--binary", default=str(DEFAULT_BINARY), help="Path to tldr binary; default: ~/.cargo/bin/tldr")
    parser.add_argument("--filter", default=None, help="Only run cases whose id/path/metadata contains this substring")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Report JSON path; default: continuum/benchmark/report.json")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-case timeout in seconds; default: 30")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    binary = Path(args.binary).expanduser()
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = Path.cwd() / out_path
    try:
        cases = discover_cases(SCRIPT_DIR, args.filter)
    except ValidationError as exc:
        print(f"validation error: {exc}", file=sys.stderr)
        return 2
    if not cases:
        print("no cases matched", file=sys.stderr)
        return 2
    started = time.perf_counter()
    results: List[Dict[str, Any]] = []
    for case in cases:
        results.extend(score_case_commands(case, binary, args.timeout))
    runtime = time.perf_counter() - started
    report = build_report(
        binary=binary,
        cases=cases,
        results=results,
        filter_text=args.filter,
        timeout_seconds=args.timeout,
        runtime_seconds=runtime,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    report["out_path"] = str(out_path)
    print_table(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
