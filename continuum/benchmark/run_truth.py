#!/usr/bin/env python3
"""Run the tldr ground-truth benchmark corpus.

The harness is intentionally stdlib-only so it can run in the repo without
bootstrap steps. It currently scores only `tldr calls`; report shape reserves
slots for other commands and for future resolution-rung attribution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
COMMAND = "calls"
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
    allowed = ["case_id", "language", "feature", "defect_class", "description", "entrypoints", "negative_edges", "expected_unresolved"]
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
        normalized["rung"] = None
        edges.append(normalized)
    return edges, warnings


def run_tldr(binary: Path, case_dir: Path, timeout_seconds: float) -> Tuple[str, Dict[str, Any], str, float]:
    env = os.environ.copy()
    env["TLDR_NO_DAEMON"] = "1"
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [str(binary), COMMAND, str(case_dir), "--format", "json"],
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


def score_case(case: Case, binary: Path, timeout_seconds: float) -> Dict[str, Any]:
    status, output, stderr, duration = run_tldr(binary, case.execution_dir, timeout_seconds)
    base = {
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
        "command": COMMAND,
        "truth_quality_tier": case.truth_quality_tier,
        "duration_seconds": round(duration, 6),
        "timeout_seconds": timeout_seconds,
        "rung_supported": False,
    }
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
            "tldr": summarize_tldr(output),
            "counts": counts,
            "metrics": metrics(counts["true_positives"], counts["false_positives"], counts["false_negatives"]),
            "matched_edges": [edge_dict_from_key(key) for key in sorted(matched)],
            "missed_truth_edges": [edge_dict_from_key(key) for key in sorted(missed)],
            "false_positive_edges": [
                edge_dict_from_key(key, "matched negative edge" if key in forbidden_reported else "wrong-owner contradiction")
                for key in sorted(false_positive_keys)
            ],
            "true_negative_edges": [edge_dict_from_key(key) for key in sorted(true_negative_keys)],
            "unscored_reported_edges": [edge_dict_from_key(key) for key in sorted(unscored)],
        }
    )
    return base


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
    for result in results:
        total.add_case(result)
        by_language[result["language"]].add_case(result)
        by_suite_group[result["suite_group"]].add_case(result)
        by_suite_family[result["suite_family"]].add_case(result)
        by_defect_class[result["defect_class"]].add_case(result)
        by_command[result["command"]].add_case(result)
    return {
        "totals": total.to_dict(),
        "by_language": counts_map(by_language),
        "by_suite_group": counts_map(by_suite_group),
        "by_suite_family": counts_map(by_suite_family),
        "by_defect_class": counts_map(by_defect_class),
        "by_command": counts_map(by_command),
        "commands_not_run": {
            "impact": {"run": False, "reason": "VAL-021 only executes calls; report schema reserves command slot."},
            "definition": {"run": False, "reason": "VAL-021 only executes calls; report schema reserves command slot."},
            "dead": {"run": False, "reason": "VAL-021 only executes calls; report schema reserves command slot."},
        },
    }


def counts_map(groups: Dict[str, Counts]) -> Dict[str, Any]:
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
        "schema": "harness.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": str(SCRIPT_DIR),
        "binary_sha": binary_sha,
        "binary": {
            "path": str(binary),
            "sha256": binary_sha,
        },
        "corpus_commit": git_value(["rev-parse", "HEAD"]),
        "invocation": {
            "command": COMMAND,
            "filter": filter_text,
            "timeout_seconds": timeout_seconds,
            "case_count": len(cases),
            "runtime_seconds": round(runtime_seconds, 6),
        },
        "rung_supported": False,
        "scoring": {
            "schema": "scoring.v1",
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
            "rung_attribution": "Unsupported by current tldr calls output; emitted as rung:null with rung_supported:false.",
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
    for name, data in report["aggregates"]["by_suite_group"].items():
        rows.append((name, data))
    print("group                 cases skip TP  FN  FP  unscored  P      R      F1")
    print("--------------------  ----- ---- --- --- --- --------- ------ ------ ------")
    for name, data in rows:
        m = data["metrics"]
        print(
            f"{name[:20]:20}  "
            f"{data['cases']:5d} "
            f"{data['skipped_cases']:4d} "
            f"{data['true_positives']:3d} "
            f"{data['false_negatives']:3d} "
            f"{data['false_positives']:3d} "
            f"{data['unscored']:9d} "
            f"{metric_text(m['precision']):>6} "
            f"{metric_text(m['recall']):>6} "
            f"{metric_text(m['f1']):>6}"
        )
    runtime = report["invocation"]["runtime_seconds"]
    skipped = report["aggregates"]["totals"]["skipped_by_reason"]
    skipped_text = ", ".join(f"{key}={value}" for key, value in skipped.items()) if skipped else "none"
    print(f"\nruntime_seconds={runtime:.3f} skipped={skipped_text} out={report.get('out_path', '-')}")


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
    results = [score_case(case, binary, args.timeout) for case in cases]
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
