"""SARIF 2.1.0 rendering of a ``ToolReport`` for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from infra_tools import __version__
from infra_tools.core.models import Finding, Severity, ToolReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/mohananarasimha/infrastructure-tools"

_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_PROBLEM_SEVERITY: dict[str, str] = {
    "error": "error",
    "warning": "warning",
    "note": "recommendation",
}


class RuleLike(Protocol):
    @property
    def rule_id(self) -> str: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def title(self) -> str: ...
    @property
    def description(self) -> str: ...


@dataclass(frozen=True)
class SarifResult:
    """Outcome of rendering: the SARIF document and how many results have no file location."""

    document: dict[str, Any]
    unlocated: int

    def to_json(self) -> str:
        return json.dumps(self.document, indent=2) + "\n"


def _split_file_line(location: str) -> tuple[str, int] | None:
    """Parse ``path:line``. Returns None for non-file locations such as ``<stdin>:3`` or a DSN."""
    path, sep, line = location.rpartition(":")
    if not sep or not path or not line.isdigit() or int(line) < 1:
        return None
    if path.startswith("<"):
        return None
    return path, int(line)


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def _physical(uri: str, line: int) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }
    }


def _result(
    finding: Finding,
    rule_index: int,
    artifact_uri: str | None,
    file_locations: bool,
) -> tuple[dict[str, Any], bool]:
    level = _LEVELS[finding.severity]
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": f"{finding.message} Fix: {finding.remediation}"},
        "properties": {"severity": finding.severity.value, "resource": finding.resource},
    }
    logical = [{"fullyQualifiedName": finding.resource, "kind": "resource"}]

    if artifact_uri is not None:
        # Findings about a live system are pinned to one file. GitHub's own line-content
        # fingerprint would then merge every result on line 1, so identity comes from the
        # rule and resource instead.
        location = _physical(artifact_uri, 1)
        location["logicalLocations"] = logical
        result["locations"] = [location]
        result["partialFingerprints"] = {
            "primaryLocationLineHash": f"{_fingerprint(finding.rule_id, finding.resource)}:1"
        }
        return result, True

    file_line = _split_file_line(finding.location) if file_locations else None
    if file_line is None:
        result["locations"] = [{"logicalLocations": logical}]
        return result, False
    uri, line = file_line
    location = _physical(uri, line)
    location["logicalLocations"] = logical
    result["locations"] = [location]
    # Without this, upload-sarif hashes the flagged line plus the lines after it, so editing
    # a neighbouring line (e.g. the image under `- name: web`) closes and reopens an
    # unrelated alert. Rule, file, resource and message survive line shifts and nearby edits.
    result["partialFingerprints"] = {
        "primaryLocationLineHash": (
            f"{_fingerprint(finding.rule_id, uri, finding.resource, finding.message)}:1"
        )
    }
    return result, True


def build_sarif(
    report: ToolReport,
    rules: Sequence[RuleLike],
    *,
    artifact_uri: str | None = None,
    file_locations: bool = True,
) -> SarifResult:
    """Render ``report`` as one SARIF run.

    File locations come from each finding's ``path:line`` location. When ``artifact_uri`` is
    set, every result is anchored to line 1 of that file instead, for tools whose findings
    describe a live system rather than a source file. ``file_locations=False`` stops
    ``host:port`` style locations from being read as ``path:line``.
    """
    rule_index = {rule.rule_id: idx for idx, rule in enumerate(rules)}
    unknown = sorted({f.rule_id for f in report.findings} - rule_index.keys())
    if unknown:
        raise ValueError(f"findings reference rules missing from the catalog: {unknown}")

    descriptors = []
    for rule in rules:
        level = _LEVELS[rule.severity]
        descriptors.append(
            {
                "id": rule.rule_id,
                "name": rule.title,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.description},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "precision": "high",
                    "problem.severity": _PROBLEM_SEVERITY[level],
                    "tags": [report.tool],
                },
            }
        )

    results = []
    unlocated = 0
    for finding in report.findings:
        rendered, has_file = _result(
            finding, rule_index[finding.rule_id], artifact_uri, file_locations
        )
        results.append(rendered)
        if not has_file:
            unlocated += 1

    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": descriptors,
                    }
                },
                "automationDetails": {"id": f"{report.tool}/"},
                "results": results,
            }
        ],
    }
    return SarifResult(document=document, unlocated=unlocated)
