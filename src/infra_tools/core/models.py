"""Shared Pydantic models and exit-code contracts across all CLI utilities."""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Normalized severity levels ordered from highest to lowest impact."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank where higher numbers indicate greater severity."""
        return _SEVERITY_RANK[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        """Return True if this severity is at or above ``threshold``."""
        return self.rank >= threshold.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

ORDERED_SEVERITIES: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class ExitCode(IntEnum):
    """Deterministic exit codes shared across all tools."""

    OK = 0
    FINDINGS = 1
    ERROR = 2


class OutputFormat(StrEnum):
    """Supported report output formats."""

    TABLE = "table"
    JSON = "json"


class ReportFormat(StrEnum):
    """Output formats for rule-based scans whose findings map to SARIF results."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"

    def as_output_format(self) -> OutputFormat:
        if self is ReportFormat.SARIF:
            raise ValueError("SARIF has no OutputFormat equivalent")
        return OutputFormat(self.value)


class Finding(BaseModel):
    """Single actionable finding emitted by an analysis tool."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., min_length=1)
    severity: Severity
    resource: str = Field(..., min_length=1)
    location: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    remediation: str = Field(..., min_length=1)


class ReportSummary(BaseModel):
    """Aggregate counts for a tool execution report."""

    model_config = ConfigDict(frozen=True)

    documents_scanned: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    by_severity: dict[str, int] = Field(default_factory=dict)


class ToolReport(BaseModel):
    """Top-level structured report shared by table and JSON renderers."""

    model_config = ConfigDict(frozen=True)

    tool: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    passed: bool

    @classmethod
    def from_findings(
        cls,
        *,
        tool: str,
        target: str,
        documents_scanned: int,
        findings: list[Finding],
        fail_on: Severity = Severity.LOW,
    ) -> ToolReport:
        """Construct a deterministically sorted report and compute pass/fail status."""
        sorted_findings = sorted(
            findings,
            key=lambda f: (-f.severity.rank, f.rule_id, f.resource, f.location, f.message),
        )
        counts: dict[str, int] = {sev.value: 0 for sev in ORDERED_SEVERITIES}
        for finding in sorted_findings:
            counts[finding.severity.value] += 1

        passed = not any(f.severity.meets_threshold(fail_on) for f in sorted_findings)
        summary = ReportSummary(
            documents_scanned=documents_scanned,
            total_findings=len(sorted_findings),
            by_severity=counts,
        )
        return cls(
            tool=tool,
            target=target,
            summary=summary,
            findings=sorted_findings,
            passed=passed,
        )
