"""Verdict and evidence-bundle contracts.

Inspectors stay evidence-only. These models are what the verdict engine returns.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.request import ScanRequest

Classification = Literal["Trusted", "Conditional", "Undetermined", "Blocked"]
RuleId = Literal[
    "rule_critical",
    "rule_check_error",
    "rule_warnings",
    "rule_insufficient_evidence",
    "rule_trusted",
]


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: Classification
    rule_id: RuleId
    exit_code: int
    reason: str
    critical_finding_ids: list[str] = Field(default_factory=list)


class ManifestSummary(BaseModel):
    """The manifest fields the bundle keeps. The staged file list stays in the work dir."""

    model_config = ConfigDict(extra="forbid")

    root_sha256: str | None = None
    artifact_type: str
    source: str


class InspectorReport(BaseModel):
    """One inspector report as stored on the bundle. Same shape the inspectors emit."""

    model_config = ConfigDict(extra="forbid")

    inspector: str
    version: str
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: ScanRequest
    manifest: ManifestSummary
    intake_checks: list[CheckResult] = Field(default_factory=list)
    reports: list[InspectorReport] = Field(default_factory=list)
    verdict: Verdict
    tool_version: str
    policy_profile: str
    timestamp: datetime
    bundle_sha256: str = ""
