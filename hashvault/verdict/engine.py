"""Decide the trust classification. Inspectors do not.

Rules are first match wins. Warnings are decided before the v1 evidence gap:
a warning finding is Conditional even though the behavioural inspector has not
run. That is what makes a publisher or LoRA-config false alarm mark a clean
file Conditional. With no warning, missing behavioural coverage matches
``rule_insufficient_evidence``, so a live scan does not reach ``rule_trusted``.

The HLD lists insufficient evidence before warnings. This order is the one
the scan outcomes require: a clean hash match with no warning stays
Undetermined (exit 20), and a warning with no critical finding is Conditional
(exit 10), including when the hash check was skipped.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Sequence

from hashvault import __version__
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.policy import Policy, load_policy
from hashvault.verdict.models import (
    Classification,
    EvidenceBundle,
    InspectorReport,
    ManifestSummary,
    RuleId,
    Verdict,
)

# A skipped check with one of these reasons is a coverage gap, not a required-check error.
COVERAGE_GAP_REASONS = frozenset({
    "no_known_good_reference",
    "offline",
    "no_attestation",
    "publisher_not_claimed",
    "adapter_has_no_model_config",
})

EXIT_TRUSTED = 0
EXIT_CONDITIONAL = 10
EXIT_UNDETERMINED = 20
EXIT_BLOCKED = 30

BEHAVIOURAL_MISSING = "behavioural inspector has not run"


def canonical_bundle_sha256(document: dict) -> str:
    """SHA-256 of the canonical JSON with ``bundle_sha256`` empty.

    Canonical form is UTF-8, sorted keys, and no insignificant whitespace.
    """
    payload = dict(document)
    payload["bundle_sha256"] = ""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def render_bundle(bundle: EvidenceBundle) -> str:
    """Pretty-printed UTF-8 JSON, with a trailing newline."""
    document = bundle.model_dump(mode="json")
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _as_report(report: Any) -> InspectorReport:
    if isinstance(report, InspectorReport):
        return report
    data = report.model_dump() if hasattr(report, "model_dump") else report
    return InspectorReport.model_validate(data)


def _findings(reports: Sequence[InspectorReport]) -> list[Finding]:
    return [finding for report in reports for finding in report.findings]


def _all_checks(
    intake_checks: Sequence[CheckResult], reports: Sequence[InspectorReport]
) -> list[CheckResult]:
    checks = list(intake_checks)
    for report in reports:
        checks.extend(report.checks)
    return checks


def _policy_severity(policy: Policy, check_id: str) -> str | None:
    if check_id.startswith("intake."):
        name = check_id.removeprefix("intake.")
        severities = type(policy.intake.severities)
        if name in severities.model_fields:
            return getattr(policy.intake.severities, name)
        return None
    for group in (
        policy.static.severities,
        policy.provenance.severities,
        policy.behavioural.severities,
    ):
        if check_id in type(group).model_fields:
            return getattr(group, check_id)
    return None


def _check_severity(policy: Policy, check: CheckResult) -> str | None:
    looked = _policy_severity(policy, check.check_id)
    return looked if looked is not None else check.severity


def _critical_ids(reports: Sequence[InspectorReport]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for finding in _findings(reports):
        if finding.severity != "critical" or finding.check_id in seen:
            continue
        seen.add(finding.check_id)
        ids.append(finding.check_id)
    return ids


def _registry_entry_exists(reports: Sequence[InspectorReport]) -> bool:
    for report in reports:
        if report.inspector != "provenance":
            continue
        if report.coverage.get("matched_model"):
            return True
        for check in report.checks:
            if check.check_id != "provenance_hash_match":
                continue
            if check.details.get("matched"):
                return True
            if check.status in {"passed", "failed"}:
                return True
    return False


def _is_required(check: CheckResult, policy: Policy, reports: Sequence[InspectorReport]) -> bool:
    if check.check_id not in set(policy.verdict.required_checks):
        return False
    if check.status == "skipped" and check.reason in COVERAGE_GAP_REASONS:
        return False
    if check.check_id == "provenance_hash_match" and not _registry_entry_exists(reports):
        return False
    return True


def _required_errors(
    intake_checks: Sequence[CheckResult],
    reports: Sequence[InspectorReport],
    policy: Policy,
) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for check in _all_checks(intake_checks, reports):
        if check.status != "error" or not _is_required(check, policy, reports):
            continue
        if check.check_id in seen:
            continue
        seen.add(check.check_id)
        ids.append(check.check_id)
    return ids


def _warning_ids(
    intake_checks: Sequence[CheckResult],
    reports: Sequence[InspectorReport],
    policy: Policy,
) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()

    def add(check_id: str) -> None:
        if check_id not in seen:
            seen.add(check_id)
            ids.append(check_id)

    for finding in _findings(reports):
        if finding.severity == "warning":
            add(finding.check_id)
    for check in _all_checks(intake_checks, reports):
        if check.status == "failed" and _check_severity(policy, check) == "warning":
            add(check.check_id)
    return ids


def _has_provenance_anchor(reports: Sequence[InspectorReport]) -> bool:
    """v1 anchor: provenance_hash_match passed. Attestation is never verified."""
    for report in reports:
        for check in report.checks:
            if check.check_id == "provenance_hash_match" and check.status == "passed":
                return True
    return False


def _behavioural_passed(reports: Sequence[InspectorReport]) -> bool:
    """Coverage counts only when behavioural_coverage passed and the marker did not fail.

    A missing report, a skip, or an error is not coverage. status=error on a
    required behavioural check is handled by ``_required_errors`` and is not a pass.
    A skipped behavioural check is not an error.
    """
    behavioural = [report for report in reports if report.inspector == "behavioural"]
    if not behavioural:
        return False
    coverage_passed = False
    for report in behavioural:
        for check in report.checks:
            if check.check_id == "behavioural_marker" and check.status == "failed":
                return False
            if check.check_id == "behavioural_coverage" and check.status == "passed":
                coverage_passed = True
    return coverage_passed


def _verdict(
    *,
    classification: Classification,
    rule_id: RuleId,
    exit_code: int,
    reason: str,
    critical_finding_ids: list[str],
) -> Verdict:
    return Verdict(
        classification=classification,
        rule_id=rule_id,
        exit_code=exit_code,
        reason=reason,
        critical_finding_ids=critical_finding_ids,
    )


def decide_verdict(
    intake_checks: Sequence[CheckResult],
    reports: Sequence[InspectorReport],
    policy: Policy,
) -> Verdict:
    """Apply the five rules. First match wins."""
    critical_ids = _critical_ids(reports)
    if critical_ids:
        listed = ", ".join(critical_ids)
        return _verdict(
            classification="Blocked",
            rule_id="rule_critical",
            exit_code=EXIT_BLOCKED,
            reason=f"Critical finding: {listed}.",
            critical_finding_ids=critical_ids,
        )

    errors = _required_errors(intake_checks, reports, policy)
    if errors:
        listed = ", ".join(errors)
        return _verdict(
            classification="Undetermined",
            rule_id="rule_check_error",
            exit_code=EXIT_UNDETERMINED,
            reason=f"Required check status is error: {listed}.",
            critical_finding_ids=[],
        )

    warnings = _warning_ids(intake_checks, reports, policy)
    if warnings:
        listed = ", ".join(warnings)
        return _verdict(
            classification="Conditional",
            rule_id="rule_warnings",
            exit_code=EXIT_CONDITIONAL,
            reason=f"Warning: {listed}.",
            critical_finding_ids=[],
        )

    anchor = _has_provenance_anchor(reports)
    behavioural = _behavioural_passed(reports)
    if not anchor or not behavioural:
        if not behavioural:
            reason = f"The verdict is Undetermined because the {BEHAVIOURAL_MISSING}."
            if not anchor:
                reason += " There is no provenance anchor."
        else:
            reason = "The verdict is Undetermined because there is no provenance anchor."
        return _verdict(
            classification="Undetermined",
            rule_id="rule_insufficient_evidence",
            exit_code=EXIT_UNDETERMINED,
            reason=reason,
            critical_finding_ids=[],
        )

    return _verdict(
        classification="Trusted",
        rule_id="rule_trusted",
        exit_code=EXIT_TRUSTED,
        reason="Provenance anchor and behavioural coverage are present and no warnings remain.",
        critical_finding_ids=[],
    )


def decide(
    request: ScanRequest,
    manifest: ArtifactManifest,
    intake_checks: Sequence[CheckResult],
    reports: Sequence[Any],
    policy: Policy | None = None,
    *,
    timestamp: datetime | None = None,
) -> EvidenceBundle:
    """Build a sealed evidence bundle. The verdict engine is the only classifier."""
    policy = policy or load_policy(request.policy_profile)
    stored = [_as_report(report) for report in reports]
    verdict = decide_verdict(intake_checks, stored, policy)
    when = timestamp or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    bundle = EvidenceBundle(
        request=request,
        manifest=ManifestSummary(
            root_sha256=manifest.root_sha256,
            artifact_type=manifest.artifact_type,
            source=manifest.source,
        ),
        intake_checks=list(intake_checks),
        reports=stored,
        verdict=verdict,
        tool_version=__version__,
        policy_profile=policy.name,
        timestamp=when,
        bundle_sha256="",
    )
    document = bundle.model_dump(mode="json")
    document["bundle_sha256"] = canonical_bundle_sha256(document)
    return EvidenceBundle.model_validate(document)
