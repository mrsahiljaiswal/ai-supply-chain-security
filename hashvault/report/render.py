"""Render an evidence bundle as a single self-contained HTML file.

The template is local. Nothing is fetched, and artifact text is escaped.
"""

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from hashvault.verdict.models import EvidenceBundle, InspectorReport

_SEVERITIES = frozenset({"info", "warning", "critical"})
_CLASSIFICATIONS = frozenset({"Trusted", "Conditional", "Undetermined", "Blocked"})


def _environment() -> Environment:
    # autoescape is unconditional so a .html rename cannot turn escaping off.
    return Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _coverage_lines(coverage: dict[str, Any] | None) -> list[str]:
    lines: list[str] = []

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            if not value and prefix:
                lines.append(f"{prefix}: {{}}")
                return
            for key, item in value.items():
                child = f"{prefix}.{key}" if prefix else str(key)
                walk(child, item)
            return
        if isinstance(value, list):
            if not value:
                lines.append(f"{prefix}: []")
            elif all(isinstance(item, str) for item in value):
                for item in value:
                    lines.append(f"{prefix}: {item}")
            elif all(not isinstance(item, (dict, list)) for item in value):
                rendered = ", ".join("" if item is None else str(item) for item in value)
                lines.append(f"{prefix}: {rendered}")
            else:
                for index, item in enumerate(value):
                    walk(f"{prefix}[{index}]", item)
            return
        shown = "" if value is None else str(value)
        lines.append(f"{prefix}: {shown}" if prefix else shown)

    walk("", coverage or {})
    return lines


def _behavioural(reports: list[InspectorReport]) -> dict[str, Any] | None:
    if not reports:
        return None
    checks: list[dict[str, str]] = []
    reasons: list[str] = []
    any_error = False
    any_ran = False
    for report in reports:
        coverage = report.coverage or {}
        statuses = {check.status for check in report.checks}
        if "error" in statuses or coverage.get("scanner_error"):
            any_error = True
        elif coverage.get("eligible") is True and any(
            check.status in {"passed", "failed"} for check in report.checks
        ):
            any_ran = True
        reason = coverage.get("scanner_error") or coverage.get("reason")
        if not reason:
            for check in report.checks:
                if check.reason:
                    reason = check.reason
                    break
        if reason:
            reasons.append(str(reason))
        for check in report.checks:
            checks.append({
                "check_id": check.check_id,
                "status": check.status,
                "reason": check.reason or "",
            })
    if any_error:
        summary = "error"
    elif any_ran:
        summary = "ran"
    else:
        summary = "skipped"
    return {
        "summary": summary,
        "reason": reasons[0] if reasons else "unspecified",
        "checks": checks,
    }


def _context(bundle: EvidenceBundle) -> dict[str, Any]:
    verdict = bundle.verdict
    findings = []
    coverage = []
    behavioural_reports = []
    for report in bundle.reports:
        if report.inspector == "behavioural":
            behavioural_reports.append(report)
        for finding in report.findings:
            severity = finding.severity if finding.severity in _SEVERITIES else "info"
            findings.append({
                "severity": finding.severity,
                "severity_class": severity,
                "check_id": finding.check_id,
                "message": finding.message,
            })
        coverage.append({
            "inspector": report.inspector,
            "lines": _coverage_lines(report.coverage),
        })
    classification = verdict.classification
    return {
        "classification": classification,
        "classification_class": classification.lower() if classification in _CLASSIFICATIONS else "other",
        "exit_code": verdict.exit_code,
        "rule_id": verdict.rule_id,
        "reason": verdict.reason,
        "critical_finding_ids": list(verdict.critical_finding_ids),
        "root_sha256": bundle.manifest.root_sha256 or "",
        "artifact_type": bundle.manifest.artifact_type,
        "source": bundle.manifest.source,
        "findings": findings,
        "coverage": coverage,
        "behavioural": _behavioural(behavioural_reports),
        "tool_version": bundle.tool_version,
        "policy_profile": bundle.policy_profile,
        "timestamp": bundle.timestamp.isoformat(),
    }


def render_html(bundle: EvidenceBundle) -> str:
    """Return the HTML report, including a trailing newline."""
    html = _environment().get_template("report.html").render(**_context(bundle))
    if not html.endswith("\n"):
        html += "\n"
    return html


def write_html_report(bundle: EvidenceBundle, dest: Path) -> Path:
    """Write the report to ``dest`` and return that path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_html(bundle), encoding="utf-8")
    return dest
