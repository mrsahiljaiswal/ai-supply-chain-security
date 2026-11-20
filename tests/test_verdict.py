"""Verdict engine tests. Behavioural coverage is a fake report; nothing here loads a model."""

import json
from datetime import datetime, timezone

from typer.testing import CliRunner

from hashvault.cli import app
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.policy import load_policy
from hashvault.verdict import EvidenceBundle, InspectorReport, canonical_bundle_sha256, decide, render_bundle

runner = CliRunner()
WHEN = datetime(2026, 11, 20, 6, 0, tzinfo=timezone.utc)


def _manifest(path, **kw) -> ArtifactManifest:
    data = dict(
        scan_id="hv-test",
        source="local_dir",
        source_ref=str(path),
        artifact_type="full_model",
        root_sha256="ab" * 32,
        work_dir=str(path),
        staged_at_utc=WHEN,
    )
    data.update(kw)
    return ArtifactManifest(**data)


def _report(inspector, checks=None, findings=None, coverage=None) -> InspectorReport:
    return InspectorReport(
        inspector=inspector,
        version="0.1.0",
        checks=checks or [],
        findings=findings or [],
        coverage=coverage or {},
    )


def _finding(check_id, severity, message) -> Finding:
    inspector = "provenance" if check_id.startswith("provenance_") else "static"
    return Finding(inspector=inspector, check_id=check_id, severity=severity, message=message)


def _bundle(path, reports, intake=None) -> EvidenceBundle:
    return decide(
        ScanRequest(artifact=str(path)),
        _manifest(path),
        intake or [],
        reports,
        load_policy("strict"),
        timestamp=WHEN,
    )


def _static_ok():
    return _report("static", checks=[
        CheckResult(check_id="safetensors_structure", status="passed"),
        CheckResult(check_id="safetensors_trailing_bytes", status="passed"),
    ])


def test_critical_static_blocks_even_when_provenance_is_skipped(fixtures):
    reports = [
        _report("static", checks=[
            CheckResult(check_id="pickle_dangerous_callable", status="failed", severity="critical"),
        ], findings=[
            _finding("pickle_dangerous_callable", "critical", "os.system"),
        ]),
        _report("provenance", checks=[
            CheckResult(
                check_id="provenance_hash_match",
                status="skipped",
                reason="no_known_good_reference",
            ),
        ]),
    ]
    verdict = _bundle(fixtures["full_model"], reports).verdict
    assert verdict.classification == "Blocked"
    assert verdict.rule_id == "rule_critical"
    assert verdict.exit_code == 30
    assert verdict.critical_finding_ids == ["pickle_dangerous_callable"]


def test_hash_mismatch_is_blocked(fixtures):
    reports = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="failed", severity="critical"),
        ], findings=[
            _finding("provenance_hash_match", "critical", "hash mismatch for <root>"),
        ], coverage={"matched_model": "acme/tiny-base"}),
    ]
    verdict = _bundle(fixtures["full_model"], reports).verdict
    assert verdict.classification == "Blocked"
    assert verdict.exit_code == 30
    assert verdict.rule_id == "rule_critical"
    assert "provenance_hash_match" in verdict.critical_finding_ids


def test_hash_match_without_behavioural_is_undetermined(fixtures):
    reports = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="passed"),
            CheckResult(check_id="provenance_publisher", status="skipped", reason="publisher_not_claimed"),
        ], coverage={"matched_model": "acme/tiny-base"}),
    ]
    verdict = _bundle(fixtures["full_model"], reports).verdict
    assert verdict.classification == "Undetermined"
    assert verdict.rule_id == "rule_insufficient_evidence"
    assert verdict.exit_code == 20
    assert "behavioural inspector has not run" in verdict.reason
    assert verdict.critical_finding_ids == []


def test_warning_only_is_conditional_hash_matched_or_skipped(fixtures):
    warning = _finding("provenance_base_claim", "warning", "spoofed base")
    matched = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="passed"),
            CheckResult(
                check_id="provenance_base_claim", status="failed", severity="warning",
                reason="spoofed base",
            ),
        ], findings=[warning], coverage={"matched_model": "acme/tiny-base"}),
    ]
    skipped = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(
                check_id="provenance_hash_match", status="skipped", reason="no_known_good_reference",
            ),
            CheckResult(
                check_id="provenance_base_claim", status="failed", severity="warning",
                reason="spoofed base",
            ),
        ], findings=[warning]),
    ]
    for reports in (matched, skipped):
        verdict = _bundle(fixtures["full_model"], reports).verdict
        assert verdict.classification == "Conditional", verdict
        assert verdict.rule_id == "rule_warnings"
        assert verdict.exit_code == 10


def test_required_check_error_is_undetermined_and_critical_still_wins(fixtures):
    errored = [
        _report("static", checks=[
            CheckResult(check_id="pickle_opcode_scan", status="error", reason="scanner blew up"),
        ]),
        _report("provenance", checks=[
            CheckResult(
                check_id="provenance_hash_match", status="skipped", reason="no_known_good_reference",
            ),
        ]),
    ]
    verdict = _bundle(fixtures["full_model"], errored).verdict
    assert verdict.classification == "Undetermined"
    assert verdict.rule_id == "rule_check_error"
    assert verdict.exit_code == 20
    assert "pickle_opcode_scan" in verdict.reason

    both = [
        _report("static", checks=[
            CheckResult(check_id="pickle_dangerous_callable", status="failed", severity="critical"),
        ], findings=[
            _finding("pickle_dangerous_callable", "critical", "os.system"),
        ]),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="error", reason="registry read failed"),
        ], coverage={"matched_model": "acme/tiny-base"}),
    ]
    verdict = _bundle(fixtures["full_model"], both).verdict
    assert verdict.classification == "Blocked"
    assert verdict.rule_id == "rule_critical"
    assert verdict.exit_code == 30
    assert verdict.critical_finding_ids == ["pickle_dangerous_callable"]


def test_fake_behavioural_pass_with_anchor_is_trusted(fixtures):
    reports = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="passed"),
        ], coverage={"matched_model": "acme/tiny-base"}),
        _report("behavioural", checks=[
            CheckResult(check_id="behavioural_marker", status="passed"),
            CheckResult(check_id="behavioural_coverage", status="passed"),
        ]),
    ]
    verdict = _bundle(fixtures["full_model"], reports).verdict
    assert verdict.classification == "Trusted"
    assert verdict.rule_id == "rule_trusted"
    assert verdict.exit_code == 0


def test_skipped_behavioural_is_not_an_error(fixtures):
    reports = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="passed"),
        ]),
        _report("behavioural", checks=[
            CheckResult(check_id="behavioural_comparison", status="skipped", reason="base model unverified"),
        ]),
    ]
    verdict = _bundle(fixtures["full_model"], reports).verdict
    assert verdict.rule_id == "rule_insufficient_evidence"
    assert verdict.exit_code == 20
    assert "behavioural inspector has not run" in verdict.reason


def test_bundle_json_round_trips_and_hash_matches(fixtures):
    reports = [
        _static_ok(),
        _report("provenance", checks=[
            CheckResult(check_id="provenance_hash_match", status="passed", details={"matched": "acme/tiny-base"}),
        ], coverage={"matched_model": "acme/tiny-base"}),
    ]
    bundle = _bundle(fixtures["full_model"], reports)
    text = render_bundle(bundle)
    assert text.endswith("\n")
    parsed = json.loads(text)
    assert parsed["bundle_sha256"] == canonical_bundle_sha256(parsed)
    restored = EvidenceBundle.model_validate(parsed)
    assert restored.verdict == bundle.verdict
    assert restored.tool_version == bundle.tool_version
    assert restored.policy_profile == "strict"
    assert restored.manifest.root_sha256 == "ab" * 32
    again = json.loads(render_bundle(restored))
    assert again == parsed
    assert again["bundle_sha256"] == canonical_bundle_sha256(again)


def test_cli_bundle_file_matches_stdout(fixtures, work_root, tmp_path):
    out = tmp_path / "reports"
    result = runner.invoke(app, [
        "scan", str(fixtures["full_model"]),
        "--base", "Qwen/Qwen2.5-0.5B",
        "--work-dir", str(work_root),
        "--out", str(out),
    ])
    assert result.exit_code == 20, result.stdout
    payload = json.loads(result.stdout)
    written = json.loads(next(out.glob("hashvault-report-*.json")).read_text(encoding="utf-8"))
    assert written == payload
    assert written["bundle_sha256"] == canonical_bundle_sha256(written)
    assert "rule_insufficient_evidence" in result.stderr
    assert "behavioural inspector has not run" in result.stderr
