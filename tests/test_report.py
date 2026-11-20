"""HTML evidence report. The behavioural disclaimer is a sentence, not a pass."""

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from hashvault.cli import app
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.policy import load_policy
from hashvault.report.render import render_html
from hashvault.verdict import InspectorReport, decide

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()
WHEN = datetime(2026, 11, 20, 6, 0, tzinfo=timezone.utc)
DISCLAIMER = "A behavioural pass is not proof that the model has no backdoor."
SCRIPT = "<script>alert(1)</script>"


def run(*args):
    return runner.invoke(app, [str(a) for a in args])


def _manifest(path: Path) -> ArtifactManifest:
    return ArtifactManifest(
        scan_id="hv-report",
        source="local_dir",
        source_ref=str(path),
        artifact_type="full_model",
        root_sha256="ab" * 32,
        work_dir=str(path),
        staged_at_utc=WHEN,
    )


def _finding(message: str) -> Finding:
    return Finding(
        inspector="static",
        check_id="pickle_dangerous_callable",
        severity="critical",
        message=message,
    )


def _bundle(path: Path, reports: list[InspectorReport]):
    return decide(
        ScanRequest(artifact=str(path)),
        _manifest(path),
        [],
        reports,
        load_policy("strict"),
        timestamp=WHEN,
    )


def test_scan_writes_html_beside_json(fixtures, work_root, tmp_path):
    out_dir = tmp_path / "out"
    result = run(
        "scan", fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B",
        "--work-dir", work_root, "--out", out_dir,
    )
    assert result.exit_code != 2, result.stdout + result.stderr
    written = list(out_dir.glob("hashvault-report-*.json"))
    html_paths = list(out_dir.glob("hashvault-report-*.html"))
    assert len(written) == 1
    assert len(html_paths) == 1
    assert written[0].stem == html_paths[0].stem
    assert str(html_paths[0]) in result.stderr
    bundle = json.loads(written[0].read_text(encoding="utf-8"))
    html = html_paths[0].read_text(encoding="utf-8")
    verdict = bundle["verdict"]
    assert verdict["classification"] in html
    assert verdict["rule_id"] in html
    assert bundle["manifest"]["root_sha256"] in html
    behavioural = next(item for item in bundle["reports"] if item["inspector"] == "behavioural")
    reason = behavioural["coverage"].get("reason") or behavioural["checks"][0]["reason"]
    assert reason
    assert reason in html
    assert "was skipped" in html
    assert "not a pass" in html
    assert DISCLAIMER in html


def test_json_out_path_writes_sibling_html(fixtures, work_root, tmp_path):
    dest = tmp_path / "nested" / "evidence.json"
    result = run(
        "scan", fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B",
        "--work-dir", work_root, "--out", dest,
    )
    assert result.exit_code != 2, result.stdout + result.stderr
    html_path = dest.with_suffix(".html")
    assert dest.is_file()
    assert html_path.is_file()
    assert str(html_path) in result.stderr


def test_critical_finding_check_id_is_visible(tmp_path):
    out_dir = tmp_path / "out"
    result = run(
        "scan", ROOT / "corpus" / "suspicious" / "marker-pickle",
        "--base", "acme/tiny-base",
        "--registry", ROOT / "corpus" / "registry.yaml",
        "--work-dir", tmp_path / "work",
        "--out", out_dir,
    )
    assert result.exit_code == 30, result.stdout[-500:] + result.stderr[-500:]
    html = next(out_dir.glob("hashvault-report-*.html")).read_text(encoding="utf-8")
    assert "pickle_dangerous_callable" in html
    assert "critical" in html


def test_script_in_finding_message_is_escaped(fixtures):
    path = fixtures["full_model"]
    report = InspectorReport(
        inspector="static",
        version="0.1.0",
        checks=[CheckResult(check_id="pickle_dangerous_callable", status="failed", severity="critical")],
        findings=[_finding(SCRIPT)],
    )
    html = render_html(_bundle(path, [report]))
    assert SCRIPT not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "pickle_dangerous_callable" in html
    assert DISCLAIMER not in html


def test_disclaimer_only_when_behavioural_report_exists(fixtures):
    path = fixtures["full_model"]
    static = InspectorReport(
        inspector="static",
        version="0.1.0",
        checks=[CheckResult(check_id="safetensors_structure", status="passed")],
        findings=[],
    )
    skipped = InspectorReport(
        inspector="behavioural",
        version="0.1.0",
        checks=[CheckResult(
            check_id="behavioural_coverage",
            status="skipped",
            reason="base_weights_missing",
        )],
        findings=[],
        coverage={"eligible": False, "reason": "base_weights_missing"},
    )
    without = render_html(_bundle(path, [static]))
    with_skip = render_html(_bundle(path, [static, skipped]))
    assert DISCLAIMER not in without
    assert DISCLAIMER in with_skip
    assert "base_weights_missing" in with_skip
    assert "was skipped" in with_skip
    assert "not a pass" in with_skip


def test_behavioural_error_names_the_reason(fixtures):
    path = fixtures["full_model"]
    errored = InspectorReport(
        inspector="behavioural",
        version="0.1.0",
        checks=[CheckResult(check_id="behavioural_coverage", status="error", reason="docker_unavailable")],
        findings=[],
        coverage={"eligible": True, "reason": "docker_unavailable", "scanner_error": "docker_unavailable"},
    )
    html = render_html(_bundle(path, [errored]))
    assert "Behavioural inspection errored: docker_unavailable." in html
    assert "An error is not a pass." in html
    assert DISCLAIMER in html
    assert "was skipped" not in html


def test_intake_does_not_write_html(fixtures, work_root, tmp_path):
    out_dir = tmp_path / "out"
    result = run(
        "intake", fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B",
        "--work-dir", work_root, "--out", out_dir,
    )
    assert result.exit_code == 0, result.output
    assert list(out_dir.glob("*.html")) == []
    assert list(out_dir.glob("*.intake.json"))
