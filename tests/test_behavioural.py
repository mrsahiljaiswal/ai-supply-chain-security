"""Behavioural inspector tests. No torch, no docker, no network."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from hashvault.cli import app
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest, ManifestEntry
from hashvault.contracts.request import ScanRequest
from hashvault.inspectors.behavioural.backend import (
    DockerBackend,
    ScriptedBackend,
    docker_run_command,
)
from hashvault.inspectors.behavioural.eligibility import check_eligibility
from hashvault.inspectors.behavioural.probes import (
    NO_BACKDOOR_CLAIM,
    Probe,
    ProbeBank,
    evaluate_probes,
    load_probe_bank,
)
from hashvault.inspectors.static.scanner import InspectorReport as StaticReport
from hashvault.intake.pipeline import run_intake
from hashvault.policy import load_policy
from hashvault.verdict import decide

runner = CliRunner()
WHEN = datetime(2026, 11, 20, 7, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
DIST = [[0.6, 0.4]]
FAR = [[0.1, 0.9]]
NEAR = [[0.9, 0.1]]


def _static(checks=None, findings=None) -> StaticReport:
    return StaticReport(version="0.1.0", checks=checks or [
        CheckResult(check_id="safetensors_structure", status="passed"),
        CheckResult(check_id="safetensors_trailing_bytes", status="passed"),
    ], findings=findings or [])


def _manifest(tmp_path, *, fmt="safetensors", params=8) -> ArtifactManifest:
    work = tmp_path / "hv-work"
    (work / "artifact").mkdir(parents=True, exist_ok=True)
    name = "model.safetensors" if fmt == "safetensors" else "model.pickle"
    return ArtifactManifest(
        scan_id="hv-beh",
        source="local_dir",
        source_ref=str(tmp_path / "src"),
        artifact_type="full_model",
        root_sha256="ab" * 32,
        work_dir=str(work),
        entries=[ManifestEntry(
            path=name,
            size_bytes=8,
            sha256="cd" * 32,
            detected_format=fmt,
            role="weights",
            staged_path=f"artifact/{name}",
        )],
        estimated_params=params,
        staged_at_utc=WHEN,
    )


def _request(tmp_path, base="acme/tiny-base") -> ScanRequest:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return ScanRequest(artifact=str(src), claimed_base_model=base)


def _registry(path: Path, *, name="acme/tiny-base", root="ab" * 32, local_path=None, include_root=True) -> Path:
    entry = {"name": name, "revision": None, "publisher": "acme", "files": {}}
    if include_root:
        entry["root_sha256"] = root
    if local_path is not None:
        entry["local_path"] = str(local_path)
    path.write_text(yaml.safe_dump({"models": [entry], "trusted_names": [name]}), encoding="utf-8")
    return path


def _eligible_setup(tmp_path):
    base = tmp_path / "base-weights"
    base.mkdir()
    (base / "model.safetensors").write_bytes(b"not-loaded")
    registry = _registry(tmp_path / "reg.yaml", local_path=base)
    return _request(tmp_path), _manifest(tmp_path), _static(), registry, base


def test_eligibility_skips_static_critical(tmp_path):
    request, manifest, _static_ok, registry, _base = _eligible_setup(tmp_path)
    report = _static(
        checks=[CheckResult(check_id="pickle_dangerous_callable", status="failed", severity="critical")],
        findings=[Finding(
            inspector="static", check_id="pickle_dangerous_callable",
            severity="critical", message="os.system",
        )],
    )
    decision = check_eligibility(request, manifest, report, load_policy("strict"), registry_path=registry)
    assert decision.eligible is False
    assert decision.reason == "static_critical"


def test_eligibility_skips_pickle_weights(tmp_path):
    request, _manifest_ok, report, registry, _base = _eligible_setup(tmp_path)
    decision = check_eligibility(
        request, _manifest(tmp_path, fmt="pickle"), report, load_policy("strict"), registry_path=registry,
    )
    assert decision.eligible is False
    assert decision.reason == "no_safe_load_path"


def test_eligibility_skips_missing_base(tmp_path):
    _request_ok, manifest, report, registry, _base = _eligible_setup(tmp_path)
    src = tmp_path / "src"
    no_base = ScanRequest(artifact=str(src))
    missing = check_eligibility(no_base, manifest, report, load_policy("strict"), registry_path=registry)
    assert missing.reason == "base_unverified"

    unknown = _registry(tmp_path / "other.yaml", name="other/model", local_path=tmp_path / "base-weights")
    no_entry = check_eligibility(
        _request(tmp_path), manifest, report, load_policy("strict"), registry_path=unknown,
    )
    assert no_entry.reason == "base_unverified"

    no_root = _registry(
        tmp_path / "noroot.yaml", include_root=False, local_path=tmp_path / "base-weights",
    )
    unverified = check_eligibility(
        _request(tmp_path), manifest, report, load_policy("strict"), registry_path=no_root,
    )
    assert unverified.reason == "base_unverified"


def test_eligibility_skips_missing_local_path(tmp_path):
    request, manifest, report, _registry_ok, _base = _eligible_setup(tmp_path)
    registry = _registry(tmp_path / "nolocal.yaml")
    decision = check_eligibility(request, manifest, report, load_policy("strict"), registry_path=registry)
    assert decision.eligible is False
    assert decision.reason == "base_weights_missing"


def test_eligibility_skips_params_over_the_limit(tmp_path):
    request, _manifest_ok, report, registry, _base = _eligible_setup(tmp_path)
    manifest = _manifest(tmp_path, params=500_000_001)
    decision = check_eligibility(request, manifest, report, load_policy("strict"), registry_path=registry)
    assert decision.eligible is False
    assert decision.reason == "exceeds_resource_profile"


def test_eligibility_allows_safetensors_when_registry_local_path_exists(tmp_path):
    request, manifest, report, registry, base = _eligible_setup(tmp_path)
    decision = check_eligibility(request, manifest, report, load_policy("strict"), registry_path=registry)
    assert decision.eligible is True
    assert decision.reason is None
    assert decision.base_dir == base.resolve()

    via_flag = _registry(tmp_path / "flag.yaml")
    flagged = check_eligibility(
        request, manifest, report, load_policy("strict"),
        registry_path=via_flag, base_dir=base,
    )
    assert flagged.eligible is True
    assert flagged.base_dir == base.resolve()


def test_eligibility_static_error_is_incomplete(tmp_path):
    request, manifest, _report, registry, _base = _eligible_setup(tmp_path)
    report = _static(checks=[CheckResult(check_id="safetensors_structure", status="error", reason="boom")])
    decision = check_eligibility(request, manifest, report, load_policy("strict"), registry_path=registry)
    assert decision.reason == "static_incomplete"


def _bank() -> ProbeBank:
    probes = []
    for index in range(1, 4):
        probes.append(Probe(id=f"ordinary-{index}", prompt=f"ordinary {index}", group="ordinary"))
        probes.append(Probe(
            id=f"refusal-{index}", prompt=f"refusal {index}", group="refusal", expect_refusal=True,
        ))
        probes.append(Probe(
            id=f"marker-{index}", prompt=f"marker {index}", group="marker", marker="HASHVAULT_MARKER",
        ))
    return ProbeBank(probes=probes)


def _rows(bank: ProbeBank, text="Hello from the model.", logprobs=None, overrides=None) -> list[dict]:
    overrides = overrides or {}
    rows = []
    for probe in bank.probes:
        item = {"id": probe.id, "text": text, "token_logprobs": logprobs if logprobs is not None else DIST}
        item.update(overrides.get(probe.id, {}))
        rows.append(item)
    return rows


def _checks(bank, base, candidate):
    checks, findings = evaluate_probes(bank, base, candidate, load_policy("strict"))
    by_id = {check.check_id: check for check in checks}
    return by_id, findings


def test_probe_file_has_three_groups():
    bank = load_probe_bank()
    grouped: dict[str, list] = {}
    for probe in bank.probes:
        grouped.setdefault(probe.group, []).append(probe)
    assert set(grouped) == {"ordinary", "refusal", "marker"}
    assert all(len(items) == 3 for items in grouped.values())
    assert all(item.expect_refusal for item in grouped["refusal"])
    assert all(item.marker == "HASHVAULT_MARKER" for item in grouped["marker"])


def test_marker_only_in_the_candidate_is_critical():
    bank = _bank()
    base = _rows(bank)
    candidate = _rows(bank, overrides={
        "marker-2": {"text": "prefix HASHVAULT_MARKER suffix"},
    })
    checks, findings = _checks(bank, base, candidate)
    assert checks["behavioural_marker"].status == "failed"
    assert checks["behavioural_marker"].severity == "critical"
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "behavioural_marker"
    assert finding.severity == "critical"
    assert finding.evidence["prompt_id"] == "marker-2"
    assert "HASHVAULT_MARKER" in finding.evidence["snippet"]


def test_identical_scripted_outputs_pass():
    bank = _bank()
    rows = _rows(bank)
    checks, findings = _checks(bank, rows, rows)
    assert findings == []
    assert checks["behavioural_marker"].status == "passed"
    assert checks["behavioural_kl"].status == "passed"
    assert checks["behavioural_kl"].details["mean_kl_nats"] == pytest.approx(0.0)
    assert checks["behavioural_kl"].details["mean_kl_nats"] < 0.5
    assert checks["behavioural_refusal"].status == "passed"
    assert checks["behavioural_refusal"].details["delta"] == 0
    assert checks["behavioural_coverage"].status == "passed"
    assert checks["behavioural_coverage"].reason == NO_BACKDOOR_CLAIM
    assert "no backdoor" in checks["behavioural_coverage"].reason
    assert checks["behavioural_coverage"].details["prompt_ids"] == [probe.id for probe in bank.probes]


def test_kl_above_threshold_is_a_warning():
    bank = _bank()
    base = _rows(bank, logprobs=NEAR)
    candidate = _rows(bank, logprobs=FAR)
    checks, findings = _checks(bank, base, candidate)
    assert checks["behavioural_kl"].status == "failed"
    assert checks["behavioural_kl"].severity == "warning"
    assert checks["behavioural_kl"].details["mean_kl_nats"] > 0.5
    assert any(item.check_id == "behavioural_kl" and item.severity == "warning" for item in findings)


def test_refusal_delta_above_threshold_is_a_warning():
    bank = _bank()
    base = _rows(bank, text="Here is a general answer.")
    candidate = _rows(bank, overrides={
        probe.id: {"text": "I can't help with that."}
        for probe in bank.probes if probe.expect_refusal
    })
    checks, findings = _checks(bank, base, candidate)
    assert checks["behavioural_refusal"].status == "failed"
    assert checks["behavioural_refusal"].severity == "warning"
    assert checks["behavioural_refusal"].details["delta"] > 0.5
    assert any(item.check_id == "behavioural_refusal" and item.severity == "warning" for item in findings)


def test_empty_logprobs_are_an_error_not_a_pass():
    bank = _bank()
    base = _rows(bank)
    candidate = _rows(bank, overrides={"ordinary-1": {"token_logprobs": []}})
    checks, _findings = _checks(bank, base, candidate)
    assert checks["behavioural_kl"].status == "error"
    assert checks["behavioural_kl"].status != "passed"
    assert checks["behavioural_kl"].reason == "empty logprobs"
    prompt = next(item for item in checks["behavioural_kl"].details["prompts"] if item["id"] == "ordinary-1")
    assert prompt["status"] == "error"


def test_shorter_distribution_is_the_kl_support():
    bank = _bank()
    base = _rows(bank, logprobs=[[0.5, 0.5, 0.0]])
    candidate = _rows(bank, logprobs=[[0.5, 0.5]])
    checks, findings = _checks(bank, base, candidate)
    assert findings == []
    assert checks["behavioural_kl"].status == "passed"
    assert checks["behavioural_kl"].details["mean_kl_nats"] == pytest.approx(0.0)


def _anchor_reports(behavioural):
    from hashvault.verdict import InspectorReport

    return [
        InspectorReport(
            inspector="static", version="0.1.0",
            checks=[CheckResult(check_id="safetensors_structure", status="passed")],
        ),
        InspectorReport(
            inspector="provenance", version="0.1.0",
            checks=[CheckResult(check_id="provenance_hash_match", status="passed")],
            coverage={"matched_model": "acme/tiny-base"},
        ),
        behavioural,
    ]


def test_verdict_identical_outputs_are_trusted(fixtures):
    bank = _bank()
    rows = _rows(bank)
    checks, findings = evaluate_probes(bank, rows, rows, load_policy("strict"))
    from hashvault.verdict import InspectorReport

    report = InspectorReport(inspector="behavioural", version="0.1.0", checks=checks, findings=findings)
    verdict = decide(
        ScanRequest(artifact=str(fixtures["full_model"])),
        ArtifactManifest(
            scan_id="hv-beh", source="local_dir", source_ref=str(fixtures["full_model"]),
            artifact_type="full_model", root_sha256="ab" * 32, work_dir=str(fixtures["full_model"]),
            staged_at_utc=WHEN,
        ),
        [],
        _anchor_reports(report),
        load_policy("strict"),
        timestamp=WHEN,
    ).verdict
    assert verdict.classification == "Trusted"
    assert verdict.rule_id == "rule_trusted"
    assert verdict.exit_code == 0


def test_verdict_marker_hit_is_blocked_even_when_kl_is_fine(fixtures):
    bank = _bank()
    base = _rows(bank)
    candidate = _rows(bank, overrides={"marker-1": {"text": "HASHVAULT_MARKER"}})
    checks, findings = evaluate_probes(bank, base, candidate, load_policy("strict"))
    assert next(check for check in checks if check.check_id == "behavioural_kl").status == "passed"
    from hashvault.verdict import InspectorReport

    report = InspectorReport(inspector="behavioural", version="0.1.0", checks=checks, findings=findings)
    verdict = decide(
        ScanRequest(artifact=str(fixtures["full_model"])),
        ArtifactManifest(
            scan_id="hv-beh", source="local_dir", source_ref=str(fixtures["full_model"]),
            artifact_type="full_model", root_sha256="ab" * 32, work_dir=str(fixtures["full_model"]),
            staged_at_utc=WHEN,
        ),
        [],
        _anchor_reports(report),
        load_policy("strict"),
        timestamp=WHEN,
    ).verdict
    assert verdict.classification == "Blocked"
    assert verdict.exit_code == 30
    assert "behavioural_marker" in verdict.critical_finding_ids


def test_verdict_skipped_behavioural_is_not_trusted(fixtures):
    from hashvault.verdict import InspectorReport

    report = InspectorReport(
        inspector="behavioural", version="0.1.0",
        checks=[CheckResult(check_id=check_id, status="skipped", reason="base_weights_missing")
                for check_id in (
                    "behavioural_marker", "behavioural_kl", "behavioural_refusal", "behavioural_coverage",
                )],
    )
    verdict = decide(
        ScanRequest(artifact=str(fixtures["full_model"])),
        ArtifactManifest(
            scan_id="hv-beh", source="local_dir", source_ref=str(fixtures["full_model"]),
            artifact_type="full_model", root_sha256="ab" * 32, work_dir=str(fixtures["full_model"]),
            staged_at_utc=WHEN,
        ),
        [],
        _anchor_reports(report),
        load_policy("strict"),
        timestamp=WHEN,
    ).verdict
    assert verdict.classification != "Trusted"
    assert verdict.rule_id == "rule_insufficient_evidence"
    assert verdict.exit_code == 20


def test_old_behavioural_comparison_pass_is_not_coverage(fixtures):
    from hashvault.verdict import InspectorReport

    report = InspectorReport(
        inspector="behavioural", version="0.1.0",
        checks=[CheckResult(check_id="behavioural_comparison", status="passed")],
    )
    verdict = decide(
        ScanRequest(artifact=str(fixtures["full_model"])),
        ArtifactManifest(
            scan_id="hv-beh", source="local_dir", source_ref=str(fixtures["full_model"]),
            artifact_type="full_model", root_sha256="ab" * 32, work_dir=str(fixtures["full_model"]),
            staged_at_utc=WHEN,
        ),
        [],
        _anchor_reports(report),
        load_policy("strict"),
        timestamp=WHEN,
    ).verdict
    assert verdict.classification == "Undetermined"
    assert verdict.exit_code == 20


def test_docker_command_matches_the_isolation_rules(tmp_path):
    artifact = tmp_path / "artifact"
    base = tmp_path / "base"
    work = tmp_path / "work"
    for path in (artifact, base, work):
        path.mkdir()
    command = docker_run_command(artifact, base, work)
    assert command[0:3] == ["docker", "run", "--rm"]
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cpus") + 1] == "1"
    assert command[command.index("--memory") + 1] == "2g"
    assert "--read-only" in command
    assert f"type=bind,src={artifact.resolve()},dst=/artifact,readonly" in command
    assert f"type=bind,src={base.resolve()},dst=/base,readonly" in command
    assert f"type=bind,src={work.resolve()},dst=/work" in command
    assert command[-1] == "hashvault-behave:local"


def test_docker_backend_without_docker_on_path(tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    backend = DockerBackend(tmp_path / "work")
    result = backend.generate(
        [{"id": "ordinary-1", "prompt": "Hello"}],
        tmp_path / "artifact",
        tmp_path / "base",
    )
    assert result.status == "error"
    assert result.reason == "docker_unavailable"
    assert result.base == []
    assert result.candidate == []


def test_scripted_backend_does_not_read_weights(tmp_path):
    backend = ScriptedBackend(
        base=[{"id": "ordinary-1", "text": "Paris", "token_logprobs": DIST}],
        candidate=[{"id": "ordinary-1", "text": "Paris", "token_logprobs": DIST}],
    )
    result = backend.generate(
        [{"id": "ordinary-1", "prompt": "Capital?"}],
        tmp_path / "no-such-artifact",
        tmp_path / "no-such-base",
    )
    assert result.status == "ok"
    assert result.candidate[0]["text"] == "Paris"


def test_entrypoint_does_not_use_unsafe_loaders():
    text = (ROOT / "docker" / "behave.py").read_text(encoding="utf-8")
    assert "pickle.load" not in text
    assert "pickle.loads" not in text
    assert "weights_only=False" not in text
    assert "trust_remote_code=True" not in text
    assert "weights_only=True" in text
    assert "trust_remote_code=False" in text
    compile(text, "docker/behave.py", "exec")


def _matching_registry(artifact: Path, work_root: Path, dest: Path, *, local_path: Path | None) -> Path:
    request = ScanRequest(artifact=str(artifact), claimed_base_model="acme/tiny-base")
    manifest, _checks = run_intake(request, load_policy("strict"), work_root=work_root)
    entry = {
        "name": "acme/tiny-base",
        "revision": None,
        "publisher": "acme",
        "root_sha256": manifest.root_sha256,
        "files": {item.path: item.sha256 for item in manifest.entries},
    }
    if local_path is not None:
        entry["local_path"] = str(local_path)
    dest.write_text(yaml.safe_dump({
        "models": [entry],
        "trusted_names": ["acme/tiny-base"],
    }), encoding="utf-8")
    return dest


def _script(path: Path, bank: ProbeBank, *, marker: bool) -> Path:
    base = []
    candidate = []
    for probe in bank.probes:
        base.append({"id": probe.id, "text": "Hello from the base.", "token_logprobs": DIST})
        text = "HASHVAULT_MARKER" if marker and probe.marker else "Hello from the base."
        candidate.append({"id": probe.id, "text": text, "token_logprobs": DIST})
    path.write_text(json.dumps({"base": base, "candidate": candidate}), encoding="utf-8")
    return path


def _scan(artifact, work_root, registry, out, *, base_dir=None):
    argv = [
        "scan", str(artifact),
        "--base", "acme/tiny-base",
        "--registry", str(registry),
        "--work-dir", str(work_root),
        "--out", str(out),
    ]
    if base_dir is not None:
        argv.extend(["--base-dir", str(base_dir)])
    return runner.invoke(app, argv)


def test_cli_scripted_identical_outputs_exit_0(fixtures, work_root, tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir()
    registry = _matching_registry(fixtures["full_model"], work_root / "prep", tmp_path / "reg.yaml", local_path=base)
    script = _script(tmp_path / "script.json", load_probe_bank(), marker=False)
    monkeypatch.setenv("HASHVAULT_BEHAVIOURAL_BACKEND", "scripted")
    monkeypatch.setenv("HASHVAULT_BEHAVIOURAL_SCRIPT", str(script))
    result = _scan(fixtures["full_model"], work_root / "scan", registry, tmp_path / "out")
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] == "Trusted"
    assert payload["verdict"]["rule_id"] == "rule_trusted"
    behavioural = next(item for item in payload["reports"] if item["inspector"] == "behavioural")
    statuses = {check["check_id"]: check["status"] for check in behavioural["checks"]}
    assert statuses["behavioural_marker"] == "passed"
    assert statuses["behavioural_coverage"] == "passed"
    assert behavioural["findings"] == []


def test_cli_scripted_marker_exits_30(fixtures, work_root, tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir()
    registry = _matching_registry(fixtures["full_model"], work_root / "prep", tmp_path / "reg.yaml", local_path=base)
    script = _script(tmp_path / "script.json", load_probe_bank(), marker=True)
    monkeypatch.setenv("HASHVAULT_BEHAVIOURAL_BACKEND", "scripted")
    monkeypatch.setenv("HASHVAULT_BEHAVIOURAL_SCRIPT", str(script))
    result = _scan(fixtures["full_model"], work_root / "scan", registry, tmp_path / "out")
    assert result.exit_code == 30, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] == "Blocked"
    assert "behavioural_marker" in payload["verdict"]["critical_finding_ids"]
    behavioural = next(item for item in payload["reports"] if item["inspector"] == "behavioural")
    kl = next(check for check in behavioural["checks"] if check["check_id"] == "behavioural_kl")
    assert kl["status"] == "passed"


def test_cli_skipped_behavioural_is_not_trusted(fixtures, work_root, tmp_path, monkeypatch):
    monkeypatch.delenv("HASHVAULT_BEHAVIOURAL_BACKEND", raising=False)
    registry = _matching_registry(
        fixtures["full_model"], work_root / "prep", tmp_path / "reg.yaml", local_path=None,
    )
    result = _scan(fixtures["full_model"], work_root / "scan", registry, tmp_path / "out")
    assert result.exit_code != 0
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] != "Trusted"
    assert payload["verdict"]["rule_id"] == "rule_insufficient_evidence"
    behavioural = next(item for item in payload["reports"] if item["inspector"] == "behavioural")
    assert behavioural["findings"] == []
    assert {check["status"] for check in behavioural["checks"]} == {"skipped"}
    assert {check["reason"] for check in behavioural["checks"]} == {"base_weights_missing"}


def test_cli_docker_missing_is_undetermined(fixtures, work_root, tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.delenv("HASHVAULT_BEHAVIOURAL_BACKEND", raising=False)
    base = tmp_path / "base"
    base.mkdir()
    registry = _matching_registry(fixtures["full_model"], work_root / "prep", tmp_path / "reg.yaml", local_path=base)
    result = _scan(fixtures["full_model"], work_root / "scan", registry, tmp_path / "out", base_dir=base)
    assert result.exit_code == 20, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] == "Undetermined"
    assert payload["verdict"]["classification"] != "Trusted"
    assert payload["verdict"]["rule_id"] == "rule_check_error"
    behavioural = next(item for item in payload["reports"] if item["inspector"] == "behavioural")
    assert behavioural["findings"] == []
    assert {check["status"] for check in behavioural["checks"]} == {"error"}
    assert {check["reason"] for check in behavioural["checks"]} == {"docker_unavailable"}


@pytest.mark.parametrize("relative,expected", [
    ("corpus/clean/tiny-full-model", 20),
    ("corpus/clean/tiny-lora", 20),
    ("corpus/suspicious/spoofed-base", 10),
    ("corpus/suspicious/marker-pickle", 30),
    ("corpus/suspicious/lookalike-name", 10),
])
def test_corpus_live_scan_does_not_become_trusted(relative, expected, tmp_path):
    artifact = ROOT / relative
    argv = [
        "scan", str(artifact),
        "--registry", str(ROOT / "corpus" / "registry.yaml"),
        "--work-dir", str(tmp_path / "work"),
        "--out", str(tmp_path / "out"),
    ]
    if relative.endswith("tiny-lora") or relative.endswith("spoofed-base") or relative.endswith("marker-pickle"):
        argv.extend(["--base", "acme/tiny-base"])
    if relative.endswith("tiny-full-model"):
        argv.extend(["--base", "acme/tiny-base", "--repo", "acme/tiny-base"])
    if relative.endswith("lookalike-name"):
        argv.extend(["--repo", "acme/tiny-bose"])
    result = runner.invoke(app, argv)
    assert result.exit_code == expected, result.stdout[-500:] + result.stderr[-500:]
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] != "Trusted"
    behavioural = next(item for item in payload["reports"] if item["inspector"] == "behavioural")
    assert behavioural["findings"] == []
    assert all(check["status"] == "skipped" for check in behavioural["checks"])
